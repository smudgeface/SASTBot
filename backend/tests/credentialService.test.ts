/**
 * Unit tests for backend/src/services/credentialService.ts
 *
 * Uses the REAL crypto module (with a valid MASTER_KEY set in env) so that
 * encryption / decryption round-trips are tested properly. Prisma is mocked.
 *
 * Covers:
 *   (a) createCredential stores an ENCRYPTED blob, not the plaintext secret.
 *   (b) decodeCredential round-trips back to the original plaintext.
 *   (c) getPlaintext returns the correct raw plaintext buffer.
 *   (d) rotateCredential re-encrypts with the new value (old ciphertext is
 *       replaced by a new one, and the new plaintext decrypts correctly).
 */

import { randomBytes, randomUUID } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

// Set env before any module is loaded.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Prisma mock
// ---------------------------------------------------------------------------

const mockCredentialCreate = vi.fn();
const mockCredentialFindUnique = vi.fn();
const mockCredentialFindFirst = vi.fn();
const mockCredentialUpdate = vi.fn();
const mockRepoCount = vi.fn().mockResolvedValue(0);
const mockAppSettingsCount = vi.fn().mockResolvedValue(0);

vi.mock("../src/db.js", () => ({
  prisma: {
    credential: {
      create: mockCredentialCreate,
      findUnique: mockCredentialFindUnique,
      findFirst: mockCredentialFindFirst,
      update: mockCredentialUpdate,
    },
    repo: { count: mockRepoCount },
    appSettings: { count: mockAppSettingsCount },
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a fake DB credential row from the data passed to prisma.credential.create */
function rowFromCreateData(data: Record<string, unknown>) {
  return {
    id: randomUUID(),
    orgId: data.orgId ?? null,
    kind: data.kind,
    name: data.name,
    ciphertext: data.ciphertext,
    nonce: data.nonce,
    tag: data.tag,
    keyVersion: data.keyVersion ?? 1,
    metadata: data.metadata ?? null,
    expiresAt: data.expiresAt ?? null,
    createdBy: data.createdBy ?? null,
    createdAt: new Date(),
    updatedAt: new Date(),
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createCredential — encryption", () => {
  it("stores ENCRYPTED blobs, not the plaintext secret (https_token)", async () => {
    const plaintext = "super-secret-token-abc123";

    mockCredentialCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      return Promise.resolve(rowFromCreateData(data));
    });

    const { createCredential } = await import("../src/services/credentialService.js");
    await createCredential({
      orgId: null,
      input: { kind: "https_token", name: "My Token", value: plaintext },
    });

    const callData = (
      mockCredentialCreate.mock.calls[0] as [{ data: Record<string, unknown> }]
    )[0].data;

    // The stored blobs must be Buffers (binary, not the UTF-8 string).
    expect(callData.ciphertext).toBeInstanceOf(Buffer);
    expect(callData.nonce).toBeInstanceOf(Buffer);
    expect(callData.tag).toBeInstanceOf(Buffer);

    // The ciphertext must NOT equal the plaintext as bytes.
    const ct = callData.ciphertext as Buffer;
    expect(ct.toString("utf8")).not.toBe(plaintext);
    expect(ct.equals(Buffer.from(plaintext, "utf8"))).toBe(false);

    vi.clearAllMocks();
  });

  it("each call produces a different ciphertext (random nonce)", async () => {
    const ciphertexts: Buffer[] = [];

    mockCredentialCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      ciphertexts.push(Buffer.from(data.ciphertext as Buffer));
      return Promise.resolve(rowFromCreateData(data));
    });

    const { createCredential } = await import("../src/services/credentialService.js");
    const input = { kind: "https_token" as const, name: "tok", value: "same-value" };
    await createCredential({ orgId: null, input });
    await createCredential({ orgId: null, input });

    expect(ciphertexts[0]).toBeDefined();
    expect(ciphertexts[1]).toBeDefined();
    // Two encrypts of the same plaintext must produce different ciphertexts.
    expect(ciphertexts[0]!.equals(ciphertexts[1]!)).toBe(false);

    vi.clearAllMocks();
  });
});

describe("decodeCredential — round-trip", () => {
  it("decodes https_token back to the original secret", async () => {
    const plaintext = "round-trip-secret";
    let storedRow: Record<string, unknown> | undefined;

    mockCredentialCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedRow = rowFromCreateData(data);
      return Promise.resolve(storedRow);
    });

    const { createCredential, decodeCredential } = await import(
      "../src/services/credentialService.js"
    );
    const row = await createCredential({
      orgId: null,
      input: { kind: "https_token", name: "tok", value: plaintext },
    });

    // Provide the stored row to findUnique so decodeCredential can decrypt it.
    mockCredentialFindUnique.mockResolvedValue(storedRow ?? row);

    const decoded = await decodeCredential(row.id);

    expect(decoded.kind).toBe("https_token");
    if (decoded.kind === "https_token") {
      expect(decoded.value).toBe(plaintext);
    }

    vi.clearAllMocks();
  });

  it("decodes https_basic including username from metadata", async () => {
    let storedRow: Record<string, unknown> | undefined;

    mockCredentialCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedRow = rowFromCreateData(data);
      return Promise.resolve(storedRow);
    });

    const { createCredential, decodeCredential } = await import(
      "../src/services/credentialService.js"
    );
    const row = await createCredential({
      orgId: null,
      input: { kind: "https_basic", name: "basic-cred", username: "alice", password: "p@ssw0rd!" },
    });

    mockCredentialFindUnique.mockResolvedValue(storedRow ?? row);
    const decoded = await decodeCredential(row.id);

    expect(decoded.kind).toBe("https_basic");
    if (decoded.kind === "https_basic") {
      expect(decoded.username).toBe("alice");
      expect(decoded.password).toBe("p@ssw0rd!");
    }

    vi.clearAllMocks();
  });

  it("throws CredentialNotFoundError when the row is absent", async () => {
    mockCredentialFindUnique.mockResolvedValue(null);

    const { decodeCredential, CredentialNotFoundError } = await import(
      "../src/services/credentialService.js"
    );
    await expect(decodeCredential(randomUUID())).rejects.toBeInstanceOf(CredentialNotFoundError);

    vi.clearAllMocks();
  });
});

describe("getPlaintext", () => {
  it("returns the correct raw plaintext buffer for an existing credential", async () => {
    const plaintext = "raw-secret-buffer";
    let storedRow: Record<string, unknown> | undefined;

    mockCredentialCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedRow = rowFromCreateData(data);
      return Promise.resolve(storedRow);
    });

    const { createCredential, getPlaintext } = await import(
      "../src/services/credentialService.js"
    );
    const row = await createCredential({
      orgId: null,
      input: { kind: "https_token", name: "tok", value: plaintext },
    });

    mockCredentialFindUnique.mockResolvedValue(storedRow ?? row);
    const buf = await getPlaintext(row.id);

    expect(buf.toString("utf8")).toBe(plaintext);

    vi.clearAllMocks();
  });
});

describe("rotateCredential", () => {
  it("re-encrypts with the new value; old ciphertext is replaced", async () => {
    const originalSecret = "original-value";
    const rotatedSecret = "rotated-new-value";
    let storedRow: Record<string, unknown> | undefined;

    // createCredential → capture the row
    mockCredentialCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedRow = rowFromCreateData(data);
      return Promise.resolve(storedRow);
    });

    const { createCredential, rotateCredential, getPlaintext } = await import(
      "../src/services/credentialService.js"
    );

    const row = await createCredential({
      orgId: null,
      input: { kind: "https_token", name: "tok", value: originalSecret },
    });

    // getCredential inside rotateCredential calls findFirst
    mockCredentialFindFirst.mockResolvedValue(storedRow ?? row);

    // rotateCredential calls credential.update — capture the new row
    let updatedRow: Record<string, unknown> | undefined;
    mockCredentialUpdate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      updatedRow = { ...(storedRow ?? row), ...data };
      return Promise.resolve(updatedRow);
    });

    await rotateCredential(row.id, null, { kind: "https_token", value: rotatedSecret });

    // The update must have been called with new encrypted blobs.
    const updateData = (
      mockCredentialUpdate.mock.calls[0] as [{ data: Record<string, unknown> }]
    )[0].data;
    expect(updateData.ciphertext).toBeInstanceOf(Buffer);

    // The new ciphertext must differ from the original.
    const originalCt = (storedRow ?? row).ciphertext as Buffer;
    const newCt = updateData.ciphertext as Buffer;
    expect(newCt.equals(originalCt)).toBe(false);

    // Decrypt the rotated row — should yield the rotated secret.
    mockCredentialFindUnique.mockResolvedValue(updatedRow);
    const buf = await getPlaintext(row.id);
    expect(buf.toString("utf8")).toBe(rotatedSecret);

    vi.clearAllMocks();
  });
});
