/**
 * Unit tests for backend/src/security/sessions.ts
 *
 * Verifies:
 *   (a) createSession stores a SHA-256 HASH of the token, not the raw token.
 *   (b) getUserFromToken returns the user for a valid, unexpired, active session.
 *   (c) Unknown token returns null.
 *   (d) Expired session row returns null.
 *   (e) revokeSession deletes the row and the token no longer resolves.
 */

import { createHash, randomBytes, randomUUID } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Prisma mock — registered before importing the module under test
// ---------------------------------------------------------------------------

const mockSessionCreate = vi.fn();
const mockSessionFindUnique = vi.fn();
const mockSessionDeleteMany = vi.fn();
const mockSessionDelete = vi.fn();

vi.mock("../src/db.js", () => ({
  prisma: {
    session: {
      create: mockSessionCreate,
      findUnique: mockSessionFindUnique,
      deleteMany: mockSessionDeleteMany,
      delete: mockSessionDelete,
    },
  },
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function makeActiveUser(overrides: Record<string, unknown> = {}) {
  return {
    id: randomUUID(),
    email: "test@example.com",
    isActive: true,
    isAdmin: false,
    ...overrides,
  };
}

function makeSessionRow(tokenStr: string, expiresAt: Date, user: ReturnType<typeof makeActiveUser>) {
  return {
    id: randomUUID(),
    userId: user.id,
    tokenHash: sha256(tokenStr),
    expiresAt,
    userAgent: null,
    ipAddress: null,
    user,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("createSession", () => {
  it("stores the SHA-256 hash of the token, not the raw token", async () => {
    const user = makeActiveUser();
    mockSessionCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      return Promise.resolve({
        id: randomUUID(),
        userId: user.id,
        tokenHash: data.tokenHash,
        expiresAt: data.expiresAt,
        userAgent: null,
        ipAddress: null,
      });
    });

    const { createSession } = await import("../src/security/sessions.js");
    const issued = await createSession(user.id, "Mozilla/5.0", "127.0.0.1");

    expect(issued.tokenStr).toBeTruthy();
    expect(issued.tokenStr.length).toBeGreaterThan(20);

    // The token stored in the DB must be the SHA-256 hash of the raw token.
    const expectedHash = sha256(issued.tokenStr);
    expect(mockSessionCreate).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          tokenHash: expectedHash,
        }),
      }),
    );

    // The DB must NOT store the raw token.
    const storedHash = (mockSessionCreate.mock.calls[0] as [{ data: Record<string, unknown> }])[0].data.tokenHash as string;
    expect(storedHash).not.toBe(issued.tokenStr);

    vi.clearAllMocks();
  });

  it("returns the raw token to the caller (not the hash)", async () => {
    const user = makeActiveUser();
    mockSessionCreate.mockResolvedValue({
      id: randomUUID(),
      userId: user.id,
      tokenHash: "will-be-replaced-by-hash",
      expiresAt: new Date(Date.now() + 3600_000),
      userAgent: null,
      ipAddress: null,
    });

    const { createSession } = await import("../src/security/sessions.js");
    const issued = await createSession(user.id);

    // The tokenStr returned to the caller must NOT be a SHA-256 hex string
    // (64 hex chars); it is a base64url random token.
    expect(issued.tokenStr.length).not.toBe(64);

    vi.clearAllMocks();
  });
});

describe("getUserFromToken", () => {
  it("returns the user for a valid, unexpired, active session", async () => {
    const user = makeActiveUser();
    const tokenStr = randomBytes(32).toString("base64url");
    const sessionRow = makeSessionRow(tokenStr, new Date(Date.now() + 3600_000), user);

    mockSessionFindUnique.mockResolvedValue(sessionRow);

    const { getUserFromToken } = await import("../src/security/sessions.js");
    const result = await getUserFromToken(tokenStr);

    expect(result).not.toBeNull();
    expect(result?.id).toBe(user.id);
    expect(result?.email).toBe(user.email);

    vi.clearAllMocks();
  });

  it("returns null for an unknown token", async () => {
    mockSessionFindUnique.mockResolvedValue(null);

    const { getUserFromToken } = await import("../src/security/sessions.js");
    const result = await getUserFromToken("not-a-real-token");

    expect(result).toBeNull();

    vi.clearAllMocks();
  });

  it("returns null when the token is undefined or null", async () => {
    const { getUserFromToken } = await import("../src/security/sessions.js");

    expect(await getUserFromToken(undefined)).toBeNull();
    expect(await getUserFromToken(null)).toBeNull();

    // Should not have queried the DB.
    expect(mockSessionFindUnique).not.toHaveBeenCalled();

    vi.clearAllMocks();
  });

  it("returns null for an expired session row", async () => {
    const user = makeActiveUser();
    const tokenStr = randomBytes(32).toString("base64url");
    // expiresAt is 1 ms in the past
    const sessionRow = makeSessionRow(tokenStr, new Date(Date.now() - 1), user);

    // Best-effort cleanup — the impl calls prisma.session.delete().catch(); mock it
    mockSessionDelete.mockResolvedValue({});
    mockSessionFindUnique.mockResolvedValue(sessionRow);

    const { getUserFromToken } = await import("../src/security/sessions.js");
    const result = await getUserFromToken(tokenStr);

    expect(result).toBeNull();

    vi.clearAllMocks();
  });

  it("returns null for an inactive user", async () => {
    const inactiveUser = makeActiveUser({ isActive: false });
    const tokenStr = randomBytes(32).toString("base64url");
    const sessionRow = makeSessionRow(tokenStr, new Date(Date.now() + 3600_000), inactiveUser);

    mockSessionFindUnique.mockResolvedValue(sessionRow);

    const { getUserFromToken } = await import("../src/security/sessions.js");
    const result = await getUserFromToken(tokenStr);

    expect(result).toBeNull();

    vi.clearAllMocks();
  });

  it("queries Prisma with the SHA-256 hash of the token (not the raw token)", async () => {
    const tokenStr = randomBytes(32).toString("base64url");
    mockSessionFindUnique.mockResolvedValue(null);

    const { getUserFromToken } = await import("../src/security/sessions.js");
    await getUserFromToken(tokenStr);

    expect(mockSessionFindUnique).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { tokenHash: sha256(tokenStr) },
      }),
    );

    vi.clearAllMocks();
  });
});

describe("revokeSession", () => {
  it("deletes the session row for the given token", async () => {
    const tokenStr = randomBytes(32).toString("base64url");
    mockSessionDeleteMany.mockResolvedValue({ count: 1 });

    const { revokeSession } = await import("../src/security/sessions.js");
    await revokeSession(tokenStr);

    expect(mockSessionDeleteMany).toHaveBeenCalledWith({
      where: { tokenHash: sha256(tokenStr) },
    });

    vi.clearAllMocks();
  });

  it("token no longer resolves after revoke (no row found)", async () => {
    const tokenStr = randomBytes(32).toString("base64url");
    mockSessionDeleteMany.mockResolvedValue({ count: 1 });
    // After revoke, the session row is gone → findUnique returns null.
    mockSessionFindUnique.mockResolvedValue(null);

    const { revokeSession, getUserFromToken } = await import("../src/security/sessions.js");
    await revokeSession(tokenStr);
    const result = await getUserFromToken(tokenStr);

    expect(result).toBeNull();

    vi.clearAllMocks();
  });

  it("is a no-op when token is undefined or null (does not throw)", async () => {
    const { revokeSession } = await import("../src/security/sessions.js");
    await expect(revokeSession(undefined)).resolves.toBeUndefined();
    await expect(revokeSession(null)).resolves.toBeUndefined();

    expect(mockSessionDeleteMany).not.toHaveBeenCalled();

    vi.clearAllMocks();
  });
});
