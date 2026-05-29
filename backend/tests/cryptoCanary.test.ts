/**
 * Unit tests for ensureCanary() in backend/src/security/crypto.ts.
 *
 * Does NOT duplicate the encrypt/decrypt tests in crypto.test.ts.
 *
 * Covers:
 *   (a) No canary row present → creates one with encrypted canary plaintext.
 *   (b) Canary present + correct MASTER_KEY → no throw.
 *   (c) Canary present + WRONG key (ciphertext mismatch) → throws CryptoCanaryError.
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

// We need a valid 32-byte MASTER_KEY for the real crypto to work.
const TEST_KEY = randomBytes(32).toString("base64");

beforeAll(() => {
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Prisma mock — registered before importing the module under test
// ---------------------------------------------------------------------------

const mockCanaryFindFirst = vi.fn();
const mockCanaryCreate = vi.fn();

vi.mock("../src/db.js", () => ({
  prisma: {
    canary: {
      findFirst: mockCanaryFindFirst,
      create: mockCanaryCreate,
    },
  },
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

afterEach(() => {
  vi.clearAllMocks();
});

describe("ensureCanary", () => {
  it("creates a canary row when none exists", async () => {
    process.env.MASTER_KEY = TEST_KEY;
    // Reset config cache so it picks up our key.
    const { _resetConfigForTests } = await import("../src/config.js");
    _resetConfigForTests();

    mockCanaryFindFirst.mockResolvedValue(null);
    mockCanaryCreate.mockResolvedValue({ id: "1", keyVersion: 1 });

    const { ensureCanary } = await import("../src/security/crypto.js");
    await expect(ensureCanary()).resolves.toBeUndefined();

    // Must have checked for an existing row.
    expect(mockCanaryFindFirst).toHaveBeenCalledOnce();

    // Must have created a new row with encrypted data.
    expect(mockCanaryCreate).toHaveBeenCalledOnce();
    const createCall = (
      mockCanaryCreate.mock.calls[0] as [{ data: Record<string, unknown> }]
    )[0].data;
    expect(createCall.ciphertext).toBeInstanceOf(Buffer);
    expect(createCall.nonce).toBeInstanceOf(Buffer);
    expect(createCall.tag).toBeInstanceOf(Buffer);
    expect(createCall.keyVersion).toBe(1);
  });

  it("does NOT create a row when one already exists with the correct key", async () => {
    process.env.MASTER_KEY = TEST_KEY;
    const { _resetConfigForTests } = await import("../src/config.js");
    _resetConfigForTests();

    // First call with no row — create it so we have a real encrypted canary.
    mockCanaryFindFirst.mockResolvedValueOnce(null);
    let storedCanary: Record<string, unknown> | null = null;
    mockCanaryCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedCanary = { id: "1", keyVersion: 1, ...data };
      return Promise.resolve(storedCanary);
    });

    const { ensureCanary } = await import("../src/security/crypto.js");
    await ensureCanary();

    // Second call — row already exists with the correct encryption.
    mockCanaryFindFirst.mockResolvedValueOnce(storedCanary);
    mockCanaryCreate.mockClear();

    await expect(ensureCanary()).resolves.toBeUndefined();

    // Should NOT have created a second row.
    expect(mockCanaryCreate).not.toHaveBeenCalled();
  });

  it("throws CryptoCanaryError when the canary is encrypted with a DIFFERENT key", async () => {
    // Encrypt the canary with KEY_A, then try to verify it with KEY_B.
    const keyA = randomBytes(32).toString("base64");
    const keyB = randomBytes(32).toString("base64");

    const { _resetConfigForTests } = await import("../src/config.js");

    // --- Step 1: create canary with keyA ---
    process.env.MASTER_KEY = keyA;
    _resetConfigForTests();

    mockCanaryFindFirst.mockResolvedValueOnce(null);
    let storedCanary: Record<string, unknown> | null = null;
    mockCanaryCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedCanary = { id: "1", keyVersion: 1, ...data };
      return Promise.resolve(storedCanary);
    });

    const { ensureCanary } = await import("../src/security/crypto.js");
    await ensureCanary();

    // --- Step 2: verify with keyB (wrong key) → must throw ---
    process.env.MASTER_KEY = keyB;
    _resetConfigForTests();

    mockCanaryFindFirst.mockResolvedValueOnce(storedCanary);

    const { CryptoCanaryError } = await import("../src/security/crypto.js");
    await expect(ensureCanary()).rejects.toBeInstanceOf(CryptoCanaryError);
  });

  it("throws CryptoCanaryError with a message that mentions the canary failure", async () => {
    const keyA = randomBytes(32).toString("base64");
    const keyB = randomBytes(32).toString("base64");

    const { _resetConfigForTests } = await import("../src/config.js");

    process.env.MASTER_KEY = keyA;
    _resetConfigForTests();
    mockCanaryFindFirst.mockResolvedValueOnce(null);
    let storedCanary: Record<string, unknown> | null = null;
    mockCanaryCreate.mockImplementation(({ data }: { data: Record<string, unknown> }) => {
      storedCanary = { id: "1", keyVersion: 1, ...data };
      return Promise.resolve(storedCanary);
    });
    const { ensureCanary } = await import("../src/security/crypto.js");
    await ensureCanary();

    process.env.MASTER_KEY = keyB;
    _resetConfigForTests();
    mockCanaryFindFirst.mockResolvedValueOnce(storedCanary);

    let thrown: unknown;
    try {
      await ensureCanary();
    } catch (e) {
      thrown = e;
    }

    expect(thrown).toBeDefined();
    expect((thrown as Error).message).toMatch(/canary/i);
  });
});
