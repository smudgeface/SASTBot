/**
 * Unit tests for the master-key rewrap helpers (src/services/keyRewrap.ts).
 *
 * Covers:
 *   - rewrapBlob round-trip: A-encrypted blob, rewrapped A→B, decrypts under B
 *     and FAILS under A.
 *   - decideKeyAction: the full-restore MASTER_KEY gate decision table.
 *   - rewrapAllSecrets: canary + credentials re-keyed atomically; aborts before
 *     any write when the canary doesn't verify under the source key; rejects
 *     identical / wrong-length keys.
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { encrypt, decrypt, CANARY_PLAINTEXT } from "../src/security/crypto.js";

beforeAll(() => {
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
});

// The rewrap functions accept an explicit client; the real prisma singleton is
// never queried. Mock db.js so importing keyRewrap doesn't construct a client.
vi.mock("../src/db.js", () => ({ prisma: {} }));

afterEach(() => {
  vi.clearAllMocks();
});

const KEY_A = randomBytes(32);
const KEY_B = randomBytes(32);

describe("rewrapBlob", () => {
  it("re-encrypts a blob from A to B so it decrypts under B but not A", async () => {
    const { rewrapBlob } = await import("../src/services/keyRewrap.js");
    const plaintext = Buffer.from("super-secret-token");
    const a = encrypt(plaintext, KEY_A);

    const b = rewrapBlob(a, KEY_A, KEY_B);

    // Decrypts under B → original plaintext.
    expect(decrypt(b.ciphertext, b.nonce, b.tag, KEY_B).equals(plaintext)).toBe(true);
    // Fails under A (GCM auth tag mismatch).
    expect(() => decrypt(b.ciphertext, b.nonce, b.tag, KEY_A)).toThrow();
    // A fresh nonce was generated (not reused from the A blob).
    expect(b.nonce.equals(a.nonce)).toBe(false);
  });
});

describe("decideKeyAction", () => {
  it("proceeds when the fingerprints match", async () => {
    const { decideKeyAction } = await import("../src/services/keyRewrap.js");
    expect(decideKeyAction({ dumpFp: "aaaa", runningFp: "aaaa" })).toBe("proceed");
  });

  it("proceeds for a legacy dump with no fingerprint (key ignored)", async () => {
    const { decideKeyAction } = await import("../src/services/keyRewrap.js");
    expect(decideKeyAction({ dumpFp: undefined, runningFp: "aaaa" })).toBe("proceed");
    expect(decideKeyAction({ dumpFp: undefined, runningFp: "aaaa", oldKeyFp: "bbbb" })).toBe("proceed");
  });

  it("refuses (no key) when fingerprints differ and no source key supplied", async () => {
    const { decideKeyAction } = await import("../src/services/keyRewrap.js");
    expect(decideKeyAction({ dumpFp: "aaaa", runningFp: "bbbb" })).toBe("refuse_no_key");
  });

  it("refuses (wrong key) when the supplied source key doesn't match the backup", async () => {
    const { decideKeyAction } = await import("../src/services/keyRewrap.js");
    expect(decideKeyAction({ dumpFp: "aaaa", runningFp: "bbbb", oldKeyFp: "cccc" })).toBe(
      "refuse_wrong_key",
    );
  });

  it("rewraps when fingerprints differ and the supplied source key matches the backup", async () => {
    const { decideKeyAction } = await import("../src/services/keyRewrap.js");
    expect(decideKeyAction({ dumpFp: "aaaa", runningFp: "bbbb", oldKeyFp: "aaaa" })).toBe("rewrap");
  });
});

// ---------------------------------------------------------------------------
// rewrapAllSecrets — transactional canary + credentials re-key
// ---------------------------------------------------------------------------

/**
 * Build a mock Prisma client whose canary + credentials are encrypted under
 * `srcKey`. Captures every update so tests can assert the re-encrypted bytes.
 */
function makeMockClient(srcKey: Buffer, credCount: number) {
  const canaryBlob = encrypt(CANARY_PLAINTEXT, srcKey);
  const canaryRow = {
    id: "canary-1",
    ciphertext: canaryBlob.ciphertext,
    nonce: canaryBlob.nonce,
    tag: canaryBlob.tag,
  };
  const credRows = Array.from({ length: credCount }, (_, i) => {
    const blob = encrypt(Buffer.from(`secret-${i}`), srcKey);
    return { id: `cred-${i}`, ciphertext: blob.ciphertext, nonce: blob.nonce, tag: blob.tag };
  });

  const canaryUpdate = vi.fn();
  const credUpdate = vi.fn();

  const tx = {
    canary: {
      findFirst: vi.fn().mockResolvedValue(canaryRow),
      update: canaryUpdate,
    },
    credential: {
      findMany: vi.fn().mockResolvedValue(credRows),
      update: credUpdate,
    },
  };

  const client = {
    $transaction: vi.fn(async (fn: (t: typeof tx) => Promise<unknown>) => fn(tx)),
  };

  return { client, tx, canaryUpdate, credUpdate, credRows };
}

describe("rewrapAllSecrets", () => {
  it("re-keys the canary and every credential to the new key, atomically", async () => {
    const { rewrapAllSecrets } = await import("../src/services/keyRewrap.js");
    const { client, canaryUpdate, credUpdate } = makeMockClient(KEY_A, 3);

    const counts = await rewrapAllSecrets(
      KEY_A,
      KEY_B,
      client as unknown as Parameters<typeof rewrapAllSecrets>[2],
    );

    expect(counts).toEqual({ canary: 1, credentials: 3 });
    expect(client.$transaction).toHaveBeenCalledOnce();

    // Canary re-encrypted under B → decrypts to the sentinel.
    expect(canaryUpdate).toHaveBeenCalledOnce();
    const cd = (canaryUpdate.mock.calls[0] as [{ data: { ciphertext: Buffer; nonce: Buffer; tag: Buffer } }])[0].data;
    expect(decrypt(cd.ciphertext, cd.nonce, cd.tag, KEY_B).equals(CANARY_PLAINTEXT)).toBe(true);

    // Each credential re-encrypted under B → decrypts to its original plaintext.
    expect(credUpdate).toHaveBeenCalledTimes(3);
    for (let i = 0; i < 3; i++) {
      const d = (credUpdate.mock.calls[i] as [{ data: { ciphertext: Buffer; nonce: Buffer; tag: Buffer } }])[0].data;
      expect(decrypt(d.ciphertext, d.nonce, d.tag, KEY_B).toString()).toBe(`secret-${i}`);
      // And NOT decryptable under the old key.
      expect(() => decrypt(d.ciphertext, d.nonce, d.tag, KEY_A)).toThrow();
    }
  });

  it("aborts before touching any credential when the canary doesn't decrypt under the source key", async () => {
    const { rewrapAllSecrets, KeyRewrapError } = await import("../src/services/keyRewrap.js");
    // Canary is encrypted under A, but we claim the source key is a WRONG key.
    const wrongSource = randomBytes(32);
    const { client, canaryUpdate, credUpdate } = makeMockClient(KEY_A, 2);

    await expect(
      rewrapAllSecrets(
        wrongSource,
        KEY_B,
        client as unknown as Parameters<typeof rewrapAllSecrets>[2],
      ),
    ).rejects.toBeInstanceOf(KeyRewrapError);

    // No writes happened.
    expect(canaryUpdate).not.toHaveBeenCalled();
    expect(credUpdate).not.toHaveBeenCalled();
  });

  it("rejects identical source and target keys", async () => {
    const { rewrapAllSecrets, KeyRewrapError } = await import("../src/services/keyRewrap.js");
    const { client } = makeMockClient(KEY_A, 1);
    await expect(
      rewrapAllSecrets(KEY_A, KEY_A, client as unknown as Parameters<typeof rewrapAllSecrets>[2]),
    ).rejects.toBeInstanceOf(KeyRewrapError);
  });

  it("rejects wrong-length keys", async () => {
    const { rewrapAllSecrets, KeyRewrapError } = await import("../src/services/keyRewrap.js");
    const { client } = makeMockClient(KEY_A, 1);
    await expect(
      rewrapAllSecrets(
        randomBytes(16),
        KEY_B,
        client as unknown as Parameters<typeof rewrapAllSecrets>[2],
      ),
    ).rejects.toBeInstanceOf(KeyRewrapError);
  });
});
