/**
 * Master-key rewrap.
 *
 * Re-encrypts every AES-GCM-encrypted blob in the database from one MASTER_KEY
 * to another. Used by two operator flows:
 *
 *   1. Re-key on restore (routes/adminRestore.ts) — a full backup taken under
 *      KEY_OLD is restored onto an instance running KEY_NEW; the restored canary
 *      + credentials are KEY_OLD-encrypted and get rewrapped to KEY_NEW so the
 *      instance keeps its own key.
 *   2. In-place MASTER_KEY rotation (routes/adminKeyRotation.ts) — the running
 *      instance's data (KEY_CURRENT) is rewrapped to a fresh KEY_NEW that the
 *      operator then sets in the environment + restarts.
 *
 * The complete inventory of encrypted columns (audited 2026-06-01) is exactly
 * two tables, both with (ciphertext, nonce, tag):
 *   - encryption_canary  (security/crypto.ts)
 *   - credentials        (services/credentialService.ts)
 * `app_settings` references credentials by ID only — no inline ciphertext.
 * If a new encrypted column is ever added, it MUST be rewrapped here too, or a
 * cross-key migration silently half-migrates. This file is the single source of
 * truth for "what holds key-bound ciphertext".
 */

import { Prisma } from "@prisma/client";
import type { PrismaClient } from "@prisma/client";

import { prisma } from "../db.js";
import { CANARY_PLAINTEXT, decrypt, encrypt } from "../security/crypto.js";

type Tx = PrismaClient | Prisma.TransactionClient;

export class KeyRewrapError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "KeyRewrapError";
  }
}

/**
 * Decision for a full restore's MASTER_KEY gate. Pure — operates on fingerprints
 * only so it's exhaustively unit-testable.
 *
 *   - proceed           → restore as-is (keys match, or legacy dump with no
 *                         fingerprint to compare — the boot-time canary backstops)
 *   - rewrap            → keys differ but the operator supplied a source key whose
 *                         fingerprint matches the backup → re-key the dump on restore
 *   - refuse_no_key     → keys differ and no source key was supplied (the v0.18.0
 *                         "set MASTER_KEY first" behaviour)
 *   - refuse_wrong_key  → keys differ and the supplied source key does NOT match
 *                         the backup → a doomed rewrap; refuse before pg_restore
 *
 * Note: a legacy (no-fingerprint) dump always returns `proceed`; rewrap-on-restore
 * requires a fingerprinted backup (v0.18.0+) so we can verify the supplied key.
 */
export type KeyAction = "proceed" | "rewrap" | "refuse_no_key" | "refuse_wrong_key";

export function decideKeyAction(params: {
  dumpFp?: string;
  runningFp: string;
  oldKeyFp?: string;
}): KeyAction {
  const { dumpFp, runningFp, oldKeyFp } = params;
  if (!dumpFp) return "proceed";
  if (dumpFp === runningFp) return "proceed";
  if (!oldKeyFp) return "refuse_no_key";
  if (oldKeyFp !== dumpFp) return "refuse_wrong_key";
  return "rewrap";
}

export interface RewrapCounts {
  /** Always 0 or 1 — there is a single canary row. */
  canary: number;
  /** Number of credential rows re-encrypted. */
  credentials: number;
}

/**
 * Re-encrypt a single AES-GCM blob from `oldKey` to `newKey`.
 *
 * Pure — no DB access. Exposed for unit testing the round-trip property
 * (rewrapped blob decrypts under newKey, fails under oldKey).
 */
export function rewrapBlob(
  blob: { ciphertext: Buffer; nonce: Buffer; tag: Buffer },
  oldKey: Buffer,
  newKey: Buffer,
): { ciphertext: Buffer; nonce: Buffer; tag: Buffer } {
  const plaintext = decrypt(blob.ciphertext, blob.nonce, blob.tag, oldKey);
  return encrypt(plaintext, newKey);
}

/**
 * Re-encrypt the canary + every credential from `oldKey` to `newKey`, atomically.
 *
 * Runs in a single `$transaction` so a failure part-way through rolls back —
 * there are never mixed-key rows committed. Before touching any credential it
 * sanity-checks that the canary decrypts under `oldKey` and yields the expected
 * sentinel; a failure there aborts before any write, which protects against
 * rewrapping with a key that doesn't actually own the data.
 *
 * Callers MUST have already verified `oldKey` against the data's source (the
 * restore path matches `masterKeyFingerprint(oldKey)` to the backup metadata;
 * the rotation path uses the running instance's own key as `oldKey`). The
 * canary check here is the second, defence-in-depth gate.
 *
 * @throws KeyRewrapError on a missing/undecryptable/mismatched canary.
 */
export async function rewrapAllSecrets(
  oldKey: Buffer,
  newKey: Buffer,
  client: Tx = prisma,
): Promise<RewrapCounts> {
  if (oldKey.length !== 32 || newKey.length !== 32) {
    throw new KeyRewrapError("rewrap keys must each be exactly 32 bytes");
  }
  if (oldKey.equals(newKey)) {
    throw new KeyRewrapError("source and target keys are identical — nothing to rewrap");
  }

  const run = async (tx: Tx): Promise<RewrapCounts> => {
    // 1. Canary sanity-check under the OLD key — abort before any write if it
    //    fails. This proves oldKey owns the data we are about to rewrap.
    const canary = await tx.canary.findFirst();
    if (!canary) {
      throw new KeyRewrapError(
        "no encryption canary row found — cannot verify the source key before rewrapping",
      );
    }
    let canaryPlain: Buffer;
    try {
      canaryPlain = decrypt(
        Buffer.from(canary.ciphertext),
        Buffer.from(canary.nonce),
        Buffer.from(canary.tag),
        oldKey,
      );
    } catch (err) {
      throw new KeyRewrapError(
        `the canary did not decrypt under the supplied source key — aborting rewrap before any data was changed (${(err as Error).message})`,
      );
    }
    if (!canaryPlain.equals(CANARY_PLAINTEXT)) {
      throw new KeyRewrapError(
        "the canary decrypted under the source key but its plaintext did not match — aborting rewrap before any data was changed",
      );
    }

    // 2. Rewrap the canary itself.
    const newCanary = encrypt(canaryPlain, newKey);
    await tx.canary.update({
      where: { id: canary.id },
      data: { ciphertext: newCanary.ciphertext, nonce: newCanary.nonce, tag: newCanary.tag },
    });

    // 3. Rewrap every credential.
    const credentials = await tx.credential.findMany({
      select: { id: true, ciphertext: true, nonce: true, tag: true },
    });
    for (const cred of credentials) {
      const rewrapped = rewrapBlob(
        {
          ciphertext: Buffer.from(cred.ciphertext),
          nonce: Buffer.from(cred.nonce),
          tag: Buffer.from(cred.tag),
        },
        oldKey,
        newKey,
      );
      await tx.credential.update({
        where: { id: cred.id },
        data: {
          ciphertext: rewrapped.ciphertext,
          nonce: rewrapped.nonce,
          tag: rewrapped.tag,
        },
      });
    }

    return { canary: 1, credentials: credentials.length };
  };

  // If the caller already handed us a transaction client, run inline; otherwise
  // open our own transaction so the whole rewrap is all-or-nothing.
  if ("$transaction" in client) {
    return (client as PrismaClient).$transaction((tx) => run(tx));
  }
  return run(client);
}
