import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

import { loadConfig } from "../config.js";
import { prisma } from "../db.js";

/**
 * AES-256-GCM envelope.
 *
 * Storage convention (differs from the Python version on purpose — Node's
 * crypto API separates the auth tag from the ciphertext):
 *   - `ciphertext`: raw AES-GCM ciphertext WITHOUT the tag appended.
 *   - `nonce`:      12-byte IV generated per-encrypt.
 *   - `tag`:        16-byte GCM auth tag, stored in its own column.
 */

const ALGO = "aes-256-gcm";
const IV_BYTES = 12;
const TAG_BYTES = 16;
const CANARY_PLAINTEXT = Buffer.from("sastbot-canary-v1");

export class CryptoConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoConfigError";
  }
}

export class CryptoCanaryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoCanaryError";
  }
}

export function loadMasterKey(): Buffer {
  const key = loadConfig().masterKey;
  if (key.length !== 32) {
    throw new CryptoConfigError(
      `MASTER_KEY must decode to 32 bytes (got ${key.length})`,
    );
  }
  return key;
}

// Fixed domain-separation label for the master-key fingerprint. Bumping the
// suffix would change every fingerprint — don't, or old backups stop matching.
const KEY_FINGERPRINT_LABEL = "sastbot-master-key-fingerprint-v1";

/**
 * Deterministic, non-reversible fingerprint of the master key.
 *
 * Embedded in backup metadata so a restore can detect a MASTER_KEY mismatch
 * BEFORE applying the dump — a full dump carries the encryption canary + all
 * credential ciphertexts encrypted under the source key, so restoring under a
 * different key bricks the canary on next boot and orphans every credential.
 *
 * HMAC(key, label) is one-way: the fingerprint reveals nothing about the key,
 * so it is safe to store in plaintext metadata. 16 hex chars (64 bits) is ample
 * to answer "same key or not?" — this is an equality check, not a secret.
 */
export function masterKeyFingerprint(key: Buffer = loadMasterKey()): string {
  return createHmac("sha256", key).update(KEY_FINGERPRINT_LABEL).digest("hex").slice(0, 16);
}

export interface EncryptedBlob {
  ciphertext: Buffer;
  nonce: Buffer;
  tag: Buffer;
}

export function encrypt(plaintext: Buffer, key: Buffer = loadMasterKey()): EncryptedBlob {
  const nonce = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGO, key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ciphertext, nonce, tag };
}

export function decrypt(
  ciphertext: Buffer,
  nonce: Buffer,
  tag: Buffer,
  key: Buffer = loadMasterKey(),
): Buffer {
  if (nonce.length !== IV_BYTES) {
    throw new CryptoConfigError(`nonce must be ${IV_BYTES} bytes`);
  }
  if (tag.length !== TAG_BYTES) {
    throw new CryptoConfigError(`tag must be ${TAG_BYTES} bytes`);
  }
  const decipher = createDecipheriv(ALGO, key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

/**
 * Verify — or lazily create — the encryption canary row. Call this once at
 * startup to fail fast if MASTER_KEY is wrong.
 */
export async function ensureCanary(): Promise<void> {
  const key = loadMasterKey();
  const existing = await prisma.canary.findFirst();
  if (!existing) {
    const blob = encrypt(CANARY_PLAINTEXT, key);
    await prisma.canary.create({
      data: {
        ciphertext: blob.ciphertext,
        nonce: blob.nonce,
        tag: blob.tag,
        keyVersion: 1,
      },
    });
    return;
  }

  let decrypted: Buffer;
  try {
    decrypted = decrypt(
      Buffer.from(existing.ciphertext),
      Buffer.from(existing.nonce),
      Buffer.from(existing.tag),
      key,
    );
  } catch (err) {
    throw new CryptoCanaryError(
      `Encryption canary failed to decrypt — MASTER_KEY is wrong or data is corrupted. (${(err as Error).message})`,
    );
  }
  if (!decrypted.equals(CANARY_PLAINTEXT)) {
    throw new CryptoCanaryError(
      "Encryption canary decrypted but plaintext does not match — refusing to start.",
    );
  }
}
