import { randomBytes } from "node:crypto";

import { describe, expect, it } from "vitest";

import { decrypt, encrypt } from "../src/security/crypto.js";

function makeKey(): Buffer {
  return randomBytes(32);
}

describe("AES-256-GCM envelope", () => {
  it("round-trips plaintext via encrypt + decrypt", () => {
    const key = makeKey();
    const plaintext = Buffer.from("hunter2 / the quick brown fox / 🔐");
    const blob = encrypt(plaintext, key);

    expect(blob.nonce.length).toBe(12);
    expect(blob.tag.length).toBe(16);
    expect(blob.ciphertext.length).toBe(plaintext.length);

    const recovered = decrypt(blob.ciphertext, blob.nonce, blob.tag, key);
    expect(recovered.toString("utf8")).toBe(plaintext.toString("utf8"));
  });

  it("produces a fresh nonce per call", () => {
    const key = makeKey();
    const pt = Buffer.from("same plaintext");
    const a = encrypt(pt, key);
    const b = encrypt(pt, key);
    expect(a.nonce.equals(b.nonce)).toBe(false);
    expect(a.ciphertext.equals(b.ciphertext)).toBe(false);
  });

  it("rejects a tampered ciphertext", () => {
    const key = makeKey();
    const blob = encrypt(Buffer.from("don't-tamper-with-me"), key);
    const tampered = Buffer.from(blob.ciphertext);
    tampered[0] = tampered[0] ^ 0xff;
    expect(() => decrypt(tampered, blob.nonce, blob.tag, key)).toThrow();
  });

  it("rejects a tampered auth tag", () => {
    const key = makeKey();
    const blob = encrypt(Buffer.from("tag-matters"), key);
    const tag = Buffer.from(blob.tag);
    tag[0] = tag[0] ^ 0xff;
    expect(() => decrypt(blob.ciphertext, blob.nonce, tag, key)).toThrow();
  });

  it("rejects decryption under the wrong key", () => {
    const k1 = makeKey();
    const k2 = makeKey();
    const blob = encrypt(Buffer.from("key-mismatch"), k1);
    expect(() => decrypt(blob.ciphertext, blob.nonce, blob.tag, k2)).toThrow();
  });
});
