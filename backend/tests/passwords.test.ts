import { describe, expect, it } from "vitest";

import { hashPassword, verifyPassword } from "../src/security/passwords.js";

describe("password hashing", () => {
  it("hashes and verifies a correct password", async () => {
    const hashed = await hashPassword("correct horse battery staple");
    expect(hashed).not.toBe("correct horse battery staple");
    expect(hashed.length).toBeGreaterThan(20);

    const ok = await verifyPassword("correct horse battery staple", hashed);
    expect(ok).toBe(true);
  });

  it("rejects an incorrect password", async () => {
    const hashed = await hashPassword("right");
    const ok = await verifyPassword("wrong", hashed);
    expect(ok).toBe(false);
  });

  it("rejects when the stored hash is empty", async () => {
    const ok = await verifyPassword("anything", "");
    expect(ok).toBe(false);
  });

  it("rejects when the stored hash is garbage", async () => {
    const ok = await verifyPassword("anything", "not-a-bcrypt-hash");
    expect(ok).toBe(false);
  });
});
