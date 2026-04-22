// Using bcryptjs (pure JS) rather than `bcrypt` to avoid native-binding
// shenanigans in multi-arch Docker builds. API-compatible.
import bcryptjs from "bcryptjs";

const { compare, hash } = bcryptjs;

const ROUNDS = 12;

export async function hashPassword(password: string): Promise<string> {
  return hash(password, ROUNDS);
}

export async function verifyPassword(password: string, hashed: string): Promise<boolean> {
  if (!hashed) return false;
  try {
    return await compare(password, hashed);
  } catch {
    return false;
  }
}
