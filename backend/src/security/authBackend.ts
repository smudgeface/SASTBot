import type { User } from "@prisma/client";

import { prisma } from "../db.js";

import { verifyPassword } from "./passwords.js";

/**
 * Pluggable authentication backend. M1 ships the local (DB + bcrypt) backend;
 * an OIDC backend can be added later without touching routes.
 */
export interface AuthBackend {
  authenticate(email: string, password: string): Promise<User | null>;
}

export class LocalAuthBackend implements AuthBackend {
  async authenticate(email: string, password: string): Promise<User | null> {
    const user = await prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    if (!user || !user.isActive) return null;
    const ok = await verifyPassword(password, user.passwordHash);
    if (!ok) return null;
    // Best-effort timestamp update — not critical to login correctness.
    prisma.user
      .update({ where: { id: user.id }, data: { lastLoginAt: new Date() } })
      .catch(() => undefined);
    return user;
  }
}

let cached: AuthBackend | null = null;

export function getAuthBackend(): AuthBackend {
  if (!cached) {
    cached = new LocalAuthBackend();
  }
  return cached;
}
