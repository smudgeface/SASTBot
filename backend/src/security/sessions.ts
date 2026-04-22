import { createHash, randomBytes } from "node:crypto";

import type { Session, User } from "@prisma/client";

import { prisma } from "../db.js";

export const SESSION_TTL_HOURS = 24 * 14;
export const SESSION_COOKIE_NAME = "sastbot_session";

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function tokenExpiry(): Date {
  return new Date(Date.now() + SESSION_TTL_HOURS * 60 * 60 * 1000);
}

export interface IssuedSession {
  tokenStr: string;
  session: Session;
}

/**
 * Create a session for `userId`. The returned `tokenStr` is the opaque value
 * that belongs in the cookie; the DB only stores its SHA-256 hash.
 */
export async function createSession(
  userId: string,
  userAgent?: string,
  ipAddress?: string,
): Promise<IssuedSession> {
  const tokenStr = randomBytes(32).toString("base64url");
  const session = await prisma.session.create({
    data: {
      userId,
      tokenHash: sha256(tokenStr),
      expiresAt: tokenExpiry(),
      userAgent: userAgent ?? null,
      ipAddress: ipAddress ?? null,
    },
  });
  return { tokenStr, session };
}

/**
 * Resolve the current user from an opaque cookie token. Returns null on
 * unknown / expired / inactive session or inactive user.
 */
export async function getUserFromToken(tokenStr: string | undefined | null): Promise<User | null> {
  if (!tokenStr) return null;
  const session = await prisma.session.findUnique({
    where: { tokenHash: sha256(tokenStr) },
    include: { user: true },
  });
  if (!session) return null;
  if (session.expiresAt.getTime() <= Date.now()) {
    // Best-effort cleanup; don't block the caller on failure.
    prisma.session.delete({ where: { id: session.id } }).catch(() => undefined);
    return null;
  }
  if (!session.user.isActive) return null;
  return session.user;
}

export async function revokeSession(tokenStr: string | undefined | null): Promise<void> {
  if (!tokenStr) return;
  await prisma.session
    .deleteMany({ where: { tokenHash: sha256(tokenStr) } })
    .catch(() => undefined);
}
