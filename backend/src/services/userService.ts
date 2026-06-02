import { Prisma } from "@prisma/client";
import type { PrismaClient, User } from "@prisma/client";

import { prisma } from "../db.js";
import { hashPassword, verifyPassword } from "../security/passwords.js";
import { revokeUserSessions } from "../security/sessions.js";

import type { CreateUserBody, UpdateUserBody } from "../schemas.js";

type Tx = PrismaClient | Prisma.TransactionClient;

/**
 * Advisory-lock key for admin-count-reducing operations (demote / disable /
 * delete). Serializes the "is this the last active admin?" check with the write
 * so two concurrent demotions can't both pass and leave zero admins. Distinct
 * from the first-run-setup lock (7794210).
 */
const ADMIN_GUARD_LOCK_KEY = 7794211;

export class UserNotFoundError extends Error {
  constructor() { super("User not found."); this.name = "UserNotFoundError"; }
}
export class DuplicateEmailError extends Error {
  constructor() { super("A user with that email already exists."); this.name = "DuplicateEmailError"; }
}
export class LastAdminError extends Error {
  constructor() {
    super("This would leave no active administrator. Promote or enable another admin first.");
    this.name = "LastAdminError";
  }
}
export class SelfActionError extends Error {
  constructor(message: string) { super(message); this.name = "SelfActionError"; }
}
export class InvalidCurrentPasswordError extends Error {
  constructor() { super("Current password is incorrect."); this.name = "InvalidCurrentPasswordError"; }
}
export class SamePasswordError extends Error {
  constructor() { super("New password must differ from the current password."); this.name = "SamePasswordError"; }
}

export async function countActiveAdmins(client: Tx = prisma): Promise<number> {
  return client.user.count({ where: { role: "admin", isActive: true } });
}

export async function listUsers(orgId: string | null, client: Tx = prisma): Promise<User[]> {
  return client.user.findMany({
    where: { orgId: orgId ?? null },
    orderBy: [{ createdAt: "asc" }],
  });
}

export async function getUser(
  userId: string,
  orgId: string | null,
  client: Tx = prisma,
): Promise<User> {
  const u = await client.user.findFirst({ where: { id: userId, orgId: orgId ?? null } });
  if (!u) throw new UserNotFoundError();
  return u;
}

export interface CreateUserArgs {
  orgId: string | null;
  input: CreateUserBody;
}

export async function createUser({ orgId, input }: CreateUserArgs): Promise<User> {
  const email = input.email.toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) throw new DuplicateEmailError();

  const passwordHash = await hashPassword(input.password);
  try {
    return await prisma.user.create({
      data: {
        orgId: orgId ?? null,
        email,
        name: input.name ?? null,
        passwordHash,
        role: input.role,
        isActive: true,
        mustChangePassword: true, // admin-set password is one-time
      },
    });
  } catch (err) {
    // Unique-constraint backstop against a race between the check and the insert.
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      throw new DuplicateEmailError();
    }
    throw err;
  }
}

/**
 * Run `fn` inside a transaction holding the admin-guard advisory lock — for any
 * operation that could reduce the active-admin count.
 */
async function withAdminGuardLock<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${ADMIN_GUARD_LOCK_KEY})`);
    return fn(tx);
  });
}

export async function updateUser(
  actingUserId: string,
  targetId: string,
  orgId: string | null,
  body: UpdateUserBody,
): Promise<User> {
  const data: Prisma.UserUpdateInput = {};
  if (body.name !== undefined) data.name = body.name; // may be null to clear
  if (body.role !== undefined) data.role = body.role;
  if (body.is_active !== undefined) data.isActive = body.is_active;

  // A pure name change can't affect the admin count or cause self-lockout — no
  // lock, no guard. This is the path a user takes to edit their own name.
  const touchesPrivilege = body.role !== undefined || body.is_active !== undefined;
  if (!touchesPrivilege) {
    await getUser(targetId, orgId, prisma);
    return prisma.user.update({ where: { id: targetId }, data });
  }

  return withAdminGuardLock(async (tx) => {
    const target = await getUser(targetId, orgId, tx);
    const newRole = body.role ?? target.role;
    const newActive = body.is_active ?? target.isActive;
    const roleChanged = newRole !== target.role;
    const activeChanged = newActive !== target.isActive;

    // Self-protection: only an ACTUAL change to your own role/active is blocked —
    // submitting the current values unchanged (e.g. while editing your name) is fine.
    if (targetId === actingUserId && (roleChanged || activeChanged)) {
      throw new SelfActionError("You can't change your own role or active status.");
    }

    // Last-admin guard: refuse if this would remove the final active admin.
    const wasActiveAdmin = target.role === "admin" && target.isActive;
    const willBeActiveAdmin = newRole === "admin" && newActive;
    if (wasActiveAdmin && !willBeActiveAdmin) {
      const others = await tx.user.count({
        where: { role: "admin", isActive: true, id: { not: targetId } },
      });
      if (others === 0) throw new LastAdminError();
    }

    const updated = await tx.user.update({ where: { id: targetId }, data });
    if (activeChanged && newActive === false) await revokeUserSessions(targetId);
    return updated;
  });
}

export async function resetUserPassword(
  targetId: string,
  orgId: string | null,
  password: string,
): Promise<User> {
  await getUser(targetId, orgId, prisma);
  const passwordHash = await hashPassword(password);
  const updated = await prisma.user.update({
    where: { id: targetId },
    data: { passwordHash, mustChangePassword: true },
  });
  // Force re-login everywhere with the new one-time password.
  await revokeUserSessions(targetId);
  return updated;
}

export async function deleteUser(
  actingUserId: string,
  targetId: string,
  orgId: string | null,
): Promise<void> {
  if (targetId === actingUserId) {
    throw new SelfActionError("You can't delete your own account.");
  }
  await withAdminGuardLock(async (tx) => {
    const target = await getUser(targetId, orgId, tx);
    if (target.role === "admin" && target.isActive) {
      const others = await tx.user.count({
        where: { role: "admin", isActive: true, id: { not: targetId } },
      });
      if (others === 0) throw new LastAdminError();
    }
    await tx.user.delete({ where: { id: targetId } }); // sessions cascade
  });
}

/**
 * Self-service password change. Verifies the current password, rejects a no-op,
 * sets the new hash, clears the must-change flag, and revokes the user's OTHER
 * sessions (keeping the caller's current one alive via `currentTokenStr`).
 */
export async function changeOwnPassword(
  userId: string,
  currentPassword: string,
  newPassword: string,
  currentTokenStr?: string | null,
): Promise<User> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) throw new UserNotFoundError();

  const ok = await verifyPassword(currentPassword, user.passwordHash);
  if (!ok) throw new InvalidCurrentPasswordError();
  if (await verifyPassword(newPassword, user.passwordHash)) throw new SamePasswordError();

  const passwordHash = await hashPassword(newPassword);
  const updated = await prisma.user.update({
    where: { id: userId },
    data: { passwordHash, mustChangePassword: false },
  });
  await revokeUserSessions(userId, currentTokenStr ?? undefined);
  return updated;
}
