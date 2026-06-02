import type { User } from "@prisma/client";

import { prisma } from "../db.js";
import { hashPassword } from "../security/passwords.js";

import { countAdmins, ensureDefaultOrg } from "./bootstrap.js";

/**
 * Fixed Postgres advisory-lock key for the first-run setup critical section.
 * Arbitrary 32-bit constant; only needs to be stable and unused elsewhere.
 */
const SETUP_ADVISORY_LOCK_KEY = 7794210;

export class SetupAlreadyCompleteError extends Error {
  constructor() {
    super("Setup has already been completed — an admin account already exists.");
    this.name = "SetupAlreadyCompleteError";
  }
}

export type SetupGateDecision = "allow" | "forbid" | "unauthorized";

/**
 * Pure decision for the `requireAdminOrSetupWindow` gate. `adminCount` is only
 * consulted for unauthenticated callers — the setup window is open exactly while
 * zero admins exist.
 *
 *   admin                       → allow
 *   authenticated non-admin     → forbid (403)
 *   unauthenticated, 0 admins   → allow (setup window)
 *   unauthenticated, ≥1 admin   → unauthorized (401)
 */
export function decideSetupGate(
  userRole: string | null | undefined,
  adminCount: number,
): SetupGateDecision {
  if (userRole === "admin") return "allow";
  if (userRole) return "forbid";
  return adminCount === 0 ? "allow" : "unauthorized";
}

/**
 * Create the first admin account during first-run setup.
 *
 * Wrapped in a transaction guarded by a session-level advisory lock so two
 * concurrent setup requests can't both pass the "zero admins" check and create
 * two admins. The lock serializes the check-then-insert; the second caller sees
 * the first's admin and is rejected with {@link SetupAlreadyCompleteError}.
 *
 * Only valid while the instance has zero admins — the route layer also gates on
 * this, but the re-check inside the lock is the authoritative one.
 */
export async function createFirstAdmin(email: string, password: string): Promise<User> {
  const passwordHash = await hashPassword(password);

  return prisma.$transaction(async (tx) => {
    // Serialize the critical section. xact lock auto-releases on commit/rollback.
    await tx.$executeRawUnsafe(`SELECT pg_advisory_xact_lock(${SETUP_ADVISORY_LOCK_KEY})`);

    if ((await countAdmins(tx)) > 0) {
      throw new SetupAlreadyCompleteError();
    }

    const orgId = await ensureDefaultOrg(tx);
    return tx.user.create({
      data: {
        orgId,
        email: email.toLowerCase(),
        passwordHash,
        role: "admin",
        isActive: true,
      },
    });
  });
}
