import { Prisma } from "@prisma/client";
import type { PrismaClient } from "@prisma/client";

import { loadConfig } from "../config.js";
import { prisma } from "../db.js";
import { hashPassword } from "../security/passwords.js";

type Tx = PrismaClient | Prisma.TransactionClient;

/**
 * Ensure a "default" org exists and return its id. Idempotent. The org holds no
 * secrets, so creating it eagerly at boot is safe and keeps the rest of the app's
 * single-org invariant intact even before the first admin is onboarded.
 */
export async function ensureDefaultOrg(client: Tx = prisma): Promise<string> {
  const existing = await client.org.findFirst({ orderBy: { createdAt: "asc" } });
  if (existing) return existing.id;
  const org = await client.org.create({ data: { name: "default" } });
  return org.id;
}

/** Number of admin users — 0 means the instance still needs first-run setup. */
export async function countAdmins(client: Tx = prisma): Promise<number> {
  return client.user.count({ where: { role: "admin" } });
}

/**
 * First-boot bootstrap. Always ensures the default org exists. It no longer
 * auto-creates an admin with a random password — the first admin is created
 * through the operator-driven first-run setup flow (`POST /auth/setup`) or by
 * restoring an existing backup.
 *
 * The one exception is the DEV-ONLY `BOOTSTRAP_ADMIN_PASSWORD` escape hatch: when
 * set (already a hard config error under NODE_ENV=production), the admin is
 * auto-created with that fixed password so a `docker compose down -v` lets the
 * developer log straight back in without walking the setup screen each time.
 */
export async function bootstrapIfEmpty(): Promise<void> {
  const orgId = await ensureDefaultOrg();

  if ((await countAdmins()) > 0) return;

  const config = loadConfig();
  const fixedPassword = config.bootstrapAdminPassword;
  if (!fixedPassword) {
    // No dev hatch → leave the instance in "needs setup" state for the
    // onboarding flow. Nothing secret is written to logs.
    // eslint-disable-next-line no-console
    console.log("[BOOTSTRAP] no admin user yet — first-run setup required at /setup");
    return;
  }

  const email = config.bootstrapAdminEmail;
  const passwordHash = await hashPassword(fixedPassword);
  await prisma.user.create({
    data: {
      orgId,
      email: email.toLowerCase(),
      passwordHash,
      role: "admin",
      isActive: true,
    },
  });

  // eslint-disable-next-line no-console
  console.log(`[BOOTSTRAP] admin email: ${email} password: ${fixedPassword}`);
  // eslint-disable-next-line no-console
  console.log(
    "[BOOTSTRAP] WARNING: BOOTSTRAP_ADMIN_PASSWORD is set — using a FIXED dev password. " +
      "This is a dev convenience only; unset it in production deployments.",
  );
}
