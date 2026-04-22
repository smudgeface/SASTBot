import { randomBytes } from "node:crypto";

import { loadConfig } from "../config.js";
import { prisma } from "../db.js";
import { hashPassword } from "../security/passwords.js";

/**
 * Idempotent first-boot bootstrap. Creates a "default" org if there are no
 * orgs, and a bootstrap admin user if there are no admins. The generated
 * password is printed to stdout so the operator can pick it up from
 * `docker compose logs backend | grep BOOTSTRAP`.
 */
export async function bootstrapIfEmpty(): Promise<void> {
  const orgCount = await prisma.org.count();
  let orgId: string;
  if (orgCount === 0) {
    const org = await prisma.org.create({ data: { name: "default" } });
    orgId = org.id;
    // eslint-disable-next-line no-console
    console.log("[BOOTSTRAP] created default org");
  } else {
    const org = await prisma.org.findFirst({ orderBy: { createdAt: "asc" } });
    orgId = org!.id;
  }

  const adminCount = await prisma.user.count({ where: { role: "admin" } });
  if (adminCount > 0) return;

  const config = loadConfig();
  const email = config.bootstrapAdminEmail;
  const password = randomBytes(18).toString("base64url");
  const passwordHash = await hashPassword(password);

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
  console.log(`[BOOTSTRAP] admin email: ${email} password: ${password}`);
}
