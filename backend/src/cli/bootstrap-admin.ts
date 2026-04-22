import { randomBytes } from "node:crypto";
import { parseArgs } from "node:util";

import { prisma } from "../db.js";
import { hashPassword } from "../security/passwords.js";

/**
 * CLI: `pnpm run bootstrap-admin --email you@example.com`
 *
 * Creates (or resurrects) an admin user with a randomly generated password.
 * Prints the password on stdout — rotate immediately after first login.
 */

async function main(): Promise<void> {
  const { values } = parseArgs({
    options: {
      email: { type: "string", short: "e" },
      "org-name": { type: "string" },
    },
    strict: true,
    allowPositionals: false,
  });

  const email = values.email;
  if (!email) {
    // eslint-disable-next-line no-console
    console.error("Usage: bootstrap-admin --email you@example.com [--org-name default]");
    process.exit(2);
  }

  const orgName = values["org-name"] ?? "default";

  const org =
    (await prisma.org.findUnique({ where: { name: orgName } })) ??
    (await prisma.org.create({ data: { name: orgName } }));

  const password = randomBytes(18).toString("base64url");
  const passwordHash = await hashPassword(password);

  const normalized = email.toLowerCase();
  const existing = await prisma.user.findUnique({ where: { email: normalized } });
  if (existing) {
    await prisma.user.update({
      where: { id: existing.id },
      data: { passwordHash, role: "admin", isActive: true, orgId: org.id },
    });
    // eslint-disable-next-line no-console
    console.log(`[BOOTSTRAP] reset admin email: ${normalized} password: ${password}`);
  } else {
    await prisma.user.create({
      data: {
        email: normalized,
        passwordHash,
        role: "admin",
        isActive: true,
        orgId: org.id,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[BOOTSTRAP] created admin email: ${normalized} password: ${password}`);
  }
}

main()
  .then(async () => {
    await prisma.$disconnect();
    process.exit(0);
  })
  .catch(async (err) => {
    // eslint-disable-next-line no-console
    console.error(err);
    await prisma.$disconnect().catch(() => undefined);
    process.exit(1);
  });
