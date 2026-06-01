/**
 * CLI: emit metadata.json for the pre-deploy backup tarball.
 *
 * Invoked from `docker/backend-entrypoint.sh` after pg_dump but before tar.
 * Writes the same JSON shape as the HTTP backup endpoint so the restore
 * endpoint validates both paths identically.
 *
 * Usage:
 *   node dist/cli/write-backup-metadata.js <output-path>
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";

import { buildBackupMetadata } from "../services/backupMetadata.js";
import { getAppliedSchemaVersion, getExpectedSchemaVersion } from "../routes/version.js";
import { masterKeyFingerprint } from "../security/crypto.js";
import { prisma } from "../db.js";

async function main(): Promise<void> {
  const outputPath = process.argv[2];
  if (!outputPath) {
    // eslint-disable-next-line no-console
    console.error("Usage: write-backup-metadata <output-path>");
    process.exit(2);
  }

  const [schemaVersion, expectedSchemaVersion] = await Promise.all([
    getAppliedSchemaVersion(),
    getExpectedSchemaVersion(),
  ]);

  const metadata = buildBackupMetadata({
    schemaVersion,
    expectedSchemaVersion,
    masterKeyFingerprint: masterKeyFingerprint(),
  });

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(metadata, null, 2), "utf8");

  // eslint-disable-next-line no-console
  console.log(`[write-backup-metadata] wrote ${outputPath} schema=${schemaVersion} expected=${expectedSchemaVersion}`);
}

main()
  .then(async () => {
    await prisma.$disconnect();
    process.exit(0);
  })
  .catch(async (err) => {
    // eslint-disable-next-line no-console
    console.error("[write-backup-metadata] failed:", err);
    await prisma.$disconnect().catch(() => undefined);
    process.exit(1);
  });
