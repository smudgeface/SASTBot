/**
 * Shared metadata builder for DB backup tarballs.
 *
 * Used by:
 *   - `routes/adminBackup.ts` — the HTTP endpoint admins click in the UI.
 *   - `cli/write-backup-metadata.ts` — invoked by `docker/backend-entrypoint.sh`
 *     during pre-deploy backups.
 *
 * Keeping a single shape here means the restore endpoint's Zod schema in
 * `routes/adminRestore.ts` validates dumps from both paths identically.
 */

import { APP_VERSION, SASTBOT_DUMP_FORMAT_VERSION } from "../routes/version.js";

export interface BackupMetadata {
  app_version: string;
  schema_version: string;
  expected_schema_version: string;
  exported_at: string;
  sastbot_dump_format_version: number;
}

export interface BackupMetadataInput {
  schemaVersion: string;
  expectedSchemaVersion: string;
  exportedAt?: Date;
  appVersion?: string;
  dumpFormatVersion?: number;
}

export function buildBackupMetadata(input: BackupMetadataInput): BackupMetadata {
  return {
    app_version: input.appVersion ?? APP_VERSION,
    schema_version: input.schemaVersion,
    expected_schema_version: input.expectedSchemaVersion,
    exported_at: (input.exportedAt ?? new Date()).toISOString(),
    sastbot_dump_format_version: input.dumpFormatVersion ?? SASTBOT_DUMP_FORMAT_VERSION,
  };
}
