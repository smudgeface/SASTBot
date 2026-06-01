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
  artifact_count: number;
  artifact_bytes_total: number;
  // Non-reversible fingerprint of the MASTER_KEY this dump's data was encrypted
  // under (see security/crypto.ts:masterKeyFingerprint). Lets restore detect a
  // key mismatch before it bricks the canary. Empty string = unknown (legacy
  // dumps, or a caller that didn't supply it) → restore skips the key check.
  master_key_fingerprint: string;
}

export interface BackupMetadataInput {
  schemaVersion: string;
  expectedSchemaVersion: string;
  exportedAt?: Date;
  appVersion?: string;
  dumpFormatVersion?: number;
  artifactCount?: number;
  artifactBytesTotal?: number;
  // Callers with access to the key (the HTTP backup route + the CLI) pass the
  // computed fingerprint here. Kept out of this pure builder so it stays
  // crypto/config-free and unit-testable without a MASTER_KEY.
  masterKeyFingerprint?: string;
}

export function buildBackupMetadata(input: BackupMetadataInput): BackupMetadata {
  return {
    app_version: input.appVersion ?? APP_VERSION,
    schema_version: input.schemaVersion,
    expected_schema_version: input.expectedSchemaVersion,
    exported_at: (input.exportedAt ?? new Date()).toISOString(),
    sastbot_dump_format_version: input.dumpFormatVersion ?? SASTBOT_DUMP_FORMAT_VERSION,
    artifact_count: input.artifactCount ?? 0,
    artifact_bytes_total: input.artifactBytesTotal ?? 0,
    master_key_fingerprint: input.masterKeyFingerprint ?? "",
  };
}
