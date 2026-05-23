/**
 * Tiered restore service — `mode=runtime` overlay.
 *
 * Background: the legacy restore (mode=full) runs `pg_restore --clean --if-exists`
 * which drops and recreates every table. That's the right call for "I want the
 * whole DB exactly as it was at backup time", but it also wipes any admin-side
 * edits (rotated credentials, updated Jira config, new repos added since the
 * backup) — surprising for an operator who just wants to undo bad scan data.
 *
 * mode=runtime preserves the "Auth + Admin config" bucket and rebuilds only
 * the scan-output bucket from the dump. See docs/user/backup-restore.md for
 * the operator-facing description and CLAUDE.md / docs/M8_PROD_DB_OPS_PLAN.md
 * for the architecture.
 *
 * Strategy (the "schema-rename dance"):
 *   1. Terminate other backend connections so they don't block the schema rename.
 *   2. Rename `public` → `public_live`. Create a new empty `public`.
 *   3. pg_restore --clean --if-exists into the now-empty `public`.
 *   4. Rename `public` → `restore_temp`. Rename `public_live` → `public`.
 *      Now: `public` is the live state (untouched), `restore_temp` holds the dump.
 *   5. Pre-flight: LEFT JOIN check that every cross-bucket FK in restore_temp
 *      (e.g. scan_runs.repo_id) still resolves against live public.repos/orgs.
 *      Any violations → abort, drop restore_temp, return 422.
 *   6. Overlay transaction: SET session_replication_role = replica (bypass FK
 *      triggers — pre-flight already validated). TRUNCATE the RESTORE-bucket
 *      tables in `public`. INSERT into `public.<t>` SELECT * FROM
 *      restore_temp.<t>. TRUNCATE + INSERT `_prisma_migrations` too.
 *   7. DROP SCHEMA restore_temp CASCADE.
 *
 * Why not sed-replace `public.` → `restore_temp.` on the dump SQL? A
 * user-supplied string containing the literal substring `public.<word>` (a
 * CVE summary, a Jira issue title, a scope note) would be silently corrupted.
 *
 * Why require dump.schema_version == running expected_schema_version? After
 * the rename dance, `public` is at the new schema and `restore_temp` is at
 * the old. Overlaying old-schema rows into new-schema tables fails on column
 * mismatch. mode=full handles this via prisma migrate deploy because there
 * pg_restore brings the whole old schema into public, then Prisma migrates
 * it forward. mode=runtime intentionally keeps public untouched, so the
 * dump must already be at the running schema. Operators wanting a
 * migrate-forward restore must use mode=full.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { spawn } from "node:child_process";

import { prisma } from "../db.js";
import { clearDirContents } from "./artifactStore.js";

/**
 * Tables whose contents survive a mode=runtime restore. The operator's
 * "anything I manage under Admin or Settings" mental model.
 */
export const PRESERVE_BUCKET = [
  "orgs",
  "users",
  "sessions",
  "credentials",
  "repos",
  "app_settings",
  "encryption_canary",
] as const;

/**
 * Tables rebuilt from the dump in both modes, in parent-first INSERT order.
 * The TRUNCATE order is the reverse — children-first to keep cascade
 * triggers from doing surprising work even though we disable them.
 */
export const RESTORE_BUCKET_INSERT_ORDER = [
  "scan_scopes",         // FKs → repos (PRESERVE), orgs (PRESERVE)
  "jira_tickets",        // FKs → orgs (PRESERVE)
  "scan_runs",           // FKs → scan_scopes, repos, orgs
  "sbom_components",     // FKs → scan_runs
  "scope_components",    // FKs → scan_scopes, orgs
  "sast_issues",         // FKs → scan_scopes, jira_tickets, orgs
  "sca_issues",          // FKs → scan_scopes, jira_tickets, orgs
  "scan_findings",       // FKs → scan_runs, sbom_components, sca_issues
  "sast_findings",       // FKs → scan_runs, scan_scopes, sast_issues, orgs
  "scan_run_components", // FKs → scan_runs, scope_components
  "cve_knowledge",       // no FKs
] as const;

export const RESTORE_BUCKET_TRUNCATE_ORDER = [...RESTORE_BUCKET_INSERT_ORDER].reverse();

/**
 * Cross-bucket FK constraints — RESTORE-bucket tables referencing
 * PRESERVE-bucket tables. These are what the pre-flight LEFT JOIN check
 * exercises before we touch public.
 *
 * Each entry: { childTable, childColumn, parentTable, parentColumn, nullable }.
 * Nullable FKs only need to be checked when the value is non-null.
 */
export interface CrossBucketFk {
  childTable: string;
  childColumn: string;
  parentTable: string;
  parentColumn: string;
  nullable: boolean;
}

export const CROSS_BUCKET_FKS: CrossBucketFk[] = [
  { childTable: "scan_scopes",         childColumn: "repo_id", parentTable: "repos", parentColumn: "id", nullable: false },
  { childTable: "scan_scopes",         childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
  { childTable: "scan_runs",           childColumn: "repo_id", parentTable: "repos", parentColumn: "id", nullable: false },
  { childTable: "scan_runs",           childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
  { childTable: "sbom_components",     childColumn: "scan_run_id", parentTable: "scan_runs", parentColumn: "id", nullable: false }, // both RESTORE — listed for completeness only
  { childTable: "sast_findings",       childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
  { childTable: "sast_issues",         childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
  { childTable: "sca_issues",          childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
  { childTable: "scope_components",    childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
  { childTable: "jira_tickets",        childColumn: "org_id",  parentTable: "orgs",  parentColumn: "id", nullable: true  },
];

/** Pre-flight result: one entry per (child table, parent table) pair with violations. */
export interface FkViolation {
  childTable: string;
  childColumn: string;
  parentTable: string;
  violationCount: bigint;
  sampleMissingIds: string[];
}

/**
 * Runs pg_restore against the live DB connection. The caller is expected to
 * have already done the rename dance so `public` is empty.
 */
async function runPgRestoreIntoPublic(
  dumpPath: string,
  pgEnv: Record<string, string>,
): Promise<{ exitCode: number | null; stderr: string }> {
  const dbName = pgEnv["PGDATABASE"] ?? "";

  return new Promise((resolve) => {
    let proc: ReturnType<typeof spawn>;
    try {
      proc = spawn(
        "pg_restore",
        [
          "--clean",
          "--if-exists",
          "--no-owner",
          "--no-privileges",
          ...(dbName ? ["-d", dbName] : []),
          dumpPath,
        ],
        {
          env: { ...process.env, ...pgEnv },
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
    } catch (err) {
      resolve({ exitCode: -1, stderr: err instanceof Error ? err.message : String(err) });
      return;
    }
    const stderrChunks: Buffer[] = [];
    proc.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));
    proc.on("close", (code) => {
      resolve({
        exitCode: code,
        stderr: Buffer.concat(stderrChunks).toString("utf8").trim(),
      });
    });
    proc.on("error", (err) => {
      resolve({ exitCode: -1, stderr: err.message });
    });
  });
}

/**
 * Terminate every other connection to the current database. ALTER SCHEMA
 * RENAME holds an AccessExclusiveLock on the schema; any other connection
 * holding even an AccessShareLock on a table inside it will block us.
 * Restoring is admin-only and explicitly ends with process.exit(0), so a
 * brief disruption is acceptable.
 */
async function terminateOtherBackends(): Promise<void> {
  await prisma.$executeRawUnsafe(`
    SELECT pg_terminate_backend(pid)
    FROM pg_stat_activity
    WHERE datname = current_database()
      AND pid <> pg_backend_pid()
  `);
}

/**
 * Step 1+2 of the rename dance: move live state aside, create empty public.
 * Throws if rename fails (caller should clean up by inverting).
 */
async function setUpEmptyPublic(): Promise<void> {
  // Drop a leftover restore_temp from a previous aborted run, if any.
  await prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS restore_temp CASCADE`);
  // public_live shouldn't exist either, but defend against a half-run.
  await prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS public_live CASCADE`);

  await prisma.$executeRawUnsafe(`ALTER SCHEMA public RENAME TO public_live`);
  await prisma.$executeRawUnsafe(`CREATE SCHEMA public`);
  // Restore the default permissions Prisma expects on a fresh public schema.
  await prisma.$executeRawUnsafe(`GRANT ALL ON SCHEMA public TO public`);
}

/**
 * Step 4 of the rename dance: rotate public → restore_temp, public_live → public.
 */
async function rotateSchemasIntoFinalPositions(): Promise<void> {
  await prisma.$executeRawUnsafe(`ALTER SCHEMA public RENAME TO restore_temp`);
  await prisma.$executeRawUnsafe(`ALTER SCHEMA public_live RENAME TO public`);
}

/**
 * Recovery path: pg_restore failed after we already created the empty public.
 * Drop the partial public, restore public_live → public.
 */
async function recoverFromFailedRestore(): Promise<void> {
  await prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS public CASCADE`).catch(() => undefined);
  await prisma.$executeRawUnsafe(`ALTER SCHEMA public_live RENAME TO public`).catch(() => undefined);
}

/**
 * Pre-flight: do all the cross-bucket FK references in restore_temp resolve
 * against live public? Returns the violations, empty array if clean.
 */
export async function checkCrossBucketFks(): Promise<FkViolation[]> {
  const violations: FkViolation[] = [];

  for (const fk of CROSS_BUCKET_FKS) {
    // Only check FKs where the parent table is in PRESERVE bucket (public is
    // authoritative). FKs that target tables also in RESTORE bucket are
    // self-consistent within the dump.
    if (!PRESERVE_BUCKET.includes(fk.parentTable as (typeof PRESERVE_BUCKET)[number])) continue;

    const nullClause = fk.nullable ? `AND child.${fk.childColumn} IS NOT NULL` : "";
    const rows = await prisma.$queryRawUnsafe<{ count: bigint; sample: string[] }[]>(
      `SELECT COUNT(*)::bigint AS count,
              COALESCE(ARRAY_AGG(DISTINCT child.${fk.childColumn}::text) FILTER (WHERE parent.${fk.parentColumn} IS NULL), '{}') AS sample
       FROM restore_temp.${fk.childTable} AS child
       LEFT JOIN public.${fk.parentTable} AS parent ON child.${fk.childColumn} = parent.${fk.parentColumn}
       WHERE parent.${fk.parentColumn} IS NULL
         ${nullClause}`,
    );
    const result = rows[0];
    if (result && result.count > 0n) {
      violations.push({
        childTable: fk.childTable,
        childColumn: fk.childColumn,
        parentTable: fk.parentTable,
        violationCount: result.count,
        sampleMissingIds: (result.sample ?? []).slice(0, 5),
      });
    }
  }
  return violations;
}

/**
 * Step 6: TRUNCATE the RESTORE-bucket tables in public and overlay them
 * with restore_temp's contents. Wrapped in a transaction. FK triggers are
 * bypassed via session_replication_role = replica because we already
 * pre-flighted cross-bucket FKs.
 */
async function applyRuntimeOverlay(): Promise<void> {
  await prisma.$transaction(async (tx) => {
    await tx.$executeRawUnsafe(`SET LOCAL session_replication_role = replica`);

    const truncateList = RESTORE_BUCKET_TRUNCATE_ORDER.map((t) => `public.${t}`).join(", ");
    await tx.$executeRawUnsafe(`TRUNCATE ${truncateList}`);

    for (const tbl of RESTORE_BUCKET_INSERT_ORDER) {
      await tx.$executeRawUnsafe(`INSERT INTO public.${tbl} SELECT * FROM restore_temp.${tbl}`);
    }

    // _prisma_migrations is always restored from the dump — it records what
    // the dump's DB had applied at backup time. With the schema-version
    // equality check that gates this code path, dump._prisma_migrations
    // should already match public._prisma_migrations, but we overwrite to
    // be explicit about the contract.
    await tx.$executeRawUnsafe(`TRUNCATE public._prisma_migrations`);
    await tx.$executeRawUnsafe(
      `INSERT INTO public._prisma_migrations SELECT * FROM restore_temp._prisma_migrations`,
    );
  });
}

/**
 * Drop restore_temp after the overlay completes (or after a failure where
 * we want to clean up).
 */
async function dropRestoreTemp(): Promise<void> {
  await prisma.$executeRawUnsafe(`DROP SCHEMA IF EXISTS restore_temp CASCADE`);
}

/**
 * A6.4: Pre-flight orphan check for mode=runtime.
 *
 * Enumerates artifact files under <artifactSourceDir>/sbom/ and
 * <artifactSourceDir>/sarif/, parses the UUID from each filename, and
 * confirms that every UUID corresponds to a row in restore_temp.scan_runs.
 * Any UUID that doesn't match is an "orphan" — evidence that the dump is
 * internally inconsistent (artifact file with no matching scan run row).
 *
 * Only called after the rename dance has placed the dump in restore_temp.
 * Returns { orphans: [] } when artifactSourceDir is null (old-format tarball).
 */
export async function checkArtifactOrphans(
  artifactSourceDir: string | null,
): Promise<{ orphans: string[] }> {
  if (!artifactSourceDir) return { orphans: [] };

  const sbomDir = path.join(artifactSourceDir, "sbom");
  const sarifDir = path.join(artifactSourceDir, "sarif");
  const sbomFiles = await fs.readdir(sbomDir).catch(() => [] as string[]);
  const sarifFiles = await fs.readdir(sarifDir).catch(() => [] as string[]);
  const uuids = new Set<string>();
  for (const f of sbomFiles) {
    const m = f.match(/^([0-9a-f-]{36})\.json$/);
    if (m) uuids.add(m[1]);
  }
  for (const f of sarifFiles) {
    const m = f.match(/^([0-9a-f-]{36})\.sarif\.json$/);
    if (m) uuids.add(m[1]);
  }
  if (uuids.size === 0) return { orphans: [] };

  const ids = [...uuids];
  const rows = await prisma.$queryRawUnsafe<{ id: string }[]>(
    `SELECT id::text AS id FROM restore_temp.scan_runs WHERE id = ANY($1::uuid[])`,
    ids,
  );
  const known = new Set(rows.map((r) => r.id));
  const orphans = ids.filter((id) => !known.has(id));
  return { orphans };
}

/**
 * High-level entry point. Caller (the route handler) has already validated
 * the upload, version-checked it, and produced a path to the .pgcustom dump.
 */
export interface RuntimeRestoreInput {
  dumpPath: string;
  pgEnv: Record<string, string>;
  artifactSourceDir: string | null;  // extractDir/artifacts/, or null for old-format tarballs
  artifactTargetDir: string;          // config.artifactDir
}

export type RuntimeRestoreResult =
  | { ok: true }
  | { ok: false; status: 422 | 500; detail: string; violations?: FkViolation[] };

export async function runRuntimeRestore(input: RuntimeRestoreInput): Promise<RuntimeRestoreResult> {
  await terminateOtherBackends();

  // Phase 1: rename dance + pg_restore into a transient empty public.
  await setUpEmptyPublic();

  const restoreResult = await runPgRestoreIntoPublic(input.dumpPath, input.pgEnv);
  if (restoreResult.exitCode !== 0) {
    await recoverFromFailedRestore();
    return {
      ok: false,
      status: 500,
      detail:
        `pg_restore exited with code ${restoreResult.exitCode} into the staging schema. ` +
        `The live database has been restored to its pre-restore state. ` +
        (restoreResult.stderr ? `pg_restore stderr: ${restoreResult.stderr}` : "No stderr output captured."),
    };
  }

  // Rotate: public → restore_temp, public_live → public.
  await rotateSchemasIntoFinalPositions();

  // Phase 2: pre-flight FK check.
  let violations: FkViolation[];
  try {
    violations = await checkCrossBucketFks();
  } catch (err) {
    await dropRestoreTemp();
    return {
      ok: false,
      status: 500,
      detail: `Pre-flight FK check failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (violations.length > 0) {
    await dropRestoreTemp();
    const detail = formatFkViolationMessage(violations);
    return { ok: false, status: 422, detail, violations };
  }

  // A6.4: artifact orphan pre-flight (after rename dance, before overlay).
  let orphanResult: { orphans: string[] };
  try {
    orphanResult = await checkArtifactOrphans(input.artifactSourceDir);
  } catch (err) {
    await dropRestoreTemp();
    return {
      ok: false,
      status: 500,
      detail: `Artifact orphan pre-flight failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (orphanResult.orphans.length > 0) {
    await dropRestoreTemp();
    return {
      ok: false,
      status: 422,
      detail:
        `Tarball contains ${orphanResult.orphans.length} artifact file(s) without matching scan_runs rows in the dump ` +
        `(e.g. ${orphanResult.orphans.slice(0, 3).join(", ")}). The dump appears corrupted — re-take the backup.`,
    };
  }

  // Phase 3: overlay.
  try {
    await applyRuntimeOverlay();
  } catch (err) {
    // Public is in a partial state. We can't recover it from restore_temp
    // generically (some rows may have been TRUNCATE'd). Leave restore_temp
    // in place so the operator (or a re-run) can investigate.
    return {
      ok: false,
      status: 500,
      detail:
        `Overlay transaction failed mid-flight: ${err instanceof Error ? err.message : String(err)}. ` +
        `The restore_temp schema has been kept for inspection — DROP it manually after recovery.`,
    };
  }

  await dropRestoreTemp();

  // A6.3: artifact dir overlay — after DB transaction commits, wipe and copy.
  // `clearDirContents` keeps the directory itself in place: `fs.rm` of the dir
  // fails EBUSY on a mount point in containerized deployments where
  // ARTIFACT_DIR is a Docker volume. Failure here leaves the DB authoritative;
  // operator can re-run idempotently.
  try {
    await clearDirContents(input.artifactTargetDir);
    if (input.artifactSourceDir) {
      const hasSource = await fs.access(input.artifactSourceDir).then(() => true).catch(() => false);
      if (hasSource) {
        const entries = await fs.readdir(input.artifactSourceDir);
        for (const entry of entries) {
          await fs.cp(
            path.join(input.artifactSourceDir, entry),
            path.join(input.artifactTargetDir, entry),
            { recursive: true },
          );
        }
      }
    }
  } catch (err) {
    return {
      ok: false,
      status: 500,
      detail:
        `DB overlay succeeded but artifact-dir overlay failed: ${err instanceof Error ? err.message : String(err)}. ` +
        `Re-run the same tarball in mode=runtime to retry (idempotent — DB will TRUNCATE+overlay to the same end state).`,
    };
  }

  return { ok: true };
}

/**
 * Format the FK pre-flight violations into a single operator-friendly
 * error string. Each line names the child table, the missing IDs (sample),
 * and points the operator at mode=full.
 */
export function formatFkViolationMessage(violations: FkViolation[]): string {
  const lines: string[] = [];
  lines.push(
    "Cannot restore in mode=runtime: the backup references admin-managed rows " +
    "(repos or orgs) that no longer exist in the running database. This usually " +
    "means a repo or org was deleted between when the backup was taken and now.",
  );
  lines.push("");
  for (const v of violations) {
    const sample =
      v.sampleMissingIds.length > 0
        ? ` (e.g. ${v.sampleMissingIds.slice(0, 3).join(", ")})`
        : "";
    lines.push(
      `  - ${v.violationCount} ${v.childTable} row(s) reference ${v.parentTable} ids that no longer exist${sample}`,
    );
  }
  lines.push("");
  lines.push(
    "Fix: either re-add the missing rows in the admin UI first, or use mode=full " +
    "to restore the entire backup (which brings the missing rows back along with the scan data).",
  );
  return lines.join("\n");
}
