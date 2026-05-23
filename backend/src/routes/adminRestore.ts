/**
 * Admin DB restore route.
 *
 * POST /admin/db/restore
 *   Accepts a multipart upload of either:
 *     (a) A SASTBot tarball backup (*.tar.gz) — contains dump.pgcustom + metadata.json.
 *         Format is detected by the gzip magic bytes (0x1f 0x8b) at the start.
 *     (b) A legacy raw pg_dump custom-format file (*.dump) — detected by the
 *         "PGDMP" ASCII magic at the start (Stream F format).
 *
 *   Tarball path workflow:
 *     1. Pre-flight: disk-space check (Content-Length, 10% margin).
 *     2. Stream upload to a temp file.
 *     3. Peek at first 4 bytes to detect format.
 *     4. Extract tarball to /tmp/sastbot-restore-<uuid>/extracted/.
 *     5. Validate the two expected files are present (path-traversal defence).
 *     6. Read + Zod-validate metadata.json.
 *     7. Compare dump schema_version to running expected_schema_version:
 *          equal  → restore as-is
 *          older  → restore, then run `prisma migrate deploy`
 *          newer  → HTTP 422 (refuse)
 *     8. Run pg_restore --clean --if-exists --no-owner --no-privileges.
 *     9. If schema was older: run prisma migrate deploy, capture applied migrations.
 *    10. On full success: cleanup temp files, respond, then process.exit(0).
 *    11. On failure: keep temp files for inspection, return 500 with stderr.
 *
 *   Legacy .dump path:
 *     Same as before (Stream F) — pg_restore unconditionally, with a warning
 *     in the response body that no version metadata was present.
 *
 * Security notes:
 *   - DB credentials passed via PG* env vars only, never as CLI arguments.
 *   - Tarball extraction validates that only the two expected filenames are
 *     present (path-traversal defence) before using any extracted file.
 *   - Temp files written to /tmp inside the backend container.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import { spawn } from "node:child_process";
import * as stream from "node:stream";
import { pipeline } from "node:stream/promises";

import multipart from "@fastify/multipart";
import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { ErrorSchema } from "../schemas.js";
import { clearDirContents } from "../services/artifactStore.js";
import { runRuntimeRestore } from "../services/restoreService.js";
import { pgEnvFromUrl } from "./adminBackup.js";
import { APP_VERSION, getExpectedSchemaVersion, SASTBOT_DUMP_FORMAT_VERSION } from "./version.js";

/**
 * Restore mode — controls how much of the database the dump overlays.
 *
 *   full     — current behaviour. pg_restore --clean --if-exists replaces
 *              every table. Auto-runs prisma migrate deploy on older dumps.
 *   runtime  — rebuilds only the scan-output tables; auth + admin-config
 *              tables (orgs, users, sessions, credentials, repos,
 *              app_settings, encryption_canary) keep their current values.
 *              Requires dump.schema_version == running expected_schema_version.
 *
 * See backend/src/services/restoreService.ts and docs/user/backup-restore.md
 * for the details and the FK edge case.
 */
const RestoreModeSchema = z.enum(["full", "runtime"]).default("full");

const TMP_DIR = "/tmp";

// ---------------------------------------------------------------------------
// Metadata schema (Zod) — validated after extraction
// ---------------------------------------------------------------------------

const MetadataSchema = z.object({
  app_version: z.string(),
  schema_version: z.string(),
  expected_schema_version: z.string(),
  exported_at: z.string(),
  sastbot_dump_format_version: z.number().int(),
  artifact_count: z.number().int().optional(),
  artifact_bytes_total: z.number().int().optional(),
});

type BackupMetadata = z.infer<typeof MetadataSchema>;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Return available bytes in the given directory's filesystem.
 * Uses fs.statfs (Node 18+).
 */
async function availableBytesIn(dir: string): Promise<number> {
  const stats = await fsPromises.statfs(dir);
  // bavail: blocks available to unprivileged users; bsize: block size.
  return stats.bavail * stats.bsize;
}

/**
 * Peek at the first N bytes of a file without reading the whole thing.
 */
async function readFirstBytes(filePath: string, n: number): Promise<Buffer> {
  const fd = await fsPromises.open(filePath, "r");
  try {
    const buf = Buffer.alloc(n);
    const { bytesRead } = await fd.read(buf, 0, n, 0);
    return buf.subarray(0, bytesRead);
  } finally {
    await fd.close();
  }
}

type FileFormat = "tarball" | "pgdump" | "unknown";

/**
 * Detect the format of the uploaded file from its magic bytes:
 *   0x1f 0x8b  → gzip (tarball)
 *   "PGDMP"    → pg_dump custom format (5 ASCII bytes)
 *   otherwise  → unknown
 */
async function detectFormat(filePath: string): Promise<FileFormat> {
  const bytes = await readFirstBytes(filePath, 5);
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return "tarball";
  }
  if (bytes.length >= 5 && bytes.toString("ascii", 0, 5) === "PGDMP") {
    return "pgdump";
  }
  return "unknown";
}

/**
 * Extract a tar.gz file into the given directory using the system `tar` binary.
 * Validates that only the two expected filenames are in the archive (path-traversal
 * defence — even though we control producers, the input is operator-supplied).
 *
 * Returns an error string on failure, or null on success.
 */
async function extractTarball(tarPath: string, extractDir: string): Promise<string | null> {
  await fsPromises.mkdir(extractDir, { recursive: true });

  return new Promise((resolve) => {
    let proc: ReturnType<typeof spawn>;
    try {
      proc = spawn("tar", ["-xzf", tarPath, "-C", extractDir], {
        stdio: ["ignore", "ignore", "pipe"],
      });
    } catch (err) {
      resolve(`Failed to spawn tar: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }

    const stderrChunks: Buffer[] = [];
    proc.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));
    proc.on("close", (code) => {
      if (code !== 0) {
        const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
        resolve(`tar exited with code ${code}. ${stderr}`);
      } else {
        resolve(null);
      }
    });
    proc.on("error", (err) => resolve(`tar error: ${err.message}`));
  });
}

/**
 * Run pg_restore --clean --if-exists --no-owner --no-privileges against the
 * given dump file. Returns { exitCode, stderr }.
 *
 * pg_restore 16 requires an explicit -d/--dbname even when PGDATABASE is set in
 * the environment — unlike earlier versions that would fall back to the env var.
 */
async function runPgRestore(
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
 * Run `prisma migrate deploy` via the local binary.
 * Returns { ok, appliedMigrations, stderr }.
 *
 * The binary is resolved relative to this file: ../../node_modules/.bin/prisma
 */
async function runPrismaMigrateDeploy(
  databaseUrl: string,
): Promise<{ ok: boolean; appliedMigrations: string[]; stderr: string }> {
  // Resolve the prisma CLI relative to backend/node_modules
  const prismaBin = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "../../node_modules/.bin/prisma",
  );

  return new Promise((resolve) => {
    let proc: ReturnType<typeof spawn>;
    try {
      proc = spawn(prismaBin, ["migrate", "deploy"], {
        env: { ...process.env, DATABASE_URL: databaseUrl },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch (err) {
      resolve({
        ok: false,
        appliedMigrations: [],
        stderr: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    proc.stdout?.on("data", (c: Buffer) => stdoutChunks.push(c));
    proc.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));

    proc.on("close", (code) => {
      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();

      // Parse migration names from prisma migrate deploy stdout.
      // Lines look like:  ✔ <migration_name>
      // or (plain ASCII): [✓] <migration_name>
      // We simply scan for lines that reference migration directory names.
      const applied: string[] = [];
      for (const line of stdout.split("\n")) {
        // Prisma prints "Applying migration `20240101_foo`"
        const m = line.match(/`(20\d{13}_\w+)`/);
        if (m) applied.push(m[1]);
      }

      resolve({ ok: code === 0, appliedMigrations: applied, stderr });
    });

    proc.on("error", (err) => {
      resolve({ ok: false, appliedMigrations: [], stderr: err.message });
    });
  });
}

// ---------------------------------------------------------------------------
// Response schema
// ---------------------------------------------------------------------------

const RestoreResponseSchema = z.object({
  ok: z.boolean(),
  restarting: z.boolean(),
  migrations_applied: z.array(z.string()).optional(),
  migration_warning: z.string().optional(),
  app_version_warning: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Route plugin
// ---------------------------------------------------------------------------

const adminRestoreRoutes: FastifyPluginAsync = async (app) => {
  const config = loadConfig();

  // Register multipart at the route scope only — the rest of the API uses
  // small JSON bodies and we must not impose a 2 GiB global limit on them.
  await app.register(multipart, {
    limits: {
      fileSize: config.dbRestoreMaxBytes,
      files: 1,       // one file per request
      fields: 0,      // no extra form fields expected
    },
  });

  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.post(
    "/admin/db/restore",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "backup"],
        summary: "Upload a pg_dump file or SASTBot tarball and restore it into the application database",
        querystring: z.object({
          mode: RestoreModeSchema,
        }),
        response: {
          200: RestoreResponseSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          422: ErrorSchema,
          507: ErrorSchema,
          500: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const mode = req.query.mode;

      const pgEnv = pgEnvFromUrl(config.databaseUrl);
      if (!pgEnv) {
        return reply.code(500).send({ detail: "Could not parse DATABASE_URL to build pg_restore connection parameters" });
      }

      // -----------------------------------------------------------------------
      // 1. Pre-flight: disk space check
      // -----------------------------------------------------------------------
      const contentLength = req.headers["content-length"];
      if (contentLength) {
        const uploadBytes = parseInt(contentLength, 10);
        if (!isNaN(uploadBytes) && uploadBytes > 0) {
          const available = await availableBytesIn(TMP_DIR).catch(() => Infinity);
          const required = Math.ceil(uploadBytes * 1.1); // 10% safety margin
          if (available < required) {
            return reply.code(507).send({
              detail: `Insufficient disk space in ${TMP_DIR}: ${available} bytes available, ${required} bytes required (upload ${uploadBytes} bytes + 10% margin).`,
            });
          }
        }
      }

      // -----------------------------------------------------------------------
      // 2. Accept the multipart upload and stream to a temp file
      // -----------------------------------------------------------------------
      let uploadedFilename = "<unknown>";
      const uploadId = crypto.randomUUID();
      const tmpPath = path.join(TMP_DIR, `sastbot-restore-${uploadId}.upload`);

      let data: Awaited<ReturnType<typeof req.file>>;
      try {
        data = await req.file();
      } catch (err) {
        // @fastify/multipart throws a 413-status FastifyError when fileSize is exceeded.
        throw err;
      }

      if (!data) {
        return reply.code(400).send({ detail: "No file found in the multipart request. Include the dump file as the 'file' field." });
      }

      uploadedFilename = data.filename || "<unnamed>";

      try {
        const writeStream = fs.createWriteStream(tmpPath);
        await pipeline(data.file as stream.Readable, writeStream);
      } catch (err) {
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        const msg = err instanceof Error ? err.message : String(err);
        return reply.code(500).send({ detail: `Failed to write upload to disk: ${msg}` });
      }

      const stat = await fsPromises.stat(tmpPath).catch(() => null);
      if (!stat || stat.size === 0) {
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        return reply.code(400).send({ detail: `Uploaded file '${uploadedFilename}' is empty.` });
      }

      // -----------------------------------------------------------------------
      // 3. Detect format
      // -----------------------------------------------------------------------
      const format = await detectFormat(tmpPath);

      if (format === "unknown") {
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        return reply.code(400).send({
          detail: "Unrecognized file format. Expected a SASTBot tarball (.tar.gz, gzip magic 0x1f 0x8b) or a legacy pg_dump custom file (magic 'PGDMP').",
        });
      }

      // -----------------------------------------------------------------------
      // 4. Tarball path — extract, validate, version-check, restore
      // -----------------------------------------------------------------------
      if (format === "tarball") {
        const extractDir = path.join(TMP_DIR, `sastbot-restore-${uploadId}`, "extracted");

        // Cleanup helper for the tarball path.
        const cleanupTarball = async (): Promise<void> => {
          await fsPromises.unlink(tmpPath).catch(() => undefined);
          await fsPromises.rm(
            path.join(TMP_DIR, `sastbot-restore-${uploadId}`),
            { recursive: true, force: true },
          ).catch(() => undefined);
        };

        // Extract
        const extractErr = await extractTarball(tmpPath, extractDir);
        if (extractErr) {
          await cleanupTarball();
          return reply.code(500).send({ detail: `Failed to extract tarball: ${extractErr}` });
        }

        // Validate that only the two expected files are present (path-traversal defence).
        let extractedEntries: string[];
        try {
          extractedEntries = await fsPromises.readdir(extractDir);
        } catch (err) {
          await cleanupTarball();
          return reply.code(500).send({ detail: `Failed to read extracted contents: ${err instanceof Error ? err.message : String(err)}` });
        }

        const allowed = new Set(["dump.pgcustom", "metadata.json", "artifacts"]);
        const unexpected = extractedEntries.filter((e) => !allowed.has(e));
        if (unexpected.length > 0) {
          await cleanupTarball();
          return reply.code(400).send({
            detail: `Tarball contains unexpected files: ${unexpected.join(", ")}. Expected only dump.pgcustom, metadata.json, and artifacts/.`,
          });
        }

        const dumpPath = path.join(extractDir, "dump.pgcustom");
        const metaPath = path.join(extractDir, "metadata.json");

        // Check the dump file exists
        const dumpStat = await fsPromises.stat(dumpPath).catch(() => null);
        if (!dumpStat) {
          await cleanupTarball();
          return reply.code(400).send({ detail: "Tarball does not contain dump.pgcustom." });
        }

        // Read + validate metadata.json.
        let metadata: BackupMetadata | null = null;
        let metadataWarning: string | undefined;
        if (extractedEntries.includes("metadata.json")) {
          try {
            const raw = await fsPromises.readFile(metaPath, "utf8");
            const parsed = MetadataSchema.safeParse(JSON.parse(raw));
            if (parsed.success) {
              metadata = parsed.data;
            } else {
              metadataWarning = "metadata.json is present but could not be parsed — treating as legacy dump. Version compatibility is unknown.";
            }
          } catch {
            metadataWarning = "metadata.json could not be read — treating as legacy dump. Version compatibility is unknown.";
          }
        } else {
          metadataWarning = "Tarball does not contain metadata.json — treating as legacy dump. Version compatibility is unknown.";
        }

        // Tarball-format version check: refuse if the dump was produced by a
        // backend with a strictly newer tarball format. Backward-compat
        // (older format) is allowed — older tarballs are read by all newer
        // backends — but a newer format may carry layout the current backend
        // can't safely interpret.
        if (metadata && metadata.sastbot_dump_format_version > SASTBOT_DUMP_FORMAT_VERSION) {
          await cleanupTarball();
          return reply.code(422).send({
            detail:
              `Cannot restore: the backup was produced with tarball format version ` +
              `${metadata.sastbot_dump_format_version}, but this backend only understands ` +
              `up to format version ${SASTBOT_DUMP_FORMAT_VERSION}. ` +
              `Upgrade the backend to at least the version that produced this backup, ` +
              `then retry the restore.`,
          });
        }

        // Version check: compare dump's schema_version to running expected_schema_version.
        // Prisma migration names start with YYYYMMDDHHMMSS_ timestamps, so
        // lexicographic comparison is equivalent to chronological comparison.
        let appVersionWarning: string | undefined;
        if (metadata) {
          const runningExpected = await getExpectedSchemaVersion();
          const dumpSchema = metadata.schema_version;

          if (dumpSchema > runningExpected) {
            // Dump is from a newer schema — refuse
            await cleanupTarball();
            return reply.code(422).send({
              detail:
                `Cannot restore: the backup was created with a newer schema version ` +
                `("${dumpSchema}") than the running backend expects ("${runningExpected}"). ` +
                `Upgrade the backend to at least the version that produced this backup, ` +
                `then retry the restore.`,
            });
          }

          // App version mismatch (with schema match or older-schema case): warn but proceed.
          if (metadata.app_version !== APP_VERSION) {
            appVersionWarning = `Backup app version (${metadata.app_version}) differs from the running backend (${APP_VERSION}). The restore will proceed — verify functionality after restart.`;
          }
        }

        // -----------------------------------------------------------------
        // mode=runtime branch — preserve auth + admin-config tables; rebuild
        // scan-output tables only. Requires metadata + exact schema match.
        // -----------------------------------------------------------------
        if (mode === "runtime") {
          if (!metadata) {
            await cleanupTarball();
            return reply.code(422).send({
              detail:
                "mode=runtime requires a SASTBot tarball with valid metadata.json " +
                "(this lets the server check that the dump's schema matches the " +
                "running backend). Re-take the backup via Admin → Settings → Backup, " +
                "or use mode=full to restore this legacy dump.",
            });
          }

          const runningExpected = await getExpectedSchemaVersion();
          if (metadata.schema_version !== runningExpected) {
            await cleanupTarball();
            return reply.code(422).send({
              detail:
                `mode=runtime requires the backup's schema version ` +
                `("${metadata.schema_version}") to exactly match the running backend's ` +
                `expected schema ("${runningExpected}"). ` +
                `Use mode=full to restore older backups (which migrates the dump forward) ` +
                `or take a fresh backup against the running backend.`,
            });
          }

          app.log.info(
            { dumpPath, filename: uploadedFilename, size: dumpStat.size },
            "Starting runtime-tier restore",
          );
          const tarballArtifacts = path.join(extractDir, "artifacts");
          const hasArtifacts = await fsPromises.access(tarballArtifacts).then(() => true).catch(() => false);
          const runtimeResult = await runRuntimeRestore({
            dumpPath,
            pgEnv,
            artifactSourceDir: hasArtifacts ? tarballArtifacts : null,
            artifactTargetDir: config.artifactDir,
          });

          if (!runtimeResult.ok) {
            app.log.error(
              { detail: runtimeResult.detail, status: runtimeResult.status },
              "Runtime restore failed",
            );
            // Cleanup the tarball temp dir; the restore service cleans up
            // restore_temp on its own.
            await cleanupTarball();
            return reply.code(runtimeResult.status).send({ detail: runtimeResult.detail });
          }

          await cleanupTarball();
          app.log.info({ filename: uploadedFilename }, "Runtime restore completed — backend will restart");

          const appVersionWarning =
            metadata.app_version !== APP_VERSION
              ? `Backup app version (${metadata.app_version}) differs from the running backend (${APP_VERSION}). The runtime restore proceeded — verify functionality after restart.`
              : undefined;

          const responseBody: z.infer<typeof RestoreResponseSchema> = {
            ok: true,
            restarting: true,
            migrations_applied: [],
            ...(appVersionWarning ? { app_version_warning: appVersionWarning } : {}),
          };

          await reply.code(200).send(responseBody);
          setImmediate(() => {
            app.log.info("Exiting for clean Docker restart after runtime DB restore");
            process.exit(0);
          });
          return;
        }

        // Run pg_restore (mode=full)
        app.log.info({ dumpPath, filename: uploadedFilename, size: dumpStat.size }, "Starting pg_restore (tarball path)");
        const restoreResult = await runPgRestore(dumpPath, pgEnv);

        if (restoreResult.exitCode !== 0) {
          app.log.error(
            { code: restoreResult.exitCode, stderr: restoreResult.stderr, dumpPath },
            "pg_restore failed — temp files retained for inspection",
          );
          return reply.code(500).send({
            detail:
              `pg_restore exited with code ${restoreResult.exitCode}. ` +
              "The database may be in a partially-restored state — verify before serving traffic. " +
              `Temp files retained at: ${extractDir}. ` +
              (restoreResult.stderr ? `pg_restore stderr: ${restoreResult.stderr}` : "No stderr output captured."),
          });
        }

        // A6.2: overlay artifact directory. mode=full = "exactly as backup".
        // `clearDirContents` empties the dir without unlinking it — `fs.rm` of
        // the dir itself fails EBUSY on a mount point in containerized
        // deployments where ARTIFACT_DIR is a Docker volume.
        try {
          await clearDirContents(config.artifactDir);
          const tarballArtifacts = path.join(extractDir, "artifacts");
          const hasArtifacts = await fsPromises.access(tarballArtifacts).then(() => true).catch(() => false);
          if (hasArtifacts) {
            const entries = await fsPromises.readdir(tarballArtifacts);
            for (const entry of entries) {
              await fsPromises.cp(
                path.join(tarballArtifacts, entry),
                path.join(config.artifactDir, entry),
                { recursive: true },
              );
            }
          }
          app.log.info({ artifactCount: metadata?.artifact_count ?? 0 }, "A6: artifact dir overlaid (mode=full)");
        } catch (err) {
          app.log.error({ err }, "A6: artifact overlay failed (mode=full) — DB is restored but artifact dir is empty");
          return reply.code(500).send({
            detail: `pg_restore succeeded but artifact overlay failed: ${err instanceof Error ? err.message : String(err)}. The database is restored from the backup; the artifact directory is empty. Re-run mode=full with the same tarball to retry the artifact overlay (idempotent).`,
          });
        }

        // Auto migrate-forward if the dump schema is older than expected.
        let migrationsApplied: string[] = [];
        if (metadata && metadata.schema_version < (await getExpectedSchemaVersion())) {
          app.log.info(
            { dumpSchema: metadata.schema_version },
            "Dump schema is older than expected — running prisma migrate deploy",
          );
          const migrateResult = await runPrismaMigrateDeploy(config.databaseUrl);

          if (!migrateResult.ok) {
            // DB is in a partially-migrated state — return 500 with guidance.
            app.log.error(
              { stderr: migrateResult.stderr, extractDir },
              "prisma migrate deploy failed — DB may be in partially-migrated state",
            );
            return reply.code(500).send({
              detail:
                `pg_restore succeeded but prisma migrate deploy failed. ` +
                `The database is in a partially-migrated state — do not serve traffic until migration is complete. ` +
                `Temp files retained at: ${extractDir}. ` +
                (migrateResult.stderr ? `Prisma stderr: ${migrateResult.stderr}` : "No stderr output captured."),
            });
          }

          migrationsApplied = migrateResult.appliedMigrations;
          app.log.info({ migrationsApplied }, "prisma migrate deploy completed");
        }

        // Full success
        await cleanupTarball();
        app.log.info({ filename: uploadedFilename }, "Restore (tarball) completed successfully — backend will restart");

        const responseBody: z.infer<typeof RestoreResponseSchema> = {
          ok: true,
          restarting: true,
          migrations_applied: migrationsApplied,
          ...(metadataWarning ? { migration_warning: metadataWarning } : {}),
          ...(appVersionWarning ? { app_version_warning: appVersionWarning } : {}),
        };

        await reply.code(200).send(responseBody);

        setImmediate(() => {
          app.log.info("Exiting for clean Docker restart after DB restore (tarball path)");
          process.exit(0);
        });
        return;
      }

      // -----------------------------------------------------------------------
      // 5. Legacy .dump path — restore unconditionally with a warning
      // -----------------------------------------------------------------------
      // (format === "pgdump")

      if (mode === "runtime") {
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        return reply.code(422).send({
          detail:
            "mode=runtime requires a SASTBot tarball with metadata.json so the server " +
            "can verify the dump's schema version. The uploaded legacy .dump file has " +
            "no metadata. Use mode=full to restore this file.",
        });
      }

      app.log.info({ tmpPath, filename: uploadedFilename, size: stat.size }, "Starting pg_restore (legacy .dump path)");

      const restoreResult = await runPgRestore(tmpPath, pgEnv);

      if (restoreResult.exitCode === 0) {
        await fsPromises.unlink(tmpPath).catch((e) => {
          app.log.warn({ err: e, tmpPath }, "Could not delete restore temp file");
        });

        app.log.info({ filename: uploadedFilename }, "pg_restore (legacy) completed successfully — backend will restart");

        const responseBody: z.infer<typeof RestoreResponseSchema> = {
          ok: true,
          restarting: true,
          migrations_applied: [],
          migration_warning: "File has no version metadata (legacy .dump format). No version compatibility checks were performed — verify the DB state after restart.",
        };

        await reply.code(200).send(responseBody);

        setImmediate(() => {
          app.log.info("Exiting for clean Docker restart after DB restore (legacy path)");
          process.exit(0);
        });
        return;
      }

      // Legacy restore failure
      app.log.error(
        { code: restoreResult.exitCode, stderr: restoreResult.stderr, tmpPath },
        "pg_restore failed (legacy path) — temp file retained for inspection",
      );

      return reply.code(500).send({
        detail:
          `pg_restore exited with code ${restoreResult.exitCode}. ` +
          "The database may be in a partially-restored state — verify before serving traffic. " +
          `Temp file retained at: ${tmpPath}. ` +
          (restoreResult.stderr ? `pg_restore stderr: ${restoreResult.stderr}` : "No stderr output captured."),
      });
    },
  );
};

export default adminRestoreRoutes;
