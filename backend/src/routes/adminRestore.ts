/**
 * Admin DB restore route.
 *
 * POST /admin/db/restore
 *   Accepts a multipart upload of a pg_dump custom-format file and restores
 *   it into the configured DATABASE_URL using pg_restore. Admin-only.
 *
 *   Workflow:
 *     1. Pre-flight: check Content-Length against available /tmp disk space (507).
 *     2. Stream upload to a temp file at /tmp/sastbot-restore-<uuid>.dump.
 *     3. Run `pg_restore --list` to extract migration names for a mismatch check.
 *     4. Run `pg_restore --clean --if-exists --no-owner --no-privileges`.
 *     5. On success: delete temp file, respond { ok: true, restarting: true },
 *        then call process.exit(0) so Docker restart policy brings the backend
 *        back with clean DB connections.
 *     6. On failure: keep the temp file for operator inspection, return 500 with
 *        the captured stderr and a warning that the DB may be partially restored.
 *
 * Security notes:
 *   - DB credentials passed via PG* env vars only, never as CLI arguments.
 *   - Temp file is written to /tmp inside the backend container — this is safe
 *     because the container runs as a non-root user with no process isolation
 *     concern, and /tmp is ephemeral (destroyed when the container restarts).
 *     The dump file does not contain the master encryption key; it contains
 *     ciphertext. An attacker with container exec access already has the
 *     plaintext master key via process.env, so the temp file adds no extra
 *     exposure beyond what already exists in that threat model.
 *   - multipart plugin is registered at the route level (not globally) to avoid
 *     applying a 2 GiB body-size limit to all routes.
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

const TMP_DIR = "/tmp";

/**
 * Decompose a postgres:// URL into the env vars pg_restore understands.
 * Identical logic to the backup route's helper — kept local to avoid a
 * shared-import coupling between two sibling route files.
 */
function pgEnvFromUrl(databaseUrl: string): Record<string, string> | null {
  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    return null;
  }

  const env: Record<string, string> = {};
  if (url.hostname) env["PGHOST"] = url.hostname;
  if (url.port) env["PGPORT"] = url.port;
  if (url.username) env["PGUSER"] = decodeURIComponent(url.username);
  if (url.password) env["PGPASSWORD"] = decodeURIComponent(url.password);
  const dbName = url.pathname.slice(1);
  if (dbName) env["PGDATABASE"] = dbName;

  return env;
}

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
 * Run `pg_restore --list` on the temp file and extract migration names.
 * Returns an array of migration directory names found in the dump's TOC.
 * Returns [] on any error (non-blocking — used only for a warning).
 */
async function extractDumpMigrationNames(dumpPath: string, pgEnv: Record<string, string>): Promise<string[]> {
  return new Promise((resolve) => {
    let pr: ReturnType<typeof spawn>;
    try {
      pr = spawn("pg_restore", ["--list", dumpPath], {
        env: { ...process.env, ...pgEnv },
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      resolve([]);
      return;
    }

    const chunks: Buffer[] = [];
    pr.stdout?.on("data", (c: Buffer) => chunks.push(c));
    pr.on("close", (code) => {
      if (code !== 0) { resolve([]); return; }
      const text = Buffer.concat(chunks).toString("utf8");
      // TOC lines that reference _prisma_migrations look like:
      //   2941; 0 5 TABLE public _prisma_migrations sastbot
      // We want the migration names stored in the data: extract them from
      // TABLE DATA lines that reference _prisma_migrations specifically.
      // Simpler approach: look for any line containing _prisma_migrations.
      const migrationNames: string[] = [];
      for (const line of text.split("\n")) {
        const m = line.match(/20\d{17}_\w+/);
        if (m) migrationNames.push(m[0]);
      }
      resolve(migrationNames);
    });
    pr.on("error", () => resolve([]));
  });
}

/**
 * Read the local migration directory names (the timestamps) from the Prisma
 * migrations folder. Used to compare against the dump's migration list.
 */
async function localMigrationNames(): Promise<string[]> {
  // Resolve relative to this source file: src/routes/ → src/ → backend/ → migrations/
  const migrationsDir = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "../../prisma/migrations",
  );
  try {
    const entries = await fsPromises.readdir(migrationsDir, { withFileTypes: true });
    return entries
      .filter((e) => e.isDirectory())
      .map((e) => e.name);
  } catch {
    return [];
  }
}

const RestoreResponseSchema = z.object({
  ok: z.boolean(),
  restarting: z.boolean(),
  migration_warning: z.string().optional(),
});

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
        summary: "Upload a pg_dump file and restore it into the application database",
        response: {
          200: RestoreResponseSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          507: ErrorSchema,
          500: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const pgEnv = pgEnvFromUrl(config.databaseUrl);
      if (!pgEnv) {
        return reply.code(500).send({ detail: "Could not parse DATABASE_URL to build pg_restore connection parameters" });
      }

      // -----------------------------------------------------------------------
      // 1. Pre-flight: disk space check
      //    Read Content-Length before the body has been consumed. If the header
      //    is present, reject early if there won't be enough space (10% margin).
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
      const tmpPath = path.join(TMP_DIR, `sastbot-restore-${crypto.randomUUID()}.dump`);

      let data: Awaited<ReturnType<typeof req.file>>;
      try {
        data = await req.file();
      } catch (err) {
        // @fastify/multipart throws a 413-status FastifyError when fileSize is exceeded.
        // Let Fastify's global error handler re-throw it as-is (it already has statusCode 413).
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
        // Clean up partial write
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        const msg = err instanceof Error ? err.message : String(err);
        return reply.code(500).send({ detail: `Failed to write upload to disk: ${msg}` });
      }

      // Verify the upload landed (non-empty file)
      const stat = await fsPromises.stat(tmpPath).catch(() => null);
      if (!stat || stat.size === 0) {
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        return reply.code(400).send({ detail: `Uploaded file '${uploadedFilename}' is empty.` });
      }

      // -----------------------------------------------------------------------
      // 3. Migration version mismatch check (warn only — never refuse)
      // -----------------------------------------------------------------------
      let migrationWarning: string | undefined;
      try {
        const [dumpMigrations, localMigrations] = await Promise.all([
          extractDumpMigrationNames(tmpPath, pgEnv),
          localMigrationNames(),
        ]);

        if (dumpMigrations.length > 0 && localMigrations.length > 0) {
          const localSet = new Set(localMigrations);
          const dumpSet = new Set(dumpMigrations);
          const missingFromDump = localMigrations.filter((m) => !dumpSet.has(m));
          const extraInDump = dumpMigrations.filter((m) => !localSet.has(m));
          if (missingFromDump.length > 0 || extraInDump.length > 0) {
            const parts: string[] = [];
            if (missingFromDump.length > 0) {
              parts.push(`migrations in this backend not in the dump: ${missingFromDump.join(", ")}`);
            }
            if (extraInDump.length > 0) {
              parts.push(`migrations in the dump not in this backend: ${extraInDump.join(", ")}`);
            }
            migrationWarning = `Migration version mismatch — proceed with caution. ${parts.join("; ")}.`;
          }
        }
      } catch {
        // Migration check is best-effort; never block on it
      }

      // -----------------------------------------------------------------------
      // 4. Run pg_restore --clean --if-exists --no-owner --no-privileges
      // -----------------------------------------------------------------------
      app.log.info({ tmpPath, filename: uploadedFilename, size: stat.size }, "Starting pg_restore");

      let pgRestore: ReturnType<typeof spawn>;
      try {
        pgRestore = spawn(
          "pg_restore",
          [
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            tmpPath,
            // Connection comes from PG* env vars; no connection-string arg.
          ],
          {
            env: { ...process.env, ...pgEnv },
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
      } catch (spawnErr) {
        await fsPromises.unlink(tmpPath).catch(() => undefined);
        const msg = spawnErr instanceof Error ? spawnErr.message : String(spawnErr);
        return reply.code(500).send({ detail: `Failed to spawn pg_restore: ${msg}. Is postgresql-client-16 installed in the backend image?` });
      }

      const stderrChunks: Buffer[] = [];
      pgRestore.stderr?.on("data", (c: Buffer) => stderrChunks.push(c));

      const restoreExitCode = await new Promise<number | null>((resolve) => {
        pgRestore.on("close", resolve);
        pgRestore.on("error", () => resolve(-1));
      });

      const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();

      // -----------------------------------------------------------------------
      // 5a. Success path
      // -----------------------------------------------------------------------
      if (restoreExitCode === 0) {
        // Delete the temp file before exiting — do this non-fatally.
        await fsPromises.unlink(tmpPath).catch((e) => {
          app.log.warn({ err: e, tmpPath }, "Could not delete restore temp file");
        });

        app.log.info({ filename: uploadedFilename }, "pg_restore completed successfully — backend will restart");

        const responseBody = {
          ok: true,
          restarting: true,
          ...(migrationWarning ? { migration_warning: migrationWarning } : {}),
        };

        // Send the HTTP response first, then exit after a short tick so the
        // OS has time to flush the socket buffers before the process dies.
        await reply.code(200).send(responseBody);

        // Use setImmediate to give the event loop one tick to flush the response.
        setImmediate(() => {
          app.log.info("Exiting for clean Docker restart after DB restore");
          process.exit(0);
        });
        return;
      }

      // -----------------------------------------------------------------------
      // 5b. Failure path — keep the temp file for operator inspection
      // -----------------------------------------------------------------------
      app.log.error(
        { code: restoreExitCode, stderr, tmpPath },
        "pg_restore failed — temp file retained for inspection",
      );

      return reply.code(500).send({
        detail:
          `pg_restore exited with code ${restoreExitCode}. ` +
          "The database may be in a partially-restored state — verify before serving traffic. " +
          `Temp file retained at: ${tmpPath}. ` +
          (stderr ? `pg_restore stderr: ${stderr}` : "No stderr output captured."),
      });
    },
  );
};

export default adminRestoreRoutes;
