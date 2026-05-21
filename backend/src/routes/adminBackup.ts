/**
 * Admin DB backup route.
 *
 * GET /admin/db/backup
 *   Streams a tar.gz archive containing:
 *     - dump.pgcustom  — pg_dump (custom format, compress=9) of the database
 *     - metadata.json  — { app_version, schema_version, expected_schema_version,
 *                           exported_at, sastbot_dump_format_version }
 *
 *   Admin-only.
 *
 * Security notes:
 *   - The DATABASE_URL password is never passed via argv. Instead, we
 *     decompose the URL and pass the individual parts through the standard
 *     PG* environment variables that pg_dump reads natively.
 *   - The spawned command is never logged (argv could contain the password
 *     if we used the connection-string flag form).
 *   - The tar output is piped directly into the HTTP response — only the
 *     pg_dump output is buffered on disk (in a temp dir).
 *
 * Implementation notes:
 *   - A temp dir is created under /tmp for each backup request.
 *   - pg_dump writes dump.pgcustom to the temp dir.
 *   - metadata.json is written to the temp dir.
 *   - `tar -czf - -C <tmpdir> dump.pgcustom metadata.json` pipes the tarball
 *     to stdout, which we pipe directly into the HTTP response.
 *   - The temp dir is removed on success or error.
 */

import * as crypto from "node:crypto";
import * as fsPromises from "node:fs/promises";
import * as path from "node:path";
import { spawn } from "node:child_process";

import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

import { loadConfig } from "../config.js";
import { ErrorSchema } from "../schemas.js";
import { buildBackupMetadata } from "../services/backupMetadata.js";
import { getAppliedSchemaVersion, getExpectedSchemaVersion } from "./version.js";

/**
 * Decompose a postgres:// URL into the env vars pg_dump understands.
 * Returns null if the URL can't be parsed.
 */
export function pgEnvFromUrl(databaseUrl: string): Record<string, string> | null {
  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    return null;
  }

  // URL.hostname is already decoded; the password may contain special chars.
  const env: Record<string, string> = {};
  if (url.hostname) env["PGHOST"] = url.hostname;
  if (url.port) env["PGPORT"] = url.port;
  if (url.username) env["PGUSER"] = decodeURIComponent(url.username);
  if (url.password) env["PGPASSWORD"] = decodeURIComponent(url.password);
  // pathname starts with "/", strip it to get the database name.
  const dbName = url.pathname.slice(1);
  if (dbName) env["PGDATABASE"] = dbName;

  return env;
}

const adminBackupRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/admin/db/backup",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "backup"],
        summary: "Stream a tar.gz backup archive (dump.pgcustom + metadata.json)",
        response: {
          // 200 is a binary stream — not described in the OpenAPI schema
          // because fastify-type-provider-zod can't express application/gzip bodies.
          401: ErrorSchema,
          403: ErrorSchema,
          500: ErrorSchema,
        },
      },
    },
    async (_req, reply) => {
      const config = loadConfig();

      const pgEnv = pgEnvFromUrl(config.databaseUrl);
      if (!pgEnv) {
        return reply.code(500).send({ detail: "Could not parse DATABASE_URL to build pg_dump connection parameters" });
      }

      // Gather version metadata before spawning anything (fast async reads).
      const [schemaVersion, expectedSchemaVersion] = await Promise.all([
        getAppliedSchemaVersion(),
        getExpectedSchemaVersion(),
      ]);

      // ISO timestamp trimmed to seconds, safe for filenames (colons replaced).
      const timestamp = new Date().toISOString().replace(/:/g, "-").replace(/\..+/, "");
      // First 14 chars of the schema version is the YYYYMMDDHHMMSS prefix.
      const schemaShort = schemaVersion.slice(0, 14);
      const filename = `sastbot-backup-${timestamp}-${schemaShort}.tar.gz`;

      // Create a temp dir for the pg_dump output and metadata.
      const tmpDir = path.join("/tmp", `sastbot-backup-${crypto.randomUUID()}`);
      try {
        await fsPromises.mkdir(tmpDir, { recursive: true });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return reply.code(500).send({ detail: `Failed to create temp dir: ${msg}` });
      }

      const dumpPath = path.join(tmpDir, "dump.pgcustom");
      const metaPath = path.join(tmpDir, "metadata.json");

      // Cleanup helper — always called on success and error paths.
      const cleanup = async (): Promise<void> => {
        await fsPromises.rm(tmpDir, { recursive: true, force: true }).catch((e) => {
          app.log.warn({ err: e, tmpDir }, "Could not remove backup temp dir");
        });
      };

      // -------------------------------------------------------------------
      // Step 1: Run pg_dump into <tmpdir>/dump.pgcustom
      // -------------------------------------------------------------------
      let pgDump: ReturnType<typeof spawn>;
      try {
        pgDump = spawn(
          "pg_dump",
          [
            "--format=custom",
            "--compress=9",
            "--file",
            dumpPath,
            // No connection-string positional arg; pg_dump reads PG* env vars.
          ],
          {
            env: { ...process.env, ...pgEnv },
            stdio: ["ignore", "ignore", "pipe"],
          },
        );
      } catch (spawnErr) {
        app.log.error({ err: spawnErr }, "Failed to spawn pg_dump");
        await cleanup();
        return reply.code(500).send({ detail: "pg_dump not available — is postgresql-client-16 installed in the backend image?" });
      }

      const pgDumpStderrChunks: Buffer[] = [];
      pgDump.stderr?.on("data", (chunk: Buffer) => pgDumpStderrChunks.push(chunk));

      // Wait for pg_dump to finish (writing to a file, not piped to us).
      const pgDumpExitCode = await new Promise<number | null>((resolve) => {
        pgDump.on("close", resolve);
        pgDump.on("error", () => resolve(-1));
      });

      if (pgDumpExitCode !== 0) {
        const stderr = Buffer.concat(pgDumpStderrChunks).toString("utf8").trim();
        app.log.error({ code: pgDumpExitCode, stderr }, "pg_dump exited with non-zero code");
        await cleanup();
        return reply.code(500).send({
          detail: `pg_dump failed (exit code ${pgDumpExitCode}). ${stderr ? `Stderr: ${stderr}` : "No stderr output."}`,
        });
      }

      // -------------------------------------------------------------------
      // Step 2: Write metadata.json
      // -------------------------------------------------------------------
      const metadata = buildBackupMetadata({ schemaVersion, expectedSchemaVersion });
      try {
        await fsPromises.writeFile(metaPath, JSON.stringify(metadata, null, 2), "utf8");
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await cleanup();
        return reply.code(500).send({ detail: `Failed to write metadata.json: ${msg}` });
      }

      // -------------------------------------------------------------------
      // Step 3: Spawn tar and pipe stdout directly into the HTTP response
      // -------------------------------------------------------------------
      let tarProc: ReturnType<typeof spawn>;
      try {
        tarProc = spawn(
          "tar",
          [
            "-czf", "-",
            "-C", tmpDir,
            "dump.pgcustom",
            "metadata.json",
          ],
          {
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
      } catch (spawnErr) {
        app.log.error({ err: spawnErr }, "Failed to spawn tar");
        await cleanup();
        return reply.code(500).send({ detail: "tar not available — is it installed in the backend image?" });
      }

      // We've already successfully run pg_dump and written metadata.json to disk —
      // all fallible pre-work is complete. Commit to the 200 response and pipe tar
      // stdout directly into the raw HTTP connection.
      //
      // We do NOT probe tar with a "first data" event before writing headers,
      // because attaching a "data" listener switches the stream to flowing mode
      // and would cause the first chunk to be silently dropped before the pipe
      // is attached. Since we already confirmed that both files exist on disk
      // (pg_dump and metadata write succeeded), tar failure at this point is
      // extremely unlikely. If tar is truly missing, the spawn() call itself would
      // throw synchronously (ENOENT) and we'd handle it in the catch block above.

      // Stream tar stdout directly into the raw HTTP response, bypassing Fastify's
      // serializer. reply.hijack() prevents Fastify from sending a second response
      // after the handler returns.
      reply.hijack();
      const raw = reply.raw;
      raw.writeHead(200, {
        "Content-Type": "application/gzip",
        "Content-Disposition": `attachment; filename="${filename}"`,
      });

      const tarStderrChunks: Buffer[] = [];
      tarProc.stderr?.on("data", (c: Buffer) => tarStderrChunks.push(c));

      await new Promise<void>((resolve) => {
        // Suppress further errors on the raw socket — client disconnect is not fatal.
        raw.on("error", (err) => {
          app.log.warn({ err }, "backup tar stream: client disconnected");
          tarProc.kill();
          resolve();
        });
        tarProc.stdout?.pipe(raw);
        tarProc.stdout?.on("end", resolve);
        tarProc.stdout?.on("error", (err) => {
          app.log.error({ err }, "tar stdout error");
          raw.end();
          resolve();
        });
      });

      // After streaming, check tar exit code and clean up.
      tarProc.on("close", async (code) => {
        if (code !== 0) {
          const stderr = Buffer.concat(tarStderrChunks).toString("utf8").trim();
          app.log.error({ code, stderr }, "tar exited with non-zero code");
        } else {
          app.log.info({ filename }, "DB backup tarball streamed successfully");
        }
        await cleanup();
      });
    },
  );
};

export default adminBackupRoutes;
