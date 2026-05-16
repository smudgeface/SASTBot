/**
 * Admin DB backup route.
 *
 * GET /admin/db/backup
 *   Streams a pg_dump (custom format, compress=9) of the configured
 *   DATABASE_URL as an HTTP download. Admin-only.
 *
 * Security notes:
 *   - The DATABASE_URL password is never passed via argv. Instead, we
 *     decompose the URL and pass the individual parts through the standard
 *     PG* environment variables that pg_dump reads natively.
 *   - The spawned command is never logged (argv could contain the password
 *     if we used the connection-string flag form).
 *   - pg_dump's stdout is piped directly into the HTTP response — no
 *     in-memory buffering, so this is safe for large databases.
 */

import { spawn } from "node:child_process";

import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

import { loadConfig } from "../config.js";
import { ErrorSchema } from "../schemas.js";

/**
 * Decompose a postgres:// URL into the env vars pg_dump understands.
 * Returns null if the URL can't be parsed.
 */
function pgEnvFromUrl(databaseUrl: string): Record<string, string> | null {
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
        summary: "Stream a pg_dump of the application database (custom format, compress=9)",
        response: {
          // 200 is a binary stream — not described in the OpenAPI schema
          // because fastify-type-provider-zod can't express octet-stream bodies.
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

      // ISO timestamp trimmed to seconds, safe for filenames (colons replaced).
      const timestamp = new Date().toISOString().replace(/:/g, "-").replace(/\..+/, "");
      const filename = `sastbot-backup-${timestamp}.dump`;

      // Spawn pg_dump. Connection params come from env only — never from argv —
      // so the password is not visible in process listings or logs.
      //
      // We wrap the entire streaming operation in a try/catch so that a missing
      // pg_dump binary (ENOENT) is caught before we've committed to writing
      // the 200 header — allowing us to return a clean 500 error response.
      let pgDump: ReturnType<typeof spawn>;
      try {
        pgDump = spawn(
          "pg_dump",
          [
            "--format=custom",
            "--compress=9",
            // No connection-string positional arg; pg_dump reads PG* env vars.
          ],
          {
            env: {
              ...process.env,
              ...pgEnv,
            },
            // Do NOT inherit stdio — we pipe stdout ourselves.
            stdio: ["ignore", "pipe", "pipe"],
          },
        );
      } catch (spawnErr) {
        // spawn() itself can throw synchronously if the binary path is clearly
        // invalid; the async ENOENT comes via the 'error' event instead.
        app.log.error({ err: spawnErr }, "Failed to spawn pg_dump");
        return reply.code(500).send({ detail: "pg_dump not available — is postgresql-client-16 installed in the backend image?" });
      }

      // Pipe pg_dump stderr to the server logger for diagnostics.
      const stderrChunks: Buffer[] = [];
      pgDump.stderr?.on("data", (chunk: Buffer) => {
        stderrChunks.push(chunk);
      });

      // Wait for the first data event or the 'error' / 'close' event to confirm
      // the process started successfully before committing to the HTTP response.
      // This lets us return a clean 500 if pg_dump isn't on PATH (ENOENT error).
      await new Promise<void>((resolve, reject) => {
        pgDump.once("error", reject);
        pgDump.stdout?.once("data", () => resolve());
        // If stdout closes without data (empty DB produces a header immediately,
        // but a missing binary will close with an error first), resolve anyway
        // so we don't hang. The 'error' event fires before 'close' on ENOENT.
        pgDump.stdout?.once("close", () => resolve());
      }).catch((spawnErr: unknown) => {
        const msg = spawnErr instanceof Error ? spawnErr.message : String(spawnErr);
        app.log.error({ err: spawnErr }, "pg_dump failed to start");
        return reply.code(500).send({ detail: `pg_dump failed to start: ${msg}. Is postgresql-client-16 installed in the backend image?` });
      });

      // If reply was already sent (error path above), stop here.
      if (reply.sent) return;

      // Stream stdout directly into the raw HTTP response, bypassing Fastify's
      // serializer (which can't represent octet-stream in the Zod schema). We
      // manually write headers and pipe; reply.hijack() prevents Fastify from
      // sending a second response after the handler returns.
      reply.hijack();
      const raw = reply.raw;
      raw.writeHead(200, {
        "Content-Type": "application/octet-stream",
        "Content-Disposition": `attachment; filename="${filename}"`,
      });

      await new Promise<void>((resolve) => {
        // Suppress further errors on the raw socket — client disconnect is not fatal.
        raw.on("error", (err) => {
          app.log.warn({ err }, "pg_dump stream: client disconnected");
          pgDump.kill();
          resolve();
        });
        pgDump.stdout?.pipe(raw);
        pgDump.stdout?.on("end", resolve);
        // Any remaining stdout error after we've already started streaming
        // can only mean the process died — log and end the response.
        pgDump.stdout?.on("error", (err) => {
          app.log.error({ err }, "pg_dump stdout error");
          raw.end();
          resolve();
        });
      });

      // After the response stream ends, check the exit code for logging.
      pgDump.on("close", (code) => {
        if (code !== 0) {
          const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
          app.log.error({ code, stderr }, "pg_dump exited with non-zero code");
        } else {
          app.log.info({ filename }, "DB backup streamed successfully");
        }
      });
    },
  );
};

export default adminBackupRoutes;
