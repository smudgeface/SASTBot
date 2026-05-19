/**
 * Public version endpoint.
 *
 * GET /version
 *   Returns app version, current DB schema version, expected schema version,
 *   and the dump format version constant. No authentication required — this is
 *   safe to expose publicly because none of the values are secret.
 *
 * "schema" is the actual latest applied migration name from _prisma_migrations.
 * "expected_schema" is the lexicographically-last directory name under
 *   backend/prisma/migrations/, which is what the running code was built against.
 * In a healthy deployment these two match. Surfacing both helps diagnose
 * "is this DB caught up?" without a separate endpoint.
 */

import * as fsPromises from "node:fs/promises";
import * as path from "node:path";

import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";

/** Integer bump if/when the tarball backup format changes incompatibly. */
export const SASTBOT_DUMP_FORMAT_VERSION = 1;

/**
 * App version — kept in sync with backend/package.json `version` field.
 * Update this when bumping the package version.
 */
export const APP_VERSION = "0.2.0";

/**
 * Read the lexicographically-last migration directory name from the Prisma
 * migrations folder. This is what the running code was compiled against.
 * Returns "unknown" on any I/O error.
 */
export async function getExpectedSchemaVersion(): Promise<string> {
  // Resolve relative to this source file: src/routes/ → src/ → backend/ → prisma/migrations/
  const migrationsDir = path.resolve(
    path.dirname(new URL(import.meta.url).pathname),
    "../../prisma/migrations",
  );
  try {
    const entries = await fsPromises.readdir(migrationsDir, { withFileTypes: true });
    const dirs = entries
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort(); // lexicographic sort — migration names are YYYYMMDDHHMMSS_ prefixed, so this is chronological
    return dirs[dirs.length - 1] ?? "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Query _prisma_migrations for the latest successfully applied migration name.
 * Returns "unknown" on any error (e.g. table not yet created, DB unreachable).
 *
 * _prisma_migrations is a Prisma-internal table; the Prisma client doesn't
 * expose a typed model for it, so we use $queryRawUnsafe.
 */
export async function getAppliedSchemaVersion(): Promise<string> {
  try {
    const rows = await prisma.$queryRawUnsafe<{ migration_name: string }[]>(
      `SELECT migration_name FROM _prisma_migrations
       WHERE finished_at IS NOT NULL
       ORDER BY finished_at DESC
       LIMIT 1`,
    );
    return rows[0]?.migration_name ?? "none";
  } catch {
    return "unknown";
  }
}

const VersionResponseSchema = z.object({
  app: z.string(),
  schema: z.string(),
  expected_schema: z.string(),
  sastbot_dump_format_version: z.number().int(),
});

const versionRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/version",
    {
      schema: {
        tags: ["meta"],
        summary: "App version, schema version, and dump format version (public)",
        response: { 200: VersionResponseSchema },
      },
    },
    async () => {
      const [schema, expected_schema] = await Promise.all([
        getAppliedSchemaVersion(),
        getExpectedSchemaVersion(),
      ]);
      return {
        app: APP_VERSION,
        schema,
        expected_schema,
        sastbot_dump_format_version: SASTBOT_DUMP_FORMAT_VERSION,
      };
    },
  );
};

export default versionRoutes;
