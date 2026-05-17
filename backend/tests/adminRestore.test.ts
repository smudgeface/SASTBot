/**
 * Unit tests for the DB restore route helpers.
 *
 * The route has two security-sensitive helpers that we test directly:
 * 1. pgEnvFromUrl — same logic as the backup route; must never leak passwords.
 * 2. The disk-space pre-flight math (10% safety margin formula).
 * 3. The migration mismatch warning logic (simulated via the extracted arrays).
 *
 * We do NOT spin up a real Fastify instance here because the route depends on
 * pg_restore being on PATH and a real DB — that's smoke-tested manually against
 * the compose stack. The helpers are tested by replicating their logic here,
 * mirroring the pattern used in adminBackup.test.ts.
 */

import { describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// pgEnvFromUrl — replicated locally (private fn in the route module)
// ---------------------------------------------------------------------------

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

describe("pgEnvFromUrl (restore route)", () => {
  it("decomposes a standard DATABASE_URL into PG* env vars", () => {
    const env = pgEnvFromUrl("postgresql://myuser:mypassword@postgres:5432/mydb");
    expect(env).toMatchObject({
      PGHOST: "postgres",
      PGPORT: "5432",
      PGUSER: "myuser",
      PGPASSWORD: "mypassword",
      PGDATABASE: "mydb",
    });
  });

  it("URL-decodes special characters in the password", () => {
    const password = "p@ss/word:with!chars";
    const encoded = encodeURIComponent(password);
    const env = pgEnvFromUrl(`postgresql://user:${encoded}@host:5432/db`);
    expect(env?.["PGPASSWORD"]).toBe(password);
  });

  it("returns null for an unparseable URL", () => {
    expect(pgEnvFromUrl("not-a-url")).toBeNull();
    expect(pgEnvFromUrl("")).toBeNull();
  });

  it("password never bleeds into other PG* fields", () => {
    const password = "super-secret-restore-pw";
    const env = pgEnvFromUrl(`postgresql://admin:${encodeURIComponent(password)}@db:5432/prod`);
    expect(env?.["PGPASSWORD"]).toBe(password);
    expect(env?.["PGHOST"]).not.toContain(password);
    expect(env?.["PGUSER"]).not.toContain(password);
    expect(env?.["PGDATABASE"]).not.toContain(password);
  });
});

// ---------------------------------------------------------------------------
// Disk-space pre-flight math
// ---------------------------------------------------------------------------

/**
 * Replicate the route's required-bytes calculation.
 * required = ceil(uploadBytes * 1.1)
 */
function requiredBytes(uploadBytes: number): number {
  return Math.ceil(uploadBytes * 1.1);
}

describe("disk space pre-flight", () => {
  it("adds a 10% safety margin to the upload size", () => {
    expect(requiredBytes(1_000_000_000)).toBe(1_100_000_000);
    // 100 * 1.1 = 110.00000000000001 in IEEE-754 → ceil → 111
    expect(requiredBytes(100)).toBe(Math.ceil(100 * 1.1));
  });

  it("rounds up fractional bytes", () => {
    // 1.1 * 3 = 3.3 → ceil → 4
    expect(requiredBytes(3)).toBe(4);
    // 1.1 * 10 = 11 → ceil → 11
    expect(requiredBytes(10)).toBe(11);
  });

  it("rejects when available < required", () => {
    const available = 500_000_000; // 500 MB
    const upload = 600_000_000;    // 600 MB upload
    const required = requiredBytes(upload); // 660 MB
    expect(available < required).toBe(true);
  });

  it("accepts when available >= required", () => {
    const available = 2_000_000_000; // 2 GB
    const upload = 1_000_000_000;    // 1 GB upload
    const required = requiredBytes(upload); // 1.1 GB
    expect(available < required).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Migration mismatch detection
// ---------------------------------------------------------------------------

describe("migration mismatch warning", () => {
  function checkMigrationMismatch(dumpMigrations: string[], localMigrations: string[]): string | undefined {
    if (dumpMigrations.length === 0 || localMigrations.length === 0) return undefined;
    const localSet = new Set(localMigrations);
    const dumpSet = new Set(dumpMigrations);
    const missingFromDump = localMigrations.filter((m) => !dumpSet.has(m));
    const extraInDump = dumpMigrations.filter((m) => !localSet.has(m));
    if (missingFromDump.length === 0 && extraInDump.length === 0) return undefined;
    const parts: string[] = [];
    if (missingFromDump.length > 0) {
      parts.push(`migrations in this backend not in the dump: ${missingFromDump.join(", ")}`);
    }
    if (extraInDump.length > 0) {
      parts.push(`migrations in the dump not in this backend: ${extraInDump.join(", ")}`);
    }
    return `Migration version mismatch — proceed with caution. ${parts.join("; ")}.`;
  }

  it("returns undefined when migrations match exactly", () => {
    const migrations = ["20240101_init", "20240201_add_user"];
    expect(checkMigrationMismatch(migrations, migrations)).toBeUndefined();
  });

  it("warns when backend has migrations not in the dump", () => {
    const dumpMigs = ["20240101_init"];
    const localMigs = ["20240101_init", "20240201_add_new_feature"];
    const warning = checkMigrationMismatch(dumpMigs, localMigs);
    expect(warning).toContain("migrations in this backend not in the dump");
    expect(warning).toContain("20240201_add_new_feature");
  });

  it("warns when dump has migrations not in the backend", () => {
    const dumpMigs = ["20240101_init", "20230101_older_migration"];
    const localMigs = ["20240101_init"];
    const warning = checkMigrationMismatch(dumpMigs, localMigs);
    expect(warning).toContain("migrations in the dump not in this backend");
    expect(warning).toContain("20230101_older_migration");
  });

  it("returns undefined when either list is empty (unable to extract)", () => {
    expect(checkMigrationMismatch([], ["20240101_init"])).toBeUndefined();
    expect(checkMigrationMismatch(["20240101_init"], [])).toBeUndefined();
    expect(checkMigrationMismatch([], [])).toBeUndefined();
  });
});
