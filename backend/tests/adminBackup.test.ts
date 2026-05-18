/**
 * Unit tests for the DB backup route helper and auth gating.
 *
 * pgEnvFromUrl is now exported from adminBackup.ts (also consumed by
 * adminRestore.ts) so we test the canonical implementation directly.
 */

import { describe, expect, it } from "vitest";

import { pgEnvFromUrl } from "../src/routes/adminBackup.js";

describe("pgEnvFromUrl", () => {
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
    // Password contains @, /, : which must be percent-encoded in the URL
    const password = "p@ss/word:with!chars";
    const encoded = encodeURIComponent(password);
    const env = pgEnvFromUrl(`postgresql://user:${encoded}@host:5432/db`);
    expect(env?.["PGPASSWORD"]).toBe(password);
  });

  it("omits PGPORT when the URL has no explicit port", () => {
    const env = pgEnvFromUrl("postgresql://user:pass@host/db");
    expect(env).toBeDefined();
    expect(env?.["PGPORT"]).toBeUndefined();
    expect(env?.["PGHOST"]).toBe("host");
  });

  it("returns null for an unparseable URL", () => {
    expect(pgEnvFromUrl("not-a-url")).toBeNull();
    expect(pgEnvFromUrl("")).toBeNull();
  });

  it("handles a postgres:// URL (alias for postgresql://)", () => {
    const env = pgEnvFromUrl("postgres://u:secret@db-host:5432/appdb");
    expect(env?.["PGHOST"]).toBe("db-host");
    expect(env?.["PGPASSWORD"]).toBe("secret");
    expect(env?.["PGDATABASE"]).toBe("appdb");
  });

  it("password is NEVER present in the returned object's keys other than PGPASSWORD", () => {
    // Belt-and-suspenders: verify the password only appears under PGPASSWORD,
    // not leaked into PGHOST, PGUSER, PGDATABASE, or PGPORT.
    const password = "super-secret-password";
    const env = pgEnvFromUrl(`postgresql://admin:${encodeURIComponent(password)}@db:5432/prod`);
    expect(env?.["PGPASSWORD"]).toBe(password);
    // Ensure it didn't bleed into other fields
    expect(env?.["PGHOST"]).not.toContain(password);
    expect(env?.["PGUSER"]).not.toContain(password);
    expect(env?.["PGDATABASE"]).not.toContain(password);
  });
});
