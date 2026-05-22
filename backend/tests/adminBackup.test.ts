/**
 * Unit tests for the DB backup route helper and auth gating.
 *
 * pgEnvFromUrl is now exported from adminBackup.ts (also consumed by
 * adminRestore.ts) so we test the canonical implementation directly.
 */

import * as fsPromises from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { describe, expect, it } from "vitest";

import { pgEnvFromUrl, summarizeArtifactDir } from "../src/routes/adminBackup.js";

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

// ---------------------------------------------------------------------------
// summarizeArtifactDir
// ---------------------------------------------------------------------------

describe("summarizeArtifactDir", () => {
  it("returns zero count and bytes for a missing directory", async () => {
    const result = await summarizeArtifactDir("/tmp/nonexistent-dir-12345-sastbot-test");
    expect(result.count).toBe(0);
    expect(result.bytes).toBe(0);
  });

  it("returns zero count and bytes for an empty directory", async () => {
    const tmpDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), "sastbot-test-"));
    try {
      const result = await summarizeArtifactDir(tmpDir);
      expect(result.count).toBe(0);
      expect(result.bytes).toBe(0);
    } finally {
      await fsPromises.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("counts files and sums their sizes recursively", async () => {
    const tmpDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), "sastbot-test-"));
    try {
      const sbomDir = path.join(tmpDir, "sbom");
      const sarifDir = path.join(tmpDir, "sarif");
      await fsPromises.mkdir(sbomDir, { recursive: true });
      await fsPromises.mkdir(sarifDir, { recursive: true });
      // Write 3 files with known sizes
      await fsPromises.writeFile(path.join(sbomDir, "a.json"), "x".repeat(100));
      await fsPromises.writeFile(path.join(sbomDir, "b.json"), "y".repeat(200));
      await fsPromises.writeFile(path.join(sarifDir, "c.sarif.json"), "z".repeat(300));

      const result = await summarizeArtifactDir(tmpDir);
      expect(result.count).toBe(3);
      expect(result.bytes).toBe(600);
    } finally {
      await fsPromises.rm(tmpDir, { recursive: true, force: true });
    }
  });
});
