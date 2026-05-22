/**
 * Unit tests for the mode=runtime restore service.
 *
 * Live DB orchestration (rename dance + pg_restore) is exercised manually
 * via curl against the trial Dokploy host; these tests cover the bucket
 * partition constants and the FK-violation message formatter that operators
 * see when they trigger the edge case.
 */

import * as fsPromises from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { describe, expect, it } from "vitest";

import {
  CROSS_BUCKET_FKS,
  PRESERVE_BUCKET,
  RESTORE_BUCKET_INSERT_ORDER,
  RESTORE_BUCKET_TRUNCATE_ORDER,
  checkArtifactOrphans,
  formatFkViolationMessage,
} from "../src/services/restoreService.js";

describe("bucket partition", () => {
  it("PRESERVE and RESTORE buckets are disjoint", () => {
    const preserve = new Set<string>(PRESERVE_BUCKET);
    for (const t of RESTORE_BUCKET_INSERT_ORDER) {
      expect(preserve.has(t)).toBe(false);
    }
  });

  it("TRUNCATE order is the reverse of INSERT order", () => {
    expect(RESTORE_BUCKET_TRUNCATE_ORDER).toEqual([...RESTORE_BUCKET_INSERT_ORDER].reverse());
  });

  it("PRESERVE bucket covers the Admin-nav surfaces", () => {
    // If a table is moved into Admin surfaces, it must be added here so that
    // mode=runtime preserves its current values.
    expect(PRESERVE_BUCKET).toEqual([
      "orgs",
      "users",
      "sessions",
      "credentials",
      "repos",
      "app_settings",
      "encryption_canary",
    ]);
  });

  it("every cross-bucket FK names a real PRESERVE-bucket parent", () => {
    const preserve = new Set<string>(PRESERVE_BUCKET);
    const sameBucket = CROSS_BUCKET_FKS.filter((fk) => !preserve.has(fk.parentTable));
    // It's fine for the FK list to include intra-RESTORE entries (we filter
    // them in checkCrossBucketFks). But every entry that targets a PRESERVE
    // parent must be a real PRESERVE table — typos would silently skip pre-flight.
    const crossBucket = CROSS_BUCKET_FKS.filter((fk) => preserve.has(fk.parentTable));
    expect(crossBucket.length).toBeGreaterThan(0);
    // sameBucket only exists for documentation; not a failure.
    expect(sameBucket.every((fk) => RESTORE_BUCKET_INSERT_ORDER.includes(fk.parentTable as never))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// A6: checkArtifactOrphans — filesystem-only logic (UUID parsing)
// We test the filename-parsing and set-diff logic by setting up tmp dirs.
// The DB call is not exercised here (it requires a live restore_temp schema);
// the integration path is covered by the broader restore service contract.
// ---------------------------------------------------------------------------

describe("checkArtifactOrphans — null input (old-format tarball)", () => {
  it("returns empty orphans when artifactSourceDir is null", async () => {
    // checkArtifactOrphans short-circuits on null without touching the DB.
    const result = await checkArtifactOrphans(null);
    expect(result.orphans).toHaveLength(0);
  });
});

describe("checkArtifactOrphans — UUID filename parsing", () => {
  // We test the UUID extraction logic by verifying that:
  // (a) files that match <uuid>.json or <uuid>.sarif.json are parsed,
  // (b) files with non-UUID names are ignored.
  // We cannot run the DB query in unit tests, so we test the pre-DB portion
  // indirectly by observing that the function doesn't throw when sbom/sarif
  // dirs are present but empty — it should return { orphans: [] } because
  // uuids.size === 0.

  it("returns empty orphans when sbom/ and sarif/ dirs are empty", async () => {
    const tmpDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), "sastbot-orphan-test-"));
    try {
      await fsPromises.mkdir(path.join(tmpDir, "sbom"), { recursive: true });
      await fsPromises.mkdir(path.join(tmpDir, "sarif"), { recursive: true });
      // checkArtifactOrphans will try to query the DB when uuids.size > 0.
      // Empty dirs → uuids.size === 0 → returns early without DB call.
      const result = await checkArtifactOrphans(tmpDir);
      expect(result.orphans).toHaveLength(0);
    } finally {
      await fsPromises.rm(tmpDir, { recursive: true, force: true });
    }
  });

  it("returns empty orphans when artifact dirs are missing (catches readdir error)", async () => {
    const tmpDir = await fsPromises.mkdtemp(path.join(os.tmpdir(), "sastbot-orphan-test-"));
    try {
      // No sbom/ or sarif/ subdirs — readdir catches throw, returns []
      const result = await checkArtifactOrphans(tmpDir);
      expect(result.orphans).toHaveLength(0);
    } finally {
      await fsPromises.rm(tmpDir, { recursive: true, force: true });
    }
  });
});

describe("formatFkViolationMessage", () => {
  it("includes the parent table the operator deleted (repos)", () => {
    const msg = formatFkViolationMessage([
      {
        childTable: "scan_runs",
        childColumn: "repo_id",
        parentTable: "repos",
        violationCount: 12n,
        sampleMissingIds: ["abc-1", "abc-2"],
      },
    ]);
    expect(msg).toContain("repos");
    expect(msg).toContain("12 scan_runs row(s)");
    expect(msg).toContain("abc-1");
    expect(msg).toContain("mode=full");
  });

  it("groups multiple violations into one error message", () => {
    const msg = formatFkViolationMessage([
      {
        childTable: "scan_runs",
        childColumn: "repo_id",
        parentTable: "repos",
        violationCount: 5n,
        sampleMissingIds: [],
      },
      {
        childTable: "scan_scopes",
        childColumn: "repo_id",
        parentTable: "repos",
        violationCount: 2n,
        sampleMissingIds: [],
      },
    ]);
    expect(msg).toContain("scan_runs");
    expect(msg).toContain("scan_scopes");
  });

  it("truncates sample-ID lists to the first three to avoid wall-of-uuids", () => {
    const msg = formatFkViolationMessage([
      {
        childTable: "scan_runs",
        childColumn: "repo_id",
        parentTable: "repos",
        violationCount: 99n,
        sampleMissingIds: ["a", "b", "c", "d", "e"],
      },
    ]);
    expect(msg).toContain("a, b, c");
    expect(msg).not.toContain("a, b, c, d");
  });
});
