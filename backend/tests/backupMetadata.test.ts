/**
 * Unit tests for the shared backup-metadata builder.
 *
 * The util powers both the HTTP backup endpoint and the pre-deploy backup
 * script in docker/backend-entrypoint.sh. The restore endpoint's Zod schema
 * (routes/adminRestore.ts) validates the shape this function produces — if
 * any field name or type drifts here, restore will reject the dump as
 * "metadata.json could not be parsed".
 */

import { describe, expect, it } from "vitest";

import { buildBackupMetadata } from "../src/services/backupMetadata.js";

describe("buildBackupMetadata", () => {
  it("produces the exact field set the restore endpoint validates", () => {
    const out = buildBackupMetadata({
      schemaVersion: "20260516165953_add_per_repo_llm_token_budgets",
      expectedSchemaVersion: "20260516165953_add_per_repo_llm_token_budgets",
      exportedAt: new Date("2026-05-20T14:30:00.000Z"),
      appVersion: "0.2.0",
      dumpFormatVersion: 1,
    });

    expect(Object.keys(out).sort()).toEqual(
      [
        "app_version",
        "exported_at",
        "expected_schema_version",
        "sastbot_dump_format_version",
        "schema_version",
      ].sort(),
    );
    expect(out.app_version).toBe("0.2.0");
    expect(out.schema_version).toBe("20260516165953_add_per_repo_llm_token_budgets");
    expect(out.expected_schema_version).toBe("20260516165953_add_per_repo_llm_token_budgets");
    expect(out.exported_at).toBe("2026-05-20T14:30:00.000Z");
    expect(out.sastbot_dump_format_version).toBe(1);
  });

  it("captures the schema/expected mismatch when older dump precedes new code", () => {
    const out = buildBackupMetadata({
      schemaVersion: "20260424030102_m5c_jira_resolution",
      expectedSchemaVersion: "20260516165953_add_per_repo_llm_token_budgets",
    });
    expect(out.schema_version).not.toBe(out.expected_schema_version);
    expect(out.schema_version < out.expected_schema_version).toBe(true);
  });

  it("defaults exported_at to now() when omitted", () => {
    const before = Date.now();
    const out = buildBackupMetadata({
      schemaVersion: "20260422171946_init",
      expectedSchemaVersion: "20260422171946_init",
    });
    const after = Date.now();
    const parsed = Date.parse(out.exported_at);
    expect(parsed).toBeGreaterThanOrEqual(before);
    expect(parsed).toBeLessThanOrEqual(after);
  });

  it("defaults app_version + dump_format_version from version.ts constants when omitted", () => {
    const out = buildBackupMetadata({
      schemaVersion: "x",
      expectedSchemaVersion: "x",
    });
    // The defaults are pulled from version.ts at module load. We just assert
    // they are non-empty strings / integers — pinning the exact values here
    // would make this test brittle to every version bump.
    expect(typeof out.app_version).toBe("string");
    expect(out.app_version.length).toBeGreaterThan(0);
    expect(Number.isInteger(out.sastbot_dump_format_version)).toBe(true);
  });
});
