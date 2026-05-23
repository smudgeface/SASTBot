/**
 * Unit tests for the DB restore route helpers.
 *
 * Tests:
 * 1. Disk-space pre-flight math (10% safety margin).
 * 2. Schema-version comparison (lexicographic; migration names are YYYYMMDDHHMMSS_-prefixed).
 * 3. Format detection magic-byte logic.
 *
 * pgEnvFromUrl is now exported from adminBackup.ts (shared with adminRestore.ts)
 * and tested in adminBackup.test.ts — not duplicated here.
 */

import { describe, expect, it } from "vitest";
import { z } from "zod";

// ---------------------------------------------------------------------------
// Disk-space pre-flight math
// ---------------------------------------------------------------------------

function requiredBytes(uploadBytes: number): number {
  return Math.ceil(uploadBytes * 1.1);
}

describe("disk space pre-flight", () => {
  it("adds a 10% safety margin to the upload size", () => {
    expect(requiredBytes(1_000_000_000)).toBe(1_100_000_000);
    expect(requiredBytes(100)).toBe(Math.ceil(100 * 1.1));
  });

  it("rounds up fractional bytes", () => {
    expect(requiredBytes(3)).toBe(4);
    expect(requiredBytes(10)).toBe(11);
  });

  it("rejects when available < required", () => {
    const available = 500_000_000;
    const upload = 600_000_000;
    const required = requiredBytes(upload);
    expect(available < required).toBe(true);
  });

  it("accepts when available >= required", () => {
    const available = 2_000_000_000;
    const upload = 1_000_000_000;
    const required = requiredBytes(upload);
    expect(available < required).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Schema-version comparison logic
// ---------------------------------------------------------------------------
//
// Migration names start with YYYYMMDDHHMMSS_, so lexicographic comparison
// is equivalent to chronological comparison — verified here.

type SchemaCompareResult = "equal" | "dump_older" | "dump_newer";

function compareSchemaVersions(dumpSchema: string, expectedSchema: string): SchemaCompareResult {
  if (dumpSchema === expectedSchema) return "equal";
  if (dumpSchema < expectedSchema) return "dump_older";
  return "dump_newer";
}

describe("schema-version comparison", () => {
  const v1 = "20260101120000_initial_setup";
  const v2 = "20260515123000_backfill_evidence_paths";
  const v3 = "20260516165953_add_per_repo_llm_token_budgets";

  it("equal when both are the same migration", () => {
    expect(compareSchemaVersions(v3, v3)).toBe("equal");
  });

  it("dump_older when dump has earlier migration than expected", () => {
    expect(compareSchemaVersions(v1, v3)).toBe("dump_older");
    expect(compareSchemaVersions(v2, v3)).toBe("dump_older");
  });

  it("dump_newer when dump has later migration than expected", () => {
    expect(compareSchemaVersions(v3, v1)).toBe("dump_newer");
    expect(compareSchemaVersions(v3, v2)).toBe("dump_newer");
  });

  it("lexicographic order matches chronological order for standard migration names", () => {
    const migrations = [v2, v3, v1];
    const sorted = [...migrations].sort();
    expect(sorted).toEqual([v1, v2, v3]);
  });
});

// ---------------------------------------------------------------------------
// Format detection magic bytes
// ---------------------------------------------------------------------------

type FileFormat = "tarball" | "pgdump" | "unknown";

function detectFormatFromBytes(bytes: Buffer): FileFormat {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    return "tarball";
  }
  if (bytes.length >= 5 && bytes.toString("ascii", 0, 5) === "PGDMP") {
    return "pgdump";
  }
  return "unknown";
}

describe("format detection", () => {
  it("detects gzip magic bytes as tarball", () => {
    const buf = Buffer.from([0x1f, 0x8b, 0x08, 0x00]);
    expect(detectFormatFromBytes(buf)).toBe("tarball");
  });

  it("detects PGDMP magic as pgdump", () => {
    const buf = Buffer.from("PGDMP\x00\x00\x00\x00", "binary");
    expect(detectFormatFromBytes(buf)).toBe("pgdump");
  });

  it("returns unknown for unrecognized magic", () => {
    expect(detectFormatFromBytes(Buffer.from("hello"))).toBe("unknown");
    expect(detectFormatFromBytes(Buffer.from([0x00, 0x01, 0x02]))).toBe("unknown");
  });

  it("returns unknown for very short buffers", () => {
    expect(detectFormatFromBytes(Buffer.from([0x1f]))).toBe("unknown");
    expect(detectFormatFromBytes(Buffer.alloc(0))).toBe("unknown");
  });

  it("PGDMP detection requires at least 5 bytes", () => {
    const buf = Buffer.from("PGDM"); // only 4 bytes
    expect(detectFormatFromBytes(buf)).toBe("unknown");
  });
});

// ---------------------------------------------------------------------------
// A6: MetadataSchema backwards-compatibility — optional artifact fields
// ---------------------------------------------------------------------------

// Mirrors the MetadataSchema defined in adminRestore.ts.
// Optional fields must parse cleanly from old-format tarballs that omit them.
const MetadataSchema = z.object({
  app_version: z.string(),
  schema_version: z.string(),
  expected_schema_version: z.string(),
  exported_at: z.string(),
  sastbot_dump_format_version: z.number().int(),
  artifact_count: z.number().int().optional(),
  artifact_bytes_total: z.number().int().optional(),
});

describe("A6: MetadataSchema artifact fields", () => {
  const base = {
    app_version: "0.5.1",
    schema_version: "20260516165953_add_per_repo_llm_token_budgets",
    expected_schema_version: "20260516165953_add_per_repo_llm_token_budgets",
    exported_at: "2026-05-20T14:30:00.000Z",
    sastbot_dump_format_version: 1,
  };

  it("parses old-format metadata without artifact fields (backwards-compat)", () => {
    const result = MetadataSchema.safeParse(base);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.artifact_count).toBeUndefined();
      expect(result.data.artifact_bytes_total).toBeUndefined();
    }
  });

  it("parses new-format metadata with artifact fields", () => {
    const result = MetadataSchema.safeParse({
      ...base,
      artifact_count: 7,
      artifact_bytes_total: 102400,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.artifact_count).toBe(7);
      expect(result.data.artifact_bytes_total).toBe(102400);
    }
  });

  it("rejects non-integer artifact_count", () => {
    const result = MetadataSchema.safeParse({
      ...base,
      artifact_count: 3.5,
    });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// A6: allowlist covers 'artifacts' directory entry
// ---------------------------------------------------------------------------

describe("A6: tarball allowlist includes artifacts", () => {
  const allowed = new Set(["dump.pgcustom", "metadata.json", "artifacts"]);

  it("allows the artifacts entry", () => {
    expect(allowed.has("artifacts")).toBe(true);
  });

  it("still allows dump.pgcustom and metadata.json", () => {
    expect(allowed.has("dump.pgcustom")).toBe(true);
    expect(allowed.has("metadata.json")).toBe(true);
  });

  it("rejects unexpected entries", () => {
    const entries = ["dump.pgcustom", "metadata.json", "artifacts", "evil.sh"];
    const unexpected = entries.filter((e) => !allowed.has(e));
    expect(unexpected).toEqual(["evil.sh"]);
  });

  it("no unexpected entries for a well-formed new tarball", () => {
    const entries = ["dump.pgcustom", "metadata.json", "artifacts"];
    const unexpected = entries.filter((e) => !allowed.has(e));
    expect(unexpected).toHaveLength(0);
  });

  it("no unexpected entries for a well-formed old tarball (no artifacts/)", () => {
    const entries = ["dump.pgcustom", "metadata.json"];
    const unexpected = entries.filter((e) => !allowed.has(e));
    expect(unexpected).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// sastbot_dump_format_version gate: refuse strictly-newer tarball format
// ---------------------------------------------------------------------------

function shouldRefuseDumpFormat(dumpFormat: number, runningFormat: number): boolean {
  return dumpFormat > runningFormat;
}

describe("dump format version gate", () => {
  it("refuses when dump format is strictly newer than running", () => {
    expect(shouldRefuseDumpFormat(3, 2)).toBe(true);
    expect(shouldRefuseDumpFormat(99, 2)).toBe(true);
  });

  it("accepts equal dump format", () => {
    expect(shouldRefuseDumpFormat(2, 2)).toBe(false);
  });

  it("accepts older dump format (backwards-compat)", () => {
    expect(shouldRefuseDumpFormat(1, 2)).toBe(false);
  });
});
