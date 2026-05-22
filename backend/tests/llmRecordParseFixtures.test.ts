/**
 * Fixture-based regression tests for the LLM detection-record schemas.
 *
 * Fixtures captured from the live FSS scan (37d42b21-e54b-44d5-bdd0-d4ad78c78d18)
 * on 2026-05-22. These are records the LLM emitted that the OLD schema
 * rejected because it required canonical field names (file_path / summary /
 * confidence / reasoning) and the LLM drifted to aliases (file / title /
 * description, with confidence + reasoning omitted).
 *
 * After the schema fix every line in both fixture files MUST parse successfully.
 * This test is the regression guard — if you accidentally re-introduce a required
 * field that the LLM routinely omits, these tests will catch it immediately.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { AddRecord } from "../src/services/llmSbomService.js";
import { SastRecord } from "../src/services/llmSastService.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const SAST_FIXTURES_PATH = join(__dirname, "fixtures/sast-rejected-2026-05-22.jsonl");
const SBOM_FIXTURES_PATH = join(__dirname, "fixtures/sbom-rejected-2026-05-22.jsonl");

// ---------------------------------------------------------------------------
// SAST
// ---------------------------------------------------------------------------

describe("LLM SAST detection record schema — defensive aliases", () => {
  it("parses real rejected records that use `file`/`title`/`description` instead of canonical names", () => {
    const lines = readFileSync(SAST_FIXTURES_PATH, "utf8").trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);

    for (const line of lines) {
      const raw = JSON.parse(line);
      const result = SastRecord.safeParse(raw);
      expect(
        result.success,
        `Failed to parse: ${line.slice(0, 200)} — error: ${
          result.success ? "" : JSON.stringify((result as { error: { format(): unknown } }).error.format())
        }`,
      ).toBe(true);

      if (result.success) {
        // After parse+transform, canonical names must be populated.
        expect(typeof result.data.file_path).toBe("string");
        expect(result.data.file_path.length).toBeGreaterThan(0);
        expect(typeof result.data.summary).toBe("string");
        expect(result.data.summary.length).toBeGreaterThan(0);
        expect(typeof result.data.confidence).toBe("number");
        expect(typeof result.data.reasoning).toBe("string");
      }
    }
  });

  it("rejects a sast record with neither file_path nor file", () => {
    const result = SastRecord.safeParse({
      kind: "sast",
      cwe: "CWE-22",
      severity: "critical",
      // No file_path and no file — must fail the refine
      start_line: 10,
      end_line: 12,
      title: "something",
    });
    expect(result.success).toBe(false);
  });

  it("rejects a sast record with neither summary nor title", () => {
    const result = SastRecord.safeParse({
      kind: "sast",
      cwe: "CWE-22",
      severity: "critical",
      file_path: "src/foo.cpp",
      start_line: 10,
      end_line: 12,
      // No summary and no title — must fail the refine
    });
    expect(result.success).toBe(false);
  });

  it("normalizes file → file_path and title → summary after parse", () => {
    const result = SastRecord.safeParse({
      kind: "sast",
      cwe: "CWE-79",
      severity: "high",
      file: "src/foo.cpp",
      start_line: 5,
      end_line: 7,
      title: "XSS in response body",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.file_path).toBe("src/foo.cpp");
      expect(result.data.summary).toBe("XSS in response body");
      expect(result.data.confidence).toBe(0.5);  // default
      expect(result.data.reasoning).toBe("");     // default
    }
  });
});

// ---------------------------------------------------------------------------
// SBOM
// ---------------------------------------------------------------------------

describe("LLM SBOM augmentation record schema — defensive aliases", () => {
  it("parses real rejected `add` records that use the new `evidence` shape without legacy `evidence_path`", () => {
    const lines = readFileSync(SBOM_FIXTURES_PATH, "utf8").trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);

    for (const line of lines) {
      const raw = JSON.parse(line);
      const result = AddRecord.safeParse(raw);
      expect(
        result.success,
        `Failed to parse: ${line.slice(0, 200)} — error: ${
          result.success ? "" : JSON.stringify((result as { error: { format(): unknown } }).error.format())
        }`,
      ).toBe(true);
    }
  });

  it("accepts an add record with legacy evidence_path only", () => {
    const result = AddRecord.safeParse({
      type: "add",
      name: "oldlib",
      version: "1.0",
      ecosystem: "generic",
      component_root: "extern/oldlib",
      evidence_path: "extern/oldlib/oldlib.h",
      llm_reason: "legacy format",
    });
    expect(result.success).toBe(true);
  });

  it("accepts an add record with evidence_paths only", () => {
    const result = AddRecord.safeParse({
      type: "add",
      name: "midlib",
      version: "2.0",
      ecosystem: "generic",
      component_root: "extern/midlib",
      evidence_paths: ["extern/midlib/include/midlib.h"],
      llm_reason: "legacy paths format",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an add record with no evidence at all", () => {
    const result = AddRecord.safeParse({
      type: "add",
      name: "foo",
      version: "1.0",
      ecosystem: "generic",
      component_root: "extern/foo",
      llm_reason: "test — no evidence",
    });
    expect(result.success).toBe(false);
  });
});
