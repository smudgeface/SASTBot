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
import { ReachabilityRecord, SastAbsenceRecord, SastRecord } from "../src/services/llmSastService.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const SAST_FIXTURES_PATH = join(__dirname, "fixtures/sast-rejected-2026-05-22.jsonl");
const SBOM_FIXTURES_PATH = join(__dirname, "fixtures/sbom-rejected-2026-05-22.jsonl");
const REACHABILITY_FIXTURES_PATH = join(__dirname, "fixtures/reachability-rejected-2026-05-23.jsonl");

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

  // Regression: 2026-05-25 GoPxL BE scan emitted 24/82 records with the
  // OWASP/CWE community field name `cwe_id` instead of the prompt-canonical
  // `cwe`. The records were otherwise complete and well-formed (real
  // CWE-321/CWE-798 hardcoded-credential findings on a production firmware
  // codebase), but the schema rejected every one — a 29% drop with no
  // surfaced parse-error sample shape that was clearly malformed.
  it("normalizes cwe_id → cwe after parse (2026-05-25 GoPxL BE drift)", () => {
    const result = SastRecord.safeParse({
      kind: "sast",
      cwe_id: "CWE-321",
      severity: "high",
      file_path: "src/secrets.cpp",
      start_line: 19,
      end_line: 23,
      title: "Hardcoded symmetric cipher key",
      description: "Static AES key baked into firmware.",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.cwe).toBe("CWE-321");
    }
  });

  it("rejects a sast record with neither cwe nor cwe_id", () => {
    const result = SastRecord.safeParse({
      kind: "sast",
      severity: "high",
      file_path: "src/foo.cpp",
      start_line: 1,
      end_line: 1,
      summary: "test",
    });
    expect(result.success).toBe(false);
  });

  it("canonical cwe wins over cwe_id when both are present", () => {
    const result = SastRecord.safeParse({
      kind: "sast",
      cwe: "CWE-79",
      cwe_id: "CWE-WRONG",
      severity: "high",
      file_path: "src/foo.cpp",
      start_line: 1,
      end_line: 1,
      summary: "test",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.cwe).toBe("CWE-79");
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

// ---------------------------------------------------------------------------
// SAST absence — canonical file_path/start_line alongside legacy aliases
// ---------------------------------------------------------------------------

describe("LLM SAST absence record schema — canonical + legacy field-name aliases", () => {
  it("accepts the canonical file_path + start_line form (new prompt style)", () => {
    const result = SastAbsenceRecord.safeParse({
      kind: "sast_absence",
      cwe: "CWE-352",
      severity: "high",
      summary: "No CSRF protection",
      file_path: "src/server.cpp",
      start_line: 193,
      confidence: 0.9,
      reasoning: "grep returned no matches",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      // Transform normalizes to the internal evidence_* names so existing
      // worker/SARIF/ingest code keeps working.
      expect(result.data.evidence_file).toBe("src/server.cpp");
      expect(result.data.evidence_line).toBe(193);
    }
  });

  it("accepts the legacy evidence_file + evidence_line form (back-compat)", () => {
    const result = SastAbsenceRecord.safeParse({
      kind: "sast_absence",
      cwe: "CWE-319",
      severity: "high",
      title: "No TLS anywhere",
      evidence_file: "src/net.cpp",
      evidence_line: 12,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.evidence_file).toBe("src/net.cpp");
      expect(result.data.evidence_line).toBe(12);
      expect(result.data.summary).toBe("No TLS anywhere");
    }
  });

  it("normalizes cwe_id → cwe after parse (2026-05-25 GoPxL BE drift)", () => {
    const result = SastAbsenceRecord.safeParse({
      kind: "sast_absence",
      cwe_id: "CWE-352",
      severity: "high",
      summary: "No CSRF protection",
      file_path: "src/server.cpp",
      start_line: 193,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.cwe).toBe("CWE-352");
    }
  });

  it("canonical file_path takes precedence over legacy evidence_file when both present", () => {
    // Defensive: if a producer sends both names (e.g. transitional output
    // during a prompt-version mixup), the legacy field wins — see transform
    // order. This matches the SastRecord behaviour where file_path is the
    // canonical sink.
    const result = SastAbsenceRecord.safeParse({
      kind: "sast_absence",
      cwe: "CWE-352",
      severity: "high",
      summary: "test",
      evidence_file: "legacy.cpp",
      file_path: "canonical.cpp",
      evidence_line: 99,
      start_line: 42,
    });
    expect(result.success).toBe(true);
    if (result.success) {
      // Legacy evidence_file is what the worker reads — preferred when present
      // so back-compat is guaranteed.
      expect(result.data.evidence_file).toBe("legacy.cpp");
      expect(result.data.evidence_line).toBe(99);
    }
  });
});

// ---------------------------------------------------------------------------
// Reachability call_sites — string shorthand drift (2026-05-23 FSS scan)
// ---------------------------------------------------------------------------

describe("LLM reachability record schema — call_sites string shorthand", () => {
  it("parses real rejected records from the 2026-05-23 FSS scan (call_sites as string[])", () => {
    const lines = readFileSync(REACHABILITY_FIXTURES_PATH, "utf8").trim().split("\n");
    expect(lines.length).toBeGreaterThan(0);

    for (const line of lines) {
      const raw = JSON.parse(line);
      const result = ReachabilityRecord.safeParse(raw);
      expect(
        result.success,
        `Failed to parse: ${line.slice(0, 200)} — error: ${
          result.success ? "" : JSON.stringify((result as { error: { format(): unknown } }).error.format())
        }`,
      ).toBe(true);

      if (result.success) {
        // After transform every call_site is an object with file_path + line.
        for (const cs of result.data.call_sites) {
          expect(typeof cs.file_path).toBe("string");
          expect(cs.file_path.length).toBeGreaterThan(0);
          expect(typeof cs.line).toBe("number");
          expect(cs.line).toBeGreaterThanOrEqual(0);
        }
      }
    }
  });

  it("transforms `\"path:42\"` into `{file_path: \"path\", line: 42}`", () => {
    const result = ReachabilityRecord.safeParse({
      kind: "reachability",
      sca_issue_id: "abc-123",
      reachable: true,
      call_sites: ["src/foo.cpp:42", "src/bar.cpp:7"],
      reasoning: "two call sites",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.call_sites).toEqual([
        { file_path: "src/foo.cpp", line: 42 },
        { file_path: "src/bar.cpp", line: 7 },
      ]);
    }
  });

  it("handles a string call_site with no line as line=0", () => {
    const result = ReachabilityRecord.safeParse({
      kind: "reachability",
      sca_issue_id: "abc-123",
      reachable: false,
      call_sites: ["src/foo.cpp"],
      reasoning: "no specific line",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.call_sites).toEqual([{ file_path: "src/foo.cpp", line: 0 }]);
    }
  });

  it("accepts a MIX of object and string forms in the same call_sites array", () => {
    // The schema must tolerate a half-drift case where the LLM emits some
    // call_sites canonically and others as shorthand. (Unlikely but cheap to
    // guarantee.)
    const result = ReachabilityRecord.safeParse({
      kind: "reachability",
      sca_issue_id: "abc-123",
      reachable: true,
      call_sites: [
        { file_path: "src/a.cpp", line: 10 },
        "src/b.cpp:20",
      ],
      reasoning: "mixed shapes",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.call_sites).toEqual([
        { file_path: "src/a.cpp", line: 10 },
        { file_path: "src/b.cpp", line: 20 },
      ]);
    }
  });

  it("still accepts the canonical {file_path, line} object form", () => {
    const result = ReachabilityRecord.safeParse({
      kind: "reachability",
      sca_issue_id: "abc-123",
      reachable: true,
      call_sites: [{ file_path: "src/foo.cpp", line: 42, snippet: "..." }],
      reasoning: "canonical",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.call_sites[0]?.file_path).toBe("src/foo.cpp");
      expect(result.data.call_sites[0]?.line).toBe(42);
    }
  });

  it("handles drive-letter paths correctly (last `:N` wins)", () => {
    const result = ReachabilityRecord.safeParse({
      kind: "reachability",
      sca_issue_id: "abc",
      reachable: true,
      call_sites: ["C:/Users/foo/file.cpp:120"],
      reasoning: "drive letter",
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.call_sites[0]?.file_path).toBe("C:/Users/foo/file.cpp");
      expect(result.data.call_sites[0]?.line).toBe(120);
    }
  });
});
