/**
 * Unit tests for the B4 sarif_emit dual-write.
 *
 * Strategy:
 *  - We test the underlying `buildSarifFromIssues` + `writeArtifact` pipeline
 *    directly (since `regenerateSastSarifForScan` is private to worker.ts).
 *  - Test 1: normal path — build sarif from issues, write to disk, assert file
 *    exists and contains a valid SARIF v2.1.0 document.
 *  - Test 2: locked directory path — simulate a disk write failure, assert it
 *    throws (which worker.ts catches and converts to a sarif_emit_failed warning).
 *
 * The column write was removed in Deploy 3 (B5+B6) — SARIF is now stored only
 * on disk. The key invariant tested is:
 * "the SARIF file ends up on disk with valid content when a write is possible."
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

let tmpDir: string;
let originalArtifactDir: string | undefined;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-sarif-emit-"));
  originalArtifactDir = process.env["ARTIFACT_DIR"];
  process.env["ARTIFACT_DIR"] = tmpDir;
});

afterEach(async () => {
  if (originalArtifactDir === undefined) {
    delete process.env["ARTIFACT_DIR"];
  } else {
    process.env["ARTIFACT_DIR"] = originalArtifactDir;
  }
  await fs.rm(tmpDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

const SCAN_RUN_ID = "cccccccc-sarif-0000-0000-000000000001";
const SCOPE_ID = "dddddddd-sarif-0000-0000-000000000002";
const BASE_DATE = new Date("2026-05-22T10:00:00Z");

/** Build a minimal SastIssue fixture. */
function makeSastIssue(overrides: Record<string, unknown> = {}) {
  return {
    id: `sast-${randomBytes(4).toString("hex")}`,
    scopeId: SCOPE_ID,
    orgId: null,
    createdAt: BASE_DATE,
    updatedAt: BASE_DATE,
    firstSeenScanRunId: SCAN_RUN_ID,
    lastSeenScanRunId: SCAN_RUN_ID,
    lastSeenAt: BASE_DATE,
    latestRuleId: "CWE-89",
    latestRuleName: "SQL Injection",
    latestRuleMessage: "Untrusted input flows into a SQL query.",
    latestSeverity: "high",
    latestFilePath: "src/db.ts",
    latestStartLine: 42,
    latestEndLine: 44,
    latestSnippet: "const q = `SELECT * FROM users WHERE id = ${id}`;",
    latestCwe: "CWE-89",
    latestCvss: null,
    latestConfidence: "high",
    latestLlmSummary: null,
    latestReachability: null,
    status: "pending",
    dismissedReason: null,
    dismissedAt: null,
    resolvedAt: null,
    jiraIssueKey: null,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("B4 sarif_emit — disk artifact write", () => {
  it("writes a valid SARIF v2.1.0 file when given sast issues", async () => {
    const { buildSarifFromIssues } = await import("../src/services/sarifService.js");
    const { writeArtifact, sarifPathFor } = await import("../src/services/artifactStore.js");

    const issues = [makeSastIssue(), makeSastIssue({ latestRuleId: "CWE-79", latestSeverity: "medium" })];

    const sarif = buildSarifFromIssues(issues as unknown as Parameters<typeof buildSarifFromIssues>[0], {
      toolVersion: "0.7.0",
      modelName: "claude-code-cli",
      scopePath: "/",
      startedAt: BASE_DATE,
      endedAt: new Date(BASE_DATE.getTime() + 60_000),
    });

    const filePath = sarifPathFor(SCAN_RUN_ID);
    const body = JSON.stringify(sarif, null, 2);
    await writeArtifact(filePath, body);

    // File must exist.
    const exists = await fs.access(filePath).then(() => true).catch(() => false);
    expect(exists).toBe(true);

    // Content must parse as SARIF v2.1.0.
    const raw = await fs.readFile(filePath, "utf8");
    const doc = JSON.parse(raw) as { version: string; runs: Array<{ results: unknown[] }> };

    expect(doc.version).toBe("2.1.0");
    expect(Array.isArray(doc.runs)).toBe(true);
    expect(doc.runs[0].results).toHaveLength(2);
  });

  it("writeArtifact propagates write errors — a thrown error from fs.writeFile reaches the caller", async () => {
    // Point ARTIFACT_DIR at a file (not a directory) so mkdir of its subdir
    // will fail. This simulates the real error path that worker.ts catches and
    // converts to a sarif_emit_failed warning.
    //
    // Strategy: write a regular file at a path that writeArtifact will try to
    // treat as a directory, so mkdir of its children returns ENOTDIR.
    const blockingFile = path.join(tmpDir, "notadir");
    await fs.writeFile(blockingFile, "block");

    // ARTIFACT_DIR -> tmpDir, sarif subdir will be ${tmpDir}/sarif.
    // Make ${tmpDir}/sarif exist as a file so mkdir of ${tmpDir}/sarif/... fails.
    await fs.writeFile(path.join(tmpDir, "sarif"), "block");

    const { writeArtifact, sarifPathFor } = await import("../src/services/artifactStore.js");

    // sarifPathFor produces ${ARTIFACT_DIR}/sarif/${SCAN_RUN_ID}.sarif.json
    // writeArtifact will try to mkdir ${ARTIFACT_DIR}/sarif/ — but it's a
    // file now, so it throws ENOTDIR.
    await expect(
      writeArtifact(sarifPathFor(SCAN_RUN_ID), '{"version":"2.1.0","runs":[]}'),
    ).rejects.toThrow();
  });

  it("produces a SARIF document with no results for an empty issues list", async () => {
    const { buildSarifFromIssues } = await import("../src/services/sarifService.js");
    const { writeArtifact, sarifPathFor } = await import("../src/services/artifactStore.js");

    const sarif = buildSarifFromIssues([], {
      toolVersion: "0.7.0",
      modelName: "claude-code-cli",
      scopePath: "/",
      startedAt: null,
      endedAt: null,
    });

    const filePath = sarifPathFor(SCAN_RUN_ID);
    await writeArtifact(filePath, JSON.stringify(sarif, null, 2));

    const raw = await fs.readFile(filePath, "utf8");
    const doc = JSON.parse(raw) as { version: string; runs: Array<{ results: unknown[] }> };

    expect(doc.version).toBe("2.1.0");
    expect(doc.runs[0].results).toHaveLength(0);
  });
});
