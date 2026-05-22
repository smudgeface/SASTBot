/**
 * sastFileFirst.test.ts — M9 Stream E2 round-trip and idempotency tests.
 *
 * Tests the file-first SAST pipeline:
 *   buildSastSarifFromDetection (in-memory records → SARIF v2.1.0 doc)
 *   → JSON.stringify → writeArtifact (doc → file)
 *   → ingestSastFromArtifact (file → sast_issues rows)
 *
 * Strategy:
 *  - Mock prisma so the function never touches a real DB.
 *  - Override ARTIFACT_DIR to a tmp directory per test.
 *  - Assert that:
 *      1. Round-trip: SAST records survive buildSastSarifFromDetection → ingestSastFromArtifact.
 *      2. Absence records round-trip with __absence__:CWE snippet + correct evidence fields.
 *      3. Idempotency: calling ingest twice produces the same row set.
 *      4. lastSeenScanRunId is set on every ingested issue.
 *      5. No SARIF re-emit code path exists (structural: ingestSastFromArtifact only reads).
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Set required env vars before side-effectful modules load.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// DB mock — upsertSastIssueFromDetection and updateMany must be registered
// before any imports that depend on db.js / issueService.js.
// ---------------------------------------------------------------------------

const mockUpsertSastIssue = vi.fn();
const mockUpdateMany = vi.fn().mockResolvedValue({ count: 0 });
const mockSastIssueFindUnique = vi.fn();

// Track inserted vs updated across calls.
let _existingFingerprints: Set<string>;

// Helper to reset tracked state.
function resetDbState(existingFingerprints: Set<string> = new Set()) {
  _existingFingerprints = existingFingerprints;
  // findUnique: returns { id } if fingerprint already exists, null if new.
  mockSastIssueFindUnique.mockImplementation(
    ({ where }: { where: { uq_sast_issues_scope_fingerprint: { fingerprint: string } } }) => {
      const fp = where.uq_sast_issues_scope_fingerprint?.fingerprint;
      return Promise.resolve(fp && _existingFingerprints.has(fp) ? { id: "existing-id" } : null);
    },
  );
  // upsert: returns a minimal SastIssue shape. Records the fingerprint as seen.
  mockUpsertSastIssue.mockImplementation(
    ({ where, create }: { where: { uq_sast_issues_scope_fingerprint: { fingerprint: string } }; create: Record<string, unknown> }) => {
      const fp = where.uq_sast_issues_scope_fingerprint?.fingerprint ?? (create["fingerprint"] as string);
      if (fp) _existingFingerprints.add(fp);
      return Promise.resolve({
        id: "issue-" + (fp?.slice(0, 8) ?? "unknown"),
        fingerprint: fp,
        scopeId: SCOPE_ID,
        orgId: null,
        triageStatus: "pending",
        triageConfidence: null,
        latestRuleId: create["latestRuleId"] as string,
        latestRuleName: null,
        latestRuleMessage: create["latestRuleMessage"] as string,
        latestSeverity: create["latestSeverity"] as string,
        latestCweIds: create["latestCweIds"] as string[],
        latestFilePath: create["latestFilePath"] as string,
        latestStartLine: create["latestStartLine"] as number,
        latestEndLine: null,
        latestSnippet: create["latestSnippet"] as string | null,
        latestLlmSummary: null,
        notes: null,
        firstSeenScanRunId: fp,
        lastSeenScanRunId: fp,
        lastSeenAt: new Date(),
        createdAt: new Date(),
        updatedAt: new Date(),
        jiraIssueKey: null,
      });
    },
  );
}

vi.mock("../src/db.js", () => ({
  prisma: {
    sastIssue: {
      findUnique: (...args: unknown[]) => mockSastIssueFindUnique(...args),
      upsert: (...args: unknown[]) => mockUpsertSastIssue(...args),
      updateMany: (...args: unknown[]) => mockUpdateMany(...args),
    },
  },
}));

// ---------------------------------------------------------------------------
// Import modules under test — AFTER mocks are registered
// ---------------------------------------------------------------------------

const { buildSastSarifFromDetection } = await import("../src/services/sarifService.js");
const { writeArtifact, sarifPathFor } = await import("../src/services/artifactStore.js");
const { ingestSastFromArtifact } = await import("../src/services/sastIngest.js");

// ---------------------------------------------------------------------------
// Tmp-dir setup / teardown
// ---------------------------------------------------------------------------

let tmpDir: string;
let originalArtifactDir: string | undefined;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-e2-"));
  originalArtifactDir = process.env["ARTIFACT_DIR"];
  process.env["ARTIFACT_DIR"] = tmpDir;
  resetDbState();
  mockUpdateMany.mockClear();
  mockUpsertSastIssue.mockClear();
  mockSastIssueFindUnique.mockClear();
});

afterEach(async () => {
  if (originalArtifactDir === undefined) {
    delete process.env["ARTIFACT_DIR"];
  } else {
    process.env["ARTIFACT_DIR"] = originalArtifactDir;
  }
  await fs.rm(tmpDir, { recursive: true, force: true });
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// Fixture factories
// ---------------------------------------------------------------------------

const SCAN_RUN_ID = "aaaaaaaa-sast-0000-0000-000000000001";
const SCOPE_ID = "bbbbbbbb-sast-0000-0000-000000000002";

/** A representative SAST record. */
function makeSastRecord(overrides: Record<string, unknown> = {}) {
  return {
    cwe: "CWE-798",
    severity: "high" as const,
    file_path: "src/auth/login.c",
    start_line: 42,
    end_line: 44,
    summary: "Hardcoded credentials in authentication module",
    snippet: "// context line 1\n// context line 2\n// context line 3\nstatic char *password = \"secret\";\ncheck_login(user, password);\n// post-context 1\n// post-context 2",
    confidence: 0.85,
    reasoning: "Literal string assigned to credential variable",
    ...overrides,
  };
}

/** A representative absence record. */
function makeAbsenceRecord(overrides: Record<string, unknown> = {}) {
  return {
    cwe: "CWE-89",
    severity: "critical" as const,
    evidence_file: "src/db/query.c",
    evidence_line: 10,
    summary: "No parameterized query usage found — SQL injection risk",
    confidence: 0.7,
    reasoning: "No prepared statement patterns observed",
    ...overrides,
  };
}

/** Build a SARIF doc from records. */
function buildDoc(
  scanRunId: string,
  records: Array<ReturnType<typeof makeSastRecord>>,
  absences: Array<ReturnType<typeof makeAbsenceRecord>>,
) {
  return buildSastSarifFromDetection({
    detection: { records, absences },
    scanRunId,
    scopeId: SCOPE_ID,
    scopePath: "/",
    toolVersion: "0.9.1",
    modelName: "claude-code-cli",
    startedAt: new Date("2026-05-22T10:00:00Z"),
    endedAt: null,
  });
}

/** Write SARIF doc to disk and return it. */
async function writeAndIngest(
  scanRunId: string,
  records: Array<ReturnType<typeof makeSastRecord>>,
  absences: Array<ReturnType<typeof makeAbsenceRecord>> = [],
) {
  const doc = buildDoc(scanRunId, records, absences);
  await writeArtifact(sarifPathFor(scanRunId), JSON.stringify(doc, null, 2));
  return ingestSastFromArtifact({
    scanRunId,
    scopeId: SCOPE_ID,
    orgId: null,
    scopeDir: tmpDir,     // file paths won't resolve but fingerprint fallback handles it
    scopePath: "/",
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("buildSastSarifFromDetection produces a valid SARIF v2.1.0 document", () => {
  it("emits correct top-level SARIF shape", () => {
    const doc = buildDoc(SCAN_RUN_ID, [makeSastRecord()], []) as Record<string, unknown>;

    expect(doc["version"]).toBe("2.1.0");
    expect(doc["$schema"]).toContain("sarif-schema-2.1.0");
    const runs = doc["runs"] as unknown[];
    expect(runs).toHaveLength(1);
  });

  it("SAST record emits a result with physicalLocation and ruleId", () => {
    const doc = buildDoc(SCAN_RUN_ID, [makeSastRecord()], []) as Record<string, unknown>;
    const run = (doc["runs"] as Record<string, unknown>[])[0]!;
    const results = run["results"] as Record<string, unknown>[];

    expect(results).toHaveLength(1);
    const result = results[0]!;
    expect(result["ruleId"]).toBe("llm:CWE-798");
    expect(result["kind"]).toBe("fail");

    const loc = (result["locations"] as Record<string, unknown>[])[0]!;
    const phys = loc["physicalLocation"] as Record<string, unknown>;
    const region = phys["region"] as Record<string, unknown>;
    expect(region["startLine"]).toBe(42);
    expect(region["endLine"]).toBe(44);
  });

  it("SAST result has required sastbot:* properties", () => {
    const doc = buildDoc(SCAN_RUN_ID, [makeSastRecord()], []) as Record<string, unknown>;
    const run = (doc["runs"] as Record<string, unknown>[])[0]!;
    const result = (run["results"] as Record<string, unknown>[])[0]!;
    const props = result["properties"] as Record<string, unknown>;

    expect(props["sastbot:file_path_scope_relative"]).toBe("src/auth/login.c");
    expect(props["sastbot:llm_summary"]).toBe("Hardcoded credentials in authentication module");
    expect(props["sastbot:triage_confidence"]).toBe("0.85");
    expect(props["severity"]).toBe("high");
  });

  it("absence record emits informational kind with no physicalLocation", () => {
    const doc = buildDoc(SCAN_RUN_ID, [], [makeAbsenceRecord()]) as Record<string, unknown>;
    const run = (doc["runs"] as Record<string, unknown>[])[0]!;
    const results = run["results"] as Record<string, unknown>[];

    expect(results).toHaveLength(1);
    const result = results[0]!;
    expect(result["ruleId"]).toBe("llm:CWE-89:absence");
    expect(result["kind"]).toBe("informational");
    expect(result["locations"]).toBeUndefined();

    const props = result["properties"] as Record<string, unknown>;
    expect(props["sastbot:absence_evidence_file"]).toBe("src/db/query.c");
    expect(props["sastbot:absence_evidence_line"]).toBe("10");
  });

  it("CWE is in the driver rules with relationships", () => {
    const doc = buildDoc(SCAN_RUN_ID, [makeSastRecord()], []) as Record<string, unknown>;
    const run = (doc["runs"] as Record<string, unknown>[])[0]!;
    const driver = (run["tool"] as Record<string, unknown>)["driver"] as Record<string, unknown>;
    const rules = driver["rules"] as Record<string, unknown>[];

    expect(rules).toHaveLength(1);
    const rule = rules[0]!;
    expect(rule["id"]).toBe("llm:CWE-798");
    const rels = rule["relationships"] as Record<string, unknown>[];
    expect(rels[0]).toMatchObject({ kinds: ["relevant"], target: { id: "798", toolComponent: { name: "CWE" } } });
  });

  it("properties are sorted lexicographically", () => {
    const doc = buildDoc(SCAN_RUN_ID, [makeSastRecord()], []) as Record<string, unknown>;
    const run = (doc["runs"] as Record<string, unknown>[])[0]!;
    const result = (run["results"] as Record<string, unknown>[])[0]!;
    const props = result["properties"] as Record<string, unknown>;
    const keys = Object.keys(props);
    expect(keys).toEqual([...keys].sort());
  });
});

describe("SAST round-trip: buildSastSarifFromDetection → write → ingestSastFromArtifact", () => {
  it("upserts one sast_issue per SAST record", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(scanRunId, [makeSastRecord()]);

    expect(mockUpsertSastIssue).toHaveBeenCalledOnce();
    const call = mockUpsertSastIssue.mock.calls[0][0] as {
      create: {
        ruleId: string;
        severity: string;
        cweIds: string[];
        startLine: number;
        endLine: number | null;
        snippet: string | null;
      };
    };
    // ruleId is on create.latestRuleId
    const createData = call.create as Record<string, unknown>;
    expect(createData["latestRuleId"]).toBe("llm:CWE-798");
    expect(createData["latestSeverity"]).toBe("high");
  });

  it("sets lastSeenScanRunId=scanRunId on the upserted issue", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(scanRunId, [makeSastRecord()]);

    const call = mockUpsertSastIssue.mock.calls[0][0] as Record<string, unknown>;
    const createData = call["create"] as Record<string, unknown>;
    const updateData = call["update"] as Record<string, unknown>;
    expect(createData["lastSeenScanRunId"]).toBe(scanRunId);
    expect(updateData["lastSeenScanRunId"]).toBe(scanRunId);
  });

  it("stamps latestLlmSummary and triageConfidence via updateMany", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(scanRunId, [makeSastRecord()]);

    expect(mockUpdateMany).toHaveBeenCalled();
    const updateCall = mockUpdateMany.mock.calls[0][0] as {
      data: { latestLlmSummary?: string; triageConfidence?: number };
    };
    expect(updateCall.data.latestLlmSummary).toBe("Hardcoded credentials in authentication module");
    expect(updateCall.data.triageConfidence).toBeCloseTo(0.85);
  });

  it("returns correct inserted/updated counts for new issues", async () => {
    const scanRunId = randomUUID();
    // Two records with distinct CWE and distinct snippets → distinct fingerprints → both new.
    const result = await writeAndIngest(scanRunId, [
      makeSastRecord({ cwe: "CWE-798", snippet: "unique snippet alpha for cwe 798" }),
      makeSastRecord({ cwe: "CWE-89", file_path: "src/other.c", snippet: "unique snippet beta for cwe 89" }),
    ]);
    expect(result.inserted).toBe(2);
    expect(result.updated).toBe(0);
  });
});

describe("Absence record round-trip", () => {
  it("upserts sast_issues with __absence__:CWE snippet", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(scanRunId, [], [makeAbsenceRecord()]);

    expect(mockUpsertSastIssue).toHaveBeenCalledOnce();
    const call = mockUpsertSastIssue.mock.calls[0][0] as {
      create: Record<string, unknown>;
    };
    expect(call.create["latestSnippet"]).toBe("__absence__:CWE-89");
    expect(call.create["latestRuleId"]).toBe("llm:CWE-89:absence");
  });

  it("absence record has correct filePath and startLine from properties", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(scanRunId, [], [makeAbsenceRecord()]);

    const call = mockUpsertSastIssue.mock.calls[0][0] as {
      create: Record<string, unknown>;
    };
    // filePath comes from the evidence_file property.
    expect(call.create["latestFilePath"]).toBe("src/db/query.c");
    expect(call.create["latestStartLine"]).toBe(10);
    expect(call.create["latestEndLine"]).toBeNull();
  });
});

describe("Idempotency", () => {
  it("second ingest on same file produces same row count (upserts, no duplicates)", async () => {
    const scanRunId = randomUUID();
    const doc = buildDoc(scanRunId, [makeSastRecord()], []);
    await writeArtifact(sarifPathFor(scanRunId), JSON.stringify(doc, null, 2));

    // First ingest — issue is new.
    const first = await ingestSastFromArtifact({ scanRunId, scopeId: SCOPE_ID, orgId: null, scopeDir: tmpDir, scopePath: "/" });
    const firstCallCount = mockUpsertSastIssue.mock.calls.length;

    mockUpsertSastIssue.mockClear();
    mockUpdateMany.mockClear();
    // Pre-populate fingerprint so second call treats it as existing.
    // (resetDbState is NOT called here — existing fingerprints are still in the set)

    // Second ingest — same file, same fingerprint.
    const second = await ingestSastFromArtifact({ scanRunId, scopeId: SCOPE_ID, orgId: null, scopeDir: tmpDir, scopePath: "/" });
    const secondCallCount = mockUpsertSastIssue.mock.calls.length;

    // Both calls upsert the same number of issues.
    expect(firstCallCount).toBe(secondCallCount);
    // Second ingest sees existing fingerprint.
    expect(first.inserted).toBe(1);
    expect(second.updated).toBe(1);
    expect(second.inserted).toBe(0);
  });

  it("mixed records: first ingest inserts, second ingest updates (no new rows)", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(scanRunId, [
      makeSastRecord({ cwe: "CWE-798", snippet: "idempotency snippet alpha" }),
      makeSastRecord({ cwe: "CWE-22", file_path: "src/fs.c", snippet: "idempotency snippet beta" }),
    ]);

    expect(mockUpsertSastIssue).toHaveBeenCalledTimes(2);
    mockUpsertSastIssue.mockClear();

    // Fingerprints are now in _existingFingerprints — second ingest → updated.
    const result2 = await ingestSastFromArtifact({ scanRunId, scopeId: SCOPE_ID, orgId: null, scopeDir: tmpDir, scopePath: "/" });
    expect(result2.inserted).toBe(0);
    expect(result2.updated).toBe(2);
  });
});

describe("ingestSastFromArtifact error handling", () => {
  it("throws when no SARIF artifact file exists", async () => {
    const nonExistentId = randomUUID();
    await expect(
      ingestSastFromArtifact({ scanRunId: nonExistentId, scopeId: SCOPE_ID, orgId: null, scopeDir: tmpDir, scopePath: "/" }),
    ).rejects.toThrow(`sast_ingest: no SARIF artifact found for scan ${nonExistentId}`);
  });

  it("throws when artifact is not valid JSON", async () => {
    const scanRunId = randomUUID();
    await writeArtifact(sarifPathFor(scanRunId), "not-valid-json{{{");
    await expect(
      ingestSastFromArtifact({ scanRunId, scopeId: SCOPE_ID, orgId: null, scopeDir: tmpDir, scopePath: "/" }),
    ).rejects.toThrow("sast_ingest: SARIF artifact for scan");
  });

  it("throws when SARIF has no runs", async () => {
    const scanRunId = randomUUID();
    await writeArtifact(sarifPathFor(scanRunId), JSON.stringify({ version: "2.1.0", runs: [] }));
    await expect(
      ingestSastFromArtifact({ scanRunId, scopeId: SCOPE_ID, orgId: null, scopeDir: tmpDir, scopePath: "/" }),
    ).rejects.toThrow("sast_ingest: SARIF artifact for scan");
  });
});

describe("lastSeenScanRunId invariant", () => {
  it("is set on every upserted issue during ingest", async () => {
    const scanRunId = randomUUID();
    await writeAndIngest(
      scanRunId,
      [
        makeSastRecord({ cwe: "CWE-798", snippet: "seen-at snippet alpha" }),
        makeSastRecord({ cwe: "CWE-22", file_path: "src/fs.c", snippet: "seen-at snippet beta" }),
      ],
    );

    for (const call of mockUpsertSastIssue.mock.calls) {
      const upsertArgs = call[0] as Record<string, unknown>;
      const createData = upsertArgs["create"] as Record<string, unknown>;
      const updateData = upsertArgs["update"] as Record<string, unknown>;
      expect(createData["lastSeenScanRunId"]).toBe(scanRunId);
      expect(updateData["lastSeenScanRunId"]).toBe(scanRunId);
    }
  });
});
