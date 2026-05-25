/**
 * Unit tests for applyRecheckVerdicts (llmSastService.ts).
 *
 * Coverage (M12 Step 3):
 *   1. untrustworthy: true + "fixed"       → missingVerdict++, fixed===0
 *   2. untrustworthy: true + "file_deleted" → missingVerdict++, fileDeleted===0
 *   3. untrustworthy: true + "still_present"→ still processed normally
 *   4. untrustworthy: false (default)       → existing behaviour unchanged
 *
 * Strategy: pass a minimal in-memory "Tx" mock (matching the PrismaClient
 * shape the function uses) instead of hitting a real DB. The mock records
 * every update call so assertions can verify whether the DB was mutated.
 */

import { randomBytes, randomUUID } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Mock readSourceSnippet — still_present branch calls fs I/O we don't need.
// ---------------------------------------------------------------------------

vi.mock("../src/services/sourceSnippet.js", () => ({
  readSourceSnippet: vi.fn().mockResolvedValue(null),
}));

// ---------------------------------------------------------------------------
// Import the function under test after mocks are registered.
// ---------------------------------------------------------------------------

const { applyRecheckVerdicts } = await import("../src/services/llmSastService.js");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal fake Prisma-like Tx client that records updates. */
function makeMockTx(issueRow: Record<string, unknown>) {
  const updates: Array<{ id: string; data: Record<string, unknown> }> = [];

  const client = {
    sastIssue: {
      findFirst: vi.fn().mockResolvedValue(issueRow),
      update: vi.fn().mockImplementation(({ where, data }: { where: { id: string }; data: Record<string, unknown> }) => {
        updates.push({ id: where.id, data });
        return Promise.resolve({ id: where.id, ...data });
      }),
    },
  };

  return { client, updates };
}

function makeIssueRow(id: string, scopeId: string): Record<string, unknown> {
  return {
    id,
    fingerprint: "fp-" + id,
    latestFilePath: "src/foo.ts",
    latestStartLine: 10,
    latestEndLine: null,
    latestCweIds: [],
    latestSeverity: "high",
    triageStatus: "pending",
    jiraTicketId: null,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const SCAN_RUN_ID = randomUUID();
const SCOPE_ID = randomUUID();

describe("applyRecheckVerdicts — untrustworthy: true", () => {
  it('(1) "fixed" verdict is no-op; counted as missingVerdict', async () => {
    const issueId = randomUUID();
    const { client, updates } = makeMockTx(makeIssueRow(issueId, SCOPE_ID));

    const result = await applyRecheckVerdicts(client as never, {
      scanRunId: SCAN_RUN_ID,
      scopeId: SCOPE_ID,
      scopeDir: "/tmp/scope",
      scopePath: "/",
      inputIssues: [{ id: issueId, file_path: "src/foo.ts", start_line: 10, summary: "test", snippet: "", cwe: "CWE-79" }],
      verdicts: [{ id: issueId, verdict: "fixed", reasoning: "patched" }],
      untrustworthy: true,
    });

    expect(result.fixed).toBe(0);
    expect(result.missingVerdict).toBe(1);
    expect(updates).toHaveLength(0);
  });

  it('(2) "file_deleted" verdict is no-op; counted as missingVerdict', async () => {
    const issueId = randomUUID();
    const { client, updates } = makeMockTx(makeIssueRow(issueId, SCOPE_ID));

    const result = await applyRecheckVerdicts(client as never, {
      scanRunId: SCAN_RUN_ID,
      scopeId: SCOPE_ID,
      scopeDir: "/tmp/scope",
      scopePath: "/",
      inputIssues: [{ id: issueId, file_path: "src/foo.ts", start_line: 10, summary: "test", snippet: "", cwe: "CWE-79" }],
      verdicts: [{ id: issueId, verdict: "file_deleted", reasoning: "file removed" }],
      untrustworthy: true,
    });

    expect(result.fileDeleted).toBe(0);
    expect(result.missingVerdict).toBe(1);
    expect(updates).toHaveLength(0);
  });

  it('(3) "still_present" verdict is still processed normally', async () => {
    const issueId = randomUUID();
    const { client, updates } = makeMockTx(makeIssueRow(issueId, SCOPE_ID));

    const result = await applyRecheckVerdicts(client as never, {
      scanRunId: SCAN_RUN_ID,
      scopeId: SCOPE_ID,
      scopeDir: "/tmp/scope",
      scopePath: "/",
      inputIssues: [{ id: issueId, file_path: "src/foo.ts", start_line: 10, summary: "test", snippet: "", cwe: "CWE-79" }],
      verdicts: [{ id: issueId, verdict: "still_present", reasoning: "still there" }],
      untrustworthy: true,
    });

    expect(result.stillPresent).toBe(1);
    expect(result.missingVerdict).toBe(0);
    // DB update should have fired to advance lastSeenScanRunId.
    expect(updates).toHaveLength(1);
    expect(updates[0]!.data["lastSeenScanRunId"]).toBe(SCAN_RUN_ID);
    // triageStatus must NOT have been set to "fixed".
    expect(updates[0]!.data["triageStatus"]).toBeUndefined();
  });
});

describe("applyRecheckVerdicts — untrustworthy: false (default)", () => {
  it('(4a) "fixed" verdict updates triageStatus to "fixed" when trustworthy', async () => {
    const issueId = randomUUID();
    const { client, updates } = makeMockTx(makeIssueRow(issueId, SCOPE_ID));

    const result = await applyRecheckVerdicts(client as never, {
      scanRunId: SCAN_RUN_ID,
      scopeId: SCOPE_ID,
      scopeDir: "/tmp/scope",
      scopePath: "/",
      inputIssues: [{ id: issueId, file_path: "src/foo.ts", start_line: 10, summary: "test", snippet: "", cwe: "CWE-79" }],
      verdicts: [{ id: issueId, verdict: "fixed", reasoning: "patched" }],
      // untrustworthy omitted → defaults to false
    });

    expect(result.fixed).toBe(1);
    expect(result.missingVerdict).toBe(0);
    expect(updates).toHaveLength(1);
    expect(updates[0]!.data["triageStatus"]).toBe("fixed");
  });

  it('(4b) "file_deleted" verdict updates triageStatus to "fixed" when trustworthy', async () => {
    const issueId = randomUUID();
    const { client, updates } = makeMockTx(makeIssueRow(issueId, SCOPE_ID));

    const result = await applyRecheckVerdicts(client as never, {
      scanRunId: SCAN_RUN_ID,
      scopeId: SCOPE_ID,
      scopeDir: "/tmp/scope",
      scopePath: "/",
      inputIssues: [{ id: issueId, file_path: "src/foo.ts", start_line: 10, summary: "test", snippet: "", cwe: "CWE-79" }],
      verdicts: [{ id: issueId, verdict: "file_deleted", reasoning: "gone" }],
      untrustworthy: false,
    });

    expect(result.fileDeleted).toBe(1);
    expect(result.missingVerdict).toBe(0);
    expect(updates).toHaveLength(1);
    expect(updates[0]!.data["triageStatus"]).toBe("fixed");
    expect((updates[0]!.data["triageReasoning"] as string)).toContain("[file deleted]");
  });
});
