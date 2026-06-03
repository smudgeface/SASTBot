/**
 * Regression: persistReachabilityRecords must skip a reachability record whose
 * sca_issue_id is not a UUID (the model occasionally fabricates one) instead of
 * passing it to Prisma's @db.Uuid column, which throws P2023 and crashes the
 * whole scan at the final persist step.
 *
 * Root cause: a 2026-06 FactorySmart scan died after a full LLM detection pass
 * because the model emitted a non-UUID sca_issue_id (started with "p"). The fix
 * gates the id with isLikelyUuid before any findFirst/update keyed on it.
 */

import { randomBytes } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
});

const VALID_UUID = "11111111-2222-4333-8444-555555555555";

type PersistArgs = Parameters<
  typeof import("../src/services/llmSastService.js").persistReachabilityRecords
>;

function makeInput(record: unknown): PersistArgs[1] {
  return {
    scanRunId: "scan-1",
    scopeId: "scope-1",
    scopeDir: "/tmp/does-not-matter",
    scopePath: "/",
    orgId: null,
    records: [record as PersistArgs[1]["records"][number]],
    modelName: "test-model",
  };
}

describe("persistReachabilityRecords — non-UUID sca_issue_id guard", () => {
  it("skips a fabricated non-UUID id WITHOUT touching the DB (no P2023)", async () => {
    const { ReachabilityRecord, persistReachabilityRecords } = await import(
      "../src/services/llmSastService.js"
    );
    const bad = ReachabilityRecord.parse({
      kind: "reachability",
      sca_issue_id: "pkg:nuget/Newtonsoft.Json@13.0.0", // model fabrication
      reachable: true,
    });
    const client = {
      scaIssue: { findFirst: vi.fn(), update: vi.fn() },
    };
    const res = await persistReachabilityRecords(client as unknown as PersistArgs[0], makeInput(bad));
    expect(res.reachabilitySkipped).toBe(1);
    expect(res.reachabilityUpdated).toBe(0);
    // The gate short-circuits before any query — this is what prevents P2023.
    expect(client.scaIssue.findFirst).not.toHaveBeenCalled();
    expect(client.scaIssue.update).not.toHaveBeenCalled();
  });

  it("lets a valid UUID through to the scope lookup (then skips if unknown)", async () => {
    const { ReachabilityRecord, persistReachabilityRecords } = await import(
      "../src/services/llmSastService.js"
    );
    const good = ReachabilityRecord.parse({
      kind: "reachability",
      sca_issue_id: VALID_UUID,
      reachable: true,
    });
    const client = {
      scaIssue: { findFirst: vi.fn().mockResolvedValue(null), update: vi.fn() },
    };
    const res = await persistReachabilityRecords(client as unknown as PersistArgs[0], makeInput(good));
    expect(client.scaIssue.findFirst).toHaveBeenCalledOnce();
    expect(res.reachabilitySkipped).toBe(1); // unknown ScaIssue → skipped, not crashed
    expect(res.reachabilityUpdated).toBe(0);
  });
});
