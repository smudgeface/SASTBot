/**
 * Tests for the SCA trustworthiness gates added after the GoPxL BE
 * auto-resolve incident (2026-05-27).
 *
 * Incident: a successful scan (`9fe4acbb`) analyzed 41 components — a strict
 * superset of the prior scan's 31, including Newtonsoft.Json, SharpZipLib and
 * other packages with well-known advisories — yet OSV.dev returned 0
 * vulnerabilities. The OSV phase had silently swallowed failed HTTP responses
 * (returning `[]`, indistinguishable from "no vulns"), no error warning was
 * emitted, and the auto-fix sweep then marked all 46 real findings "fixed".
 *
 * Two complementary gates:
 *   1. osvFailureSeverity      — escalate when OSV queries actually failed.
 *   2. isDegenerateScaSweep /  — backstop: never mass-fix when a populated scan
 *      runScaAutoFixSweep         detected nothing while prior findings are active.
 */

import { randomBytes, randomUUID } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

const {
  osvFailureSeverity,
  OSV_FAILURE_RATIO_THRESHOLD,
  OSV_FAILURE_ABSOLUTE_COUNT,
} = await import("../src/worker.js");
const { isDegenerateScaSweep, runScaAutoFixSweep } = await import(
  "../src/services/scaAutoFix.js"
);

// ---------------------------------------------------------------------------
// osvFailureSeverity — Defense 1 (root cause: OSV failures were swallowed)
// ---------------------------------------------------------------------------

describe("osvFailureSeverity", () => {
  it("is info when no queries failed (caller short-circuits anyway)", () => {
    expect(osvFailureSeverity(41, 0)).toBe("info");
  });

  it("is info when nothing was queried", () => {
    expect(osvFailureSeverity(0, 0)).toBe("info");
  });

  it("escalates to error when every query failed — the likely GoPxL mechanism", () => {
    // 41 nuget+generic components, all OSV calls 429/5xx → 0 vulns reported.
    expect(osvFailureSeverity(41, 41)).toBe("error");
  });

  it("escalates to error at exactly the ratio threshold (25%)", () => {
    // 5/20 = 0.25, below the absolute guard so the ratio branch is exercised.
    expect(osvFailureSeverity(20, 5)).toBe("error");
  });

  it("stays info just below the ratio threshold and under the absolute guard", () => {
    // 5/21 = 0.238 < 0.25, and 5 < 10.
    expect(osvFailureSeverity(21, 5)).toBe("info");
  });

  it("stays info for a single transient failure on a large scan", () => {
    expect(osvFailureSeverity(500, 1)).toBe("info");
  });

  it("absolute-count guard: 10 failed on a huge scan escalates despite a tiny ratio", () => {
    // 10/510 = 0.0196 — well under 0.25, but 10 unchecked components is a real
    // blind spot (those findings would otherwise be sweep-eligible unverified).
    expect(osvFailureSeverity(500, 10)).toBe("error");
  });

  it("absolute-count guard: 9 failed on a huge scan stays info", () => {
    expect(osvFailureSeverity(500, 9)).toBe("info");
  });

  it("respects custom ratio + absolute overrides", () => {
    expect(osvFailureSeverity(100, 5, 0.5, 5)).toBe("error"); // absolute fires
    expect(osvFailureSeverity(100, 4, 0.5, 5)).toBe("info"); // neither fires
  });

  it("uses the exported constants as defaults", () => {
    expect(OSV_FAILURE_RATIO_THRESHOLD).toBe(0.25);
    expect(OSV_FAILURE_ABSOLUTE_COUNT).toBe(10);
  });
});

// ---------------------------------------------------------------------------
// isDegenerateScaSweep — Defense 2 predicate
// ---------------------------------------------------------------------------

describe("isDegenerateScaSweep", () => {
  it("is true for the GoPxL incident shape (0 detected, 46 active, 41 components)", () => {
    expect(isDegenerateScaSweep(0, 46, 41)).toBe(true);
  });

  it("is false for a normal scan that detected findings", () => {
    expect(isDegenerateScaSweep(12, 5, 40)).toBe(false);
  });

  it("is false when there is nothing to sweep (clean repo, 0 active)", () => {
    // Genuinely vuln-free repo: detecting 0 with 0 active is not destructive.
    expect(isDegenerateScaSweep(0, 0, 41)).toBe(false);
  });

  it("is false when no components were analyzed (a different gate owns that)", () => {
    // 0 components → either a legitimate full-dependency removal (the sweep
    // SHOULD propagate it) or a silent cdxgen failure (already caught by the
    // cdxgen_failed error warning before the sweep runs). Not this guard's job.
    expect(isDegenerateScaSweep(0, 5, 0)).toBe(false);
  });

  it("is true for the minimal degenerate case (1 active, 1 component)", () => {
    expect(isDegenerateScaSweep(0, 1, 1)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// runScaAutoFixSweep — the sweep must NOT fix issues when the run is degenerate
// ---------------------------------------------------------------------------

/** Minimal Prisma-like mock. `count` discriminates the two queries the sweep
 *  issues by the shape of `where.lastSeenScanRunId`:
 *   - a bare string  → "detected this run" probe   → returns detectedThisRun
 *   - `{ not: ... }`  → "active to sweep" probe     → returns activeToSweep   */
function makeMockClient(detectedThisRun: number, activeToSweep: number) {
  const updateManyCalls: Array<{ where: unknown; data: unknown }> = [];
  const client = {
    scaIssue: {
      count: vi.fn().mockImplementation(({ where }: { where: Record<string, unknown> }) => {
        return Promise.resolve(typeof where.lastSeenScanRunId === "string" ? detectedThisRun : activeToSweep);
      }),
      updateMany: vi.fn().mockImplementation((args: { where: unknown; data: unknown }) => {
        updateManyCalls.push(args);
        return Promise.resolve({ count: activeToSweep });
      }),
    },
  };
  return { client, updateManyCalls };
}

describe("runScaAutoFixSweep", () => {
  const scopeId = randomUUID();
  const scanRunId = randomUUID();

  it("withholds the sweep on a degenerate run and does NOT touch any issue", async () => {
    const { client, updateManyCalls } = makeMockClient(0, 46);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decision = await runScaAutoFixSweep(client as any, {
      scopeId,
      scanRunId,
      analyzedComponentCount: 41,
    });
    expect(decision.degenerate).toBe(true);
    expect(decision.swept).toBe(false);
    expect(decision.activeToSweep).toBe(46);
    // The critical assertion: no findings were marked fixed.
    expect(client.scaIssue.updateMany).not.toHaveBeenCalled();
    expect(updateManyCalls).toHaveLength(0);
  });

  it("runs the sweep on a normal run that detected findings", async () => {
    const { client, updateManyCalls } = makeMockClient(12, 5);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decision = await runScaAutoFixSweep(client as any, {
      scopeId,
      scanRunId,
      analyzedComponentCount: 40,
    });
    expect(decision.degenerate).toBe(false);
    expect(decision.swept).toBe(true);
    expect(client.scaIssue.updateMany).toHaveBeenCalledTimes(1);
    // Targets prior-run, non-terminal issues only.
    expect(updateManyCalls[0].where).toMatchObject({
      scopeId,
      lastSeenScanRunId: { not: scanRunId },
      dismissedStatus: { notIn: ["fixed", "suppressed", "false_positive"] },
    });
    expect(updateManyCalls[0].data).toEqual({ dismissedStatus: "fixed" });
  });

  it("runs the (harmless) sweep when 0 detected but nothing is active", async () => {
    const { client } = makeMockClient(0, 0);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decision = await runScaAutoFixSweep(client as any, {
      scopeId,
      scanRunId,
      analyzedComponentCount: 41,
    });
    expect(decision.degenerate).toBe(false);
    expect(decision.swept).toBe(true);
    expect(client.scaIssue.updateMany).toHaveBeenCalledTimes(1);
  });

  it("does not withhold when no components were analyzed (legit dep removal / other gate)", async () => {
    const { client } = makeMockClient(0, 5);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const decision = await runScaAutoFixSweep(client as any, {
      scopeId,
      scanRunId,
      analyzedComponentCount: 0,
    });
    expect(decision.degenerate).toBe(false);
    expect(decision.swept).toBe(true);
    expect(client.scaIssue.updateMany).toHaveBeenCalledTimes(1);
  });
});
