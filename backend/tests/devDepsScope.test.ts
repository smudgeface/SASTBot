/**
 * Tests for the includeDevDeps dependency-scope gating (2026-05-28).
 *
 * The repo flag `includeDevDeps` (renamed from `reachabilityIncludeDevDeps`)
 * governs whether npm dev-only components are in scope. When false (default):
 *   - the SBOM recheck drops dev-only candidates entirely (token saving), and
 *   - the curated SBOM excludes dev-only components (so it matches the
 *     Components tab's default-visible set).
 */

import { randomBytes } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

const { partitionRecheckCandidates } = await import(
  "../src/services/llmSbomRecheckService.js"
);

// ---------------------------------------------------------------------------
// partitionRecheckCandidates — recheck token-saving + prioritization
// ---------------------------------------------------------------------------

/** Build a candidate list pre-sorted non-dev-first (as the SQL ORDER BY does):
 *  `runtime` runtime components followed by `dev` dev-only components. */
function makeCandidates(runtime: number, dev: number) {
  const out: Array<{ id: string; is_dev_only: boolean }> = [];
  for (let i = 0; i < runtime; i++) out.push({ id: `r${i}`, is_dev_only: false });
  for (let i = 0; i < dev; i++) out.push({ id: `d${i}`, is_dev_only: true });
  return out;
}

describe("partitionRecheckCandidates", () => {
  it("drops all dev-only candidates when includeDevDeps=false", () => {
    const raw = makeCandidates(60, 385); // GoPxL-shaped: 60 runtime, 385 dev-only
    const p = partitionRecheckCandidates(raw, false, 100);
    expect(p.excludedDevOnly).toBe(385);
    expect(p.candidates).toHaveLength(60);
    expect(p.candidates.every((c) => !c.is_dev_only)).toBe(true);
    // 60 runtime < cap → nothing skipped, no cap pressure at all.
    expect(p.workSet).toHaveLength(60);
    expect(p.skipped).toHaveLength(0);
    expect(p.cappedDevOnly).toBe(0);
    expect(p.cappedRuntime).toBe(0);
  });

  it("keeps dev-only when includeDevDeps=true but ranks runtime first under the cap", () => {
    const raw = makeCandidates(70, 80); // 150 total, cap 100
    const p = partitionRecheckCandidates(raw, true, 100);
    expect(p.excludedDevOnly).toBe(0);
    expect(p.candidates).toHaveLength(150);
    // All 70 runtime are in the work set (non-dev-first ordering preserved).
    expect(p.workSet.filter((c) => !c.is_dev_only)).toHaveLength(70);
    expect(p.workSet.filter((c) => c.is_dev_only)).toHaveLength(30);
    // The 50 skipped are all dev-only — runtime is never starved.
    expect(p.skipped).toHaveLength(50);
    expect(p.cappedDevOnly).toBe(50);
    expect(p.cappedRuntime).toBe(0);
  });

  it("splits the capped overflow into dev vs runtime when runtime alone exceeds the cap", () => {
    const raw = makeCandidates(130, 20); // 130 runtime > cap 100
    const p = partitionRecheckCandidates(raw, true, 100);
    // First 100 are runtime; skipped = 30 runtime + 20 dev.
    expect(p.skipped).toHaveLength(50);
    expect(p.cappedRuntime).toBe(30);
    expect(p.cappedDevOnly).toBe(20);
  });

  it("is a clean no-op shape for an empty candidate set", () => {
    const p = partitionRecheckCandidates([], false, 100);
    expect(p).toMatchObject({ excludedDevOnly: 0, cappedDevOnly: 0, cappedRuntime: 0 });
    expect(p.candidates).toHaveLength(0);
    expect(p.workSet).toHaveLength(0);
    expect(p.skipped).toHaveLength(0);
  });

  it("excludes dev-only even when there are zero runtime candidates", () => {
    const raw = makeCandidates(0, 12);
    const p = partitionRecheckCandidates(raw, false, 100);
    expect(p.excludedDevOnly).toBe(12);
    expect(p.candidates).toHaveLength(0); // nothing left to recheck → phase no-op
  });
});

// ---------------------------------------------------------------------------
// buildCuratedSbomJsonForScope — dev-only exclusion in the component query
// ---------------------------------------------------------------------------

const SCOPE_ID = "aaaaaaaa-0000-0000-0000-000000000099";

function makeScopeRow(includeDevDeps: boolean) {
  return {
    id: SCOPE_ID,
    path: "/",
    lastScanRunId: "bbbbbbbb-0000-0000-0000-000000000099",
    lastScanCompletedAt: new Date("2026-05-20T00:00:00Z"),
    createdAt: new Date("2026-05-01T00:00:00Z"),
    orgId: null,
    isActive: true,
    repoId: "dddddddd-0000-0000-0000-000000000099",
    displayName: null,
    repo: { name: "r", defaultBranch: "main", includeDevDeps },
  };
}

/** Run the scope SBOM builder with a stubbed prisma and return the `where`
 *  passed to the active-components query. Returns [] components so the builder
 *  short-circuits — we only care about the filter it constructed. */
async function captureActiveComponentsWhere(includeDevDeps: boolean): Promise<Record<string, unknown>> {
  const { prisma } = await import("../src/db.js");
  vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
    makeScopeRow(includeDevDeps) as unknown as Awaited<ReturnType<typeof prisma.scanScope.findUnique>>,
  );
  // Return [] so the builder short-circuits (it returns null on no active
  // components) — we only care about the filter it constructed.
  const spy = vi
    .spyOn(prisma.scopeComponent, "findMany")
    .mockResolvedValue([] as never);
  const { buildCuratedSbomJsonForScope } = await import("../src/services/sbomCurated.js");
  await buildCuratedSbomJsonForScope(SCOPE_ID);
  const firstCallArg = spy.mock.calls[0]?.[0] as { where?: Record<string, unknown> } | undefined;
  const captured = firstCallArg?.where ?? {};
  vi.restoreAllMocks();
  return captured;
}

describe("buildCuratedSbomJsonForScope — dev-only gating", () => {
  it("excludes dev-only components when includeDevDeps=false", async () => {
    const where = await captureActiveComponentsWhere(false);
    expect(where).toMatchObject({ dismissedStatus: "active", isDevOnly: false });
  });

  it("includes dev-only components when includeDevDeps=true", async () => {
    const where = await captureActiveComponentsWhere(true);
    expect(where).toMatchObject({ dismissedStatus: "active" });
    expect(where).not.toHaveProperty("isDevOnly");
  });
});
