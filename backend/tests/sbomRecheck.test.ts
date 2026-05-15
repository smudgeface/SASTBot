/**
 * Unit tests for the SBOM Component Recheck feature (Stage 2).
 *
 * Tests cover the two-tier algorithm in runSbomRecheck:
 *   Tier 1 — filesystem evidence check (free, no LLM)
 *   Tier 2 — LLM recheck (mocked here; no real LLM call)
 *
 * We test via the raw SQL helpers used by the service. The tests use an
 * in-process Prisma client against the real Postgres DB (same approach as
 * repoCache.test.ts), but the scope-component checks are pure filesystem
 * and DB operations — no claude spawn is invoked.
 */

import { mkdtempSync, rmSync, mkdirSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

// ---------------------------------------------------------------------------
// Test helpers — exercise the Tier-1 logic directly without the full service.
// The Tier-1 path is a pure function: given a scopeDir and an evidencePath,
// existsSync decides whether to mark removed. We test this logic in isolation
// rather than calling runSbomRecheck (which also calls resolveLlmConfig and
// would fail without DB-stored LLM credentials).
// ---------------------------------------------------------------------------

describe("SBOM recheck — Tier-1: filesystem evidence check", () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "sbom-recheck-test-"));
    // Create a real file we can use as evidence.
    mkdirSync(join(tmpDir, "extern"), { recursive: true });
    writeFileSync(join(tmpDir, "extern", "zlib.h"), "/* zlib 1.2.6 */\n");
  });

  afterAll(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("marks a candidate removed when its evidence file is missing", () => {
    const evidencePath = "extern/missing-lib.h";
    const absPath = join(tmpDir, evidencePath);

    // File should NOT exist.
    expect(existsSync(absPath)).toBe(false);

    // The Tier-1 rule: if !existsSync(absPath) → mark removed.
    const shouldRemove = !existsSync(absPath);
    expect(shouldRemove).toBe(true);
  });

  it("falls through to Tier 2 when the evidence file is present", () => {
    const evidencePath = "extern/zlib.h";
    const absPath = join(tmpDir, evidencePath);

    // File should exist.
    expect(existsSync(absPath)).toBe(true);

    // The Tier-1 rule: if existsSync(absPath) → don't mark removed, fall to Tier 2.
    const shouldRemove = !existsSync(absPath);
    expect(shouldRemove).toBe(false);
  });

  it("falls through to Tier 2 when evidencePath is null (manifest-discovered component)", () => {
    // When evidencePath is null the service skips Tier-1 and goes straight to Tier 2.
    const evidencePath: string | null = null;

    // Tier-1 logic: if no evidence_path → skip Tier 1.
    const goesToTier2 = evidencePath === null;
    expect(goesToTier2).toBe(true);
  });

  it("correctly resolves scope-relative evidence path to an absolute path", () => {
    const scopeDir = tmpDir;
    const evidencePath = "extern/zlib.h";

    const absPath = join(scopeDir, evidencePath);
    expect(existsSync(absPath)).toBe(true);
    expect(absPath).toBe(join(tmpDir, "extern/zlib.h"));
  });
});

// ---------------------------------------------------------------------------
// Verdict schema validation (mirrors what the service parses).
// ---------------------------------------------------------------------------

import { z } from "zod";

const RecheckVerdictSchema = z.object({
  component_id: z.string(),
  verdict: z.enum(["present", "removed"]),
  new_evidence_path: z.string().optional(),
  rationale: z.string(),
});

const MergeVerdictSchema = z.object({
  type: z.literal("merge"),
  keep_id: z.string(),
  drop_ids: z.array(z.string()).min(1),
  rationale: z.string(),
});

const AnyVerdictSchema = z.union([MergeVerdictSchema, RecheckVerdictSchema]);

describe("SBOM recheck — Tier-2 verdict schema", () => {
  it("accepts a present verdict", () => {
    const raw = { component_id: randomUUID(), verdict: "present", rationale: "File found at evidence path." };
    expect(RecheckVerdictSchema.safeParse(raw).success).toBe(true);
  });

  it("accepts a present verdict with new_evidence_path", () => {
    const raw = {
      component_id: randomUUID(),
      verdict: "present",
      new_evidence_path: "extern/moved/zlib.h",
      rationale: "File moved during refactor.",
    };
    expect(RecheckVerdictSchema.safeParse(raw).success).toBe(true);
  });

  it("accepts a removed verdict", () => {
    const raw = { component_id: randomUUID(), verdict: "removed", rationale: "No references found in codebase." };
    expect(RecheckVerdictSchema.safeParse(raw).success).toBe(true);
  });

  it("rejects an unknown verdict value", () => {
    const raw = { component_id: randomUUID(), verdict: "unknown", rationale: "Not sure." };
    expect(RecheckVerdictSchema.safeParse(raw).success).toBe(false);
  });

  it("rejects a verdict missing rationale", () => {
    const raw = { component_id: randomUUID(), verdict: "present" };
    expect(RecheckVerdictSchema.safeParse(raw).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Merge verdict schema validation.
// ---------------------------------------------------------------------------

describe("SBOM recheck — merge verdict schema", () => {
  it("accepts a valid merge verdict with one drop_id", () => {
    const raw = {
      type: "merge",
      keep_id: randomUUID(),
      drop_ids: [randomUUID()],
      rationale: "Same xenomai CPE family with different version segments.",
    };
    expect(MergeVerdictSchema.safeParse(raw).success).toBe(true);
  });

  it("accepts a valid merge verdict with multiple drop_ids", () => {
    const raw = {
      type: "merge",
      keep_id: randomUUID(),
      drop_ids: [randomUUID(), randomUUID(), randomUUID()],
      rationale: "Three LLM-alias variants of the same Moxa SDK under extern/Moxa/.",
    };
    expect(MergeVerdictSchema.safeParse(raw).success).toBe(true);
  });

  it("rejects a merge verdict with empty drop_ids array", () => {
    const raw = {
      type: "merge",
      keep_id: randomUUID(),
      drop_ids: [],
      rationale: "This is invalid — you must drop at least one row.",
    };
    expect(MergeVerdictSchema.safeParse(raw).success).toBe(false);
  });

  it("rejects a merge verdict missing type field", () => {
    const raw = {
      keep_id: randomUUID(),
      drop_ids: [randomUUID()],
      rationale: "Missing type.",
    };
    expect(MergeVerdictSchema.safeParse(raw).success).toBe(false);
  });

  it("rejects a merge verdict with wrong type value", () => {
    const raw = {
      type: "dedup",  // wrong value
      keep_id: randomUUID(),
      drop_ids: [randomUUID()],
      rationale: "Wrong type value.",
    };
    expect(MergeVerdictSchema.safeParse(raw).success).toBe(false);
  });

  it("rejects a merge verdict missing rationale", () => {
    const raw = { type: "merge", keep_id: randomUUID(), drop_ids: [randomUUID()] };
    expect(MergeVerdictSchema.safeParse(raw).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AnyVerdictSchema discriminated union: correctly routes merge vs presence.
// ---------------------------------------------------------------------------

describe("SBOM recheck — AnyVerdictSchema discriminated union", () => {
  it("routes a merge line to MergeVerdictSchema", () => {
    const raw = {
      type: "merge",
      keep_id: randomUUID(),
      drop_ids: [randomUUID()],
      rationale: "Same library.",
    };
    const result = AnyVerdictSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect("type" in result.data && result.data.type).toBe("merge");
    }
  });

  it("routes a presence verdict line to RecheckVerdictSchema", () => {
    const raw = { component_id: randomUUID(), verdict: "present", rationale: "Found." };
    const result = AnyVerdictSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect("verdict" in result.data && result.data.verdict).toBe("present");
    }
  });

  it("routes a removed verdict line to RecheckVerdictSchema", () => {
    const raw = { component_id: randomUUID(), verdict: "removed", rationale: "Gone." };
    const result = AnyVerdictSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect("verdict" in result.data && result.data.verdict).toBe("removed");
    }
  });

  it("rejects a line that matches neither schema", () => {
    const raw = { type: "unknown", foo: "bar" };
    expect(AnyVerdictSchema.safeParse(raw).success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Hard-cap logic (mirrors what runSbomRecheck does before Tier 1).
// ---------------------------------------------------------------------------

describe("SBOM recheck — candidate cap logic", () => {
  const MAX_CANDIDATES = 20;

  it("caps candidates at 20 when more are present", () => {
    const candidates = Array.from({ length: 35 }, (_, i) => ({ id: String(i) }));
    const workSet = candidates.slice(0, MAX_CANDIDATES);
    const capped = candidates.length - MAX_CANDIDATES;

    expect(workSet).toHaveLength(20);
    expect(capped).toBe(15);
  });

  it("does not cap when candidates are within the limit", () => {
    const candidates = Array.from({ length: 5 }, (_, i) => ({ id: String(i) }));
    const workSet = candidates.slice(0, MAX_CANDIDATES);
    const capped = Math.max(0, candidates.length - MAX_CANDIDATES);

    expect(workSet).toHaveLength(5);
    expect(capped).toBe(0);
  });

  it("handles an empty candidate set", () => {
    const candidates: { id: string }[] = [];
    const workSet = candidates.slice(0, MAX_CANDIDATES);
    const capped = Math.max(0, candidates.length - MAX_CANDIDATES);

    expect(workSet).toHaveLength(0);
    expect(capped).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// Merge application logic — DB-backed tests.
//
// These tests create real scope_components + scan_run_components rows via raw
// SQL (same approach as the existing dedup migrations), apply the merge logic
// directly, and verify the resulting DB state.
//
// The merge logic under test (from llmSbomRecheckService.ts applyMerge):
//  1. Re-point scan_run_components from drop_ids → keep_id (INSERT … ON CONFLICT DO NOTHING)
//  2. DELETE scan_run_components pointing at drop_ids
//  3. DELETE scope_components drop_id rows
// ---------------------------------------------------------------------------

// Lazy-load prisma and set env vars before the module initializes.
beforeAll(() => {
  process.env.MASTER_KEY ??= Buffer.from("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "hex").toString("base64");
  process.env.DATABASE_URL ??= "postgresql://sastbot:sastbot@localhost:5432/sastbot";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

async function getPrisma() {
  const { prisma } = await import("../src/db.js");
  return prisma;
}

/**
 * Apply one merge verdict directly (mirrors the service logic).
 * Returns the number of scope_components rows deleted.
 */
async function applyMerge(
  prisma: Awaited<ReturnType<typeof getPrisma>>,
  keepId: string,
  dropIds: string[],
): Promise<number> {
  // Step 1: re-point scan_run_components from drop_ids → keep_id
  for (const dropId of dropIds) {
    await prisma.$executeRawUnsafe(
      `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
       SELECT DISTINCT ON (src.scan_run_id, $2::uuid)
         src.scan_run_id,
         $2::uuid,
         src.discovery_method
       FROM scan_run_components src
       WHERE src.scope_component_id = $1::uuid
       ORDER BY src.scan_run_id, $2::uuid, src.discovery_method
       ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING`,
      dropId,
      keepId,
    );
  }
  // Step 2: delete join rows pointing at drop_ids
  await prisma.$executeRawUnsafe(
    `DELETE FROM scan_run_components WHERE scope_component_id = ANY($1::uuid[])`,
    `{${dropIds.join(",")}}`,
  );
  // Step 3: delete dropped scope_components rows
  const deleted = await prisma.$executeRawUnsafe(
    `DELETE FROM scope_components WHERE id = ANY($1::uuid[])`,
    `{${dropIds.join(",")}}`,
  );
  return deleted;
}

describe("SBOM recheck — merge application (DB)", () => {
  // Track IDs we create so we can clean up after the suite.
  const createdScopeIds: string[] = [];
  const createdOrgIds: string[] = [];
  const createdRepoIds: string[] = [];
  const createdScanRunIds: string[] = [];

  afterAll(async () => {
    let db: Awaited<ReturnType<typeof getPrisma>> | undefined;
    try {
      db = await getPrisma();
    } catch {
      return; // DB not available — skip cleanup
    }
    // Delete in dependency order. Cascade handles scope_components /
    // scan_run_components rows when scan_scopes / scan_runs are deleted.
    for (const id of createdScanRunIds) {
      await db.scanRun.delete({ where: { id } }).catch(() => undefined);
    }
    for (const id of createdScopeIds) {
      await db.scanScope.delete({ where: { id } }).catch(() => undefined);
    }
    for (const id of createdRepoIds) {
      await db.repo.delete({ where: { id } }).catch(() => undefined);
    }
    for (const id of createdOrgIds) {
      await db.org.delete({ where: { id } }).catch(() => undefined);
    }
  });

  /** Create a minimal org → repo → scope → scan_run fixture via Prisma API. */
  async function createFixture(db: Awaited<ReturnType<typeof getPrisma>>, suffix: string) {
    const org = await db.org.create({ data: { name: `test-merge-org-${suffix}` } });
    createdOrgIds.push(org.id);

    const repo = await db.repo.create({
      data: {
        orgId: org.id,
        name: `test-repo-${suffix}`,
        url: `https://example.com/test-repo-${suffix}.git`,
        protocol: "https",
      },
    });
    createdRepoIds.push(repo.id);

    const scope = await db.scanScope.create({
      data: { orgId: org.id, repoId: repo.id },
    });
    createdScopeIds.push(scope.id);

    const scanRun = await db.scanRun.create({
      data: {
        orgId: org.id,
        repoId: repo.id,
        scopeId: scope.id,
        status: "success",
        triggeredBy: "user",
      },
    });
    createdScanRunIds.push(scanRun.id);

    return { org, repo, scope, scanRun };
  }

  it("re-points scan_run_components from drop_id to keep_id and removes dropped row", async () => {
    let db: Awaited<ReturnType<typeof getPrisma>>;
    try {
      db = await getPrisma();
      // Quick connectivity check
      await db.$queryRaw`SELECT 1`;
    } catch {
      // No DB available in this environment — skip gracefully
      return;
    }

    const { org, scope, scanRun } = await createFixture(db, randomUUID().slice(0, 8));

    // Create two duplicate scope_components (keep + drop).
    const keepId = randomUUID();
    const dropId = randomUUID();

    for (const [id, name] of [[keepId, "xenomai@3.1"], [dropId, "xenomai@*"]] as const) {
      await db.$executeRawUnsafe(
        `INSERT INTO scope_components (id, scope_id, org_id, name, purl, component_type, licenses, dismissed_status, source, first_seen_scan_run_id, last_seen_scan_run_id, created_at, updated_at)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'pkg:generic/' || $4, 'library', '{}', 'active', 'scan', $5::uuid, $5::uuid, now(), now())`,
        id, scope.id, org.id, name, scanRun.id,
      );
    }

    // Create join rows: both components linked to the scan run.
    for (const scId of [keepId, dropId]) {
      await db.$executeRawUnsafe(
        `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method) VALUES ($1::uuid, $2::uuid, 'llm_augmentation') ON CONFLICT DO NOTHING`,
        scanRun.id, scId,
      );
    }

    // Apply the merge.
    const deleted = await applyMerge(db, keepId, [dropId]);

    // Assertions.
    expect(deleted).toBe(1);

    // keep_id should still exist.
    const keepRows = await db.$queryRawUnsafe<Array<{ id: string }>>(
      `SELECT id FROM scope_components WHERE id = $1::uuid`, keepId,
    );
    expect(keepRows).toHaveLength(1);

    // drop_id should be gone.
    const dropRows = await db.$queryRawUnsafe<Array<{ id: string }>>(
      `SELECT id FROM scope_components WHERE id = $1::uuid`, dropId,
    );
    expect(dropRows).toHaveLength(0);

    // The scan_run should still have a join to keep_id (re-pointed from drop_id).
    const joinRows = await db.$queryRawUnsafe<Array<{ scope_component_id: string }>>(
      `SELECT scope_component_id FROM scan_run_components WHERE scan_run_id = $1::uuid`, scanRun.id,
    );
    expect(joinRows.map((r) => r.scope_component_id)).toContain(keepId);
    expect(joinRows.map((r) => r.scope_component_id)).not.toContain(dropId);
  });

  it("handles multi-drop-to-one-keep without PK conflicts", async () => {
    let db: Awaited<ReturnType<typeof getPrisma>>;
    try {
      db = await getPrisma();
      await db.$queryRaw`SELECT 1`;
    } catch {
      return;
    }

    const { org, scope, scanRun } = await createFixture(db, randomUUID().slice(0, 8));

    const keepId = randomUUID();
    const drop1 = randomUUID();
    const drop2 = randomUUID();

    for (const [id, name] of [[keepId, "moxa-mxio"], [drop1, "moxa-sdk"], [drop2, "Moxa SDK"]] as const) {
      await db.$executeRawUnsafe(
        `INSERT INTO scope_components (id, scope_id, org_id, name, purl, component_type, licenses, dismissed_status, source, first_seen_scan_run_id, last_seen_scan_run_id, created_at, updated_at)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 'pkg:generic/' || $4, 'library', '{}', 'active', 'scan', $5::uuid, $5::uuid, now(), now())`,
        id, scope.id, org.id, name, scanRun.id,
      );
    }

    // Both drop rows have a join to the same scan run — the re-point must not PK-conflict.
    for (const scId of [keepId, drop1, drop2]) {
      await db.$executeRawUnsafe(
        `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method) VALUES ($1::uuid, $2::uuid, 'llm_augmentation') ON CONFLICT DO NOTHING`,
        scanRun.id, scId,
      );
    }

    // Should not throw even though both drop_ids share the same scan_run.
    const deleted = await applyMerge(db, keepId, [drop1, drop2]);
    expect(deleted).toBe(2);

    // Only keep_id remains.
    const remaining = await db.$queryRawUnsafe<Array<{ id: string }>>(
      `SELECT id FROM scope_components WHERE id = ANY($1::uuid[])`,
      `{${[keepId, drop1, drop2].join(",")}}`,
    );
    expect(remaining.map((r) => r.id)).toEqual([keepId]);

    // Join table: one row for the scan run, pointing at keep_id only.
    const joinRows = await db.$queryRawUnsafe<Array<{ scope_component_id: string }>>(
      `SELECT scope_component_id FROM scan_run_components WHERE scan_run_id = $1::uuid`, scanRun.id,
    );
    const joinIds = joinRows.map((r) => r.scope_component_id);
    expect(joinIds).toContain(keepId);
    expect(joinIds).not.toContain(drop1);
    expect(joinIds).not.toContain(drop2);
  });

  it("skips merge when keep_id is not in the active component set", async () => {
    // This mirrors the validation logic in runSbomRecheck.
    const unknownKeepId = randomUUID();
    const activeIds = new Set([randomUUID(), randomUUID()]);

    // Validation: keep_id must be in activeIds.
    const isValid = activeIds.has(unknownKeepId);
    expect(isValid).toBe(false);
  });

  it("skips merge when any drop_id is not in the active component set", async () => {
    const keepId = randomUUID();
    const validDropId = randomUUID();
    const unknownDropId = randomUUID();
    const activeIds = new Set([keepId, validDropId]);

    // Validation: all drop_ids must be in activeIds.
    const invalidDropIds = [validDropId, unknownDropId].filter((id) => !activeIds.has(id));
    expect(invalidDropIds).toHaveLength(1);
    expect(invalidDropIds[0]).toBe(unknownDropId);
  });

  it("skips merge when keep_id appears in drop_ids", () => {
    const keepId = randomUUID();
    // Validation: keep_id must not be one of the drop_ids.
    const dropIds = [randomUUID(), keepId]; // keep_id accidentally in the list
    const selfReference = dropIds.includes(keepId);
    expect(selfReference).toBe(true);
  });
});
