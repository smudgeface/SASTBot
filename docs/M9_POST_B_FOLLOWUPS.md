# M9 — pre-existing bugs to address after Deploy 3

> **Trigger:** these are validation-round findings from real scans (FSS + Gocator Classic /GoWeb, 2026-05-22) that are **not** in Stream B scope. Address as a single cleanup commit cluster after Deploy 3 (B5+B6) ships and the E2E closure gate in `docs/M9_E2E_TEST_PLAN.md` is run.
>
> **Pinned reference from `CLAUDE.md` "For AI agents" section** so the post-Deploy-3 maintainer can't miss it.

Numbered to match the validation report so cross-references stay stable.

---

## Issue 1 — `scan_runs.component_count` denorm goes stale on recheck recovery

**Symptom.** On the 2026-05-22 run, FSS reported `scan_runs.component_count = 1` but `sbom_components` had 31 rows for that scan and the curated SBOM file emitted by B1 contained 31 components. GOC similar: denorm=2434, actual=2439.

**Root cause.** `worker.ts:~1383` sets `componentCount: finalComponents.length` inside the augmentation-persist transaction. That number reflects the LLM augmentation result only. The downstream phases — `materializeRecoveredComponents` (recheck-recovered rows) and `rebuildComponentsFromScopeState` (merge-survivor rows) — insert additional `sbom_components` rows for the same scan_run but do not update the denorm.

**Operator impact.** The scans list and any reporting that reads `scan_runs.component_count` undercounts the real SBOM size. Particularly noticeable when scan-time augmentation parse errors are high — most components arrive via recheck recovery, so the denorm reads close to zero.

**Fix.** After `rebuildComponentsFromScopeState` returns (worker.ts ~line 1547), recompute and write:

```ts
const actualCount = await prisma.sbomComponent.count({ where: { scanRunId } });
if (actualCount !== components.length) {
  await prisma.scanRun.update({
    where: { id: scanRunId },
    data: { componentCount: actualCount },
  });
}
```

Belt-and-braces: also recompute in `sbom_emit` and write through (the emit step has the authoritative `sbom_components` row set in hand via `buildCuratedSbomJson`).

**Tests.** Unit test would require mocking the worker transaction chain — skip. Verification belongs in §4 Phase 1 of the closure gate: assert `scan_runs.component_count` matches `sbom_components.count(where: scanRunId)` after a real scan.

---

## Issue 2 — LLM SBOM augmentation parse errors (`evidence_path: Required`)

**Symptom.** Every scan emits N "schema: evidence_path: Required" parse errors. FSS: 23. GOC: 10. The records are silently dropped from the augmentation result. Some get recovered by `llmSbomRecheckService` via the scope_components fallback, but only for repos with prior-scan history — first-scan-of-a-new-repo loses them outright.

**Root cause.** `backend/src/services/llmSbomService.ts:123`:

```ts
evidence_path: z.string(),   // ← REQUIRED
```

Marked required despite the field's role being explicitly "Legacy single-file evidence path. Accepted for backwards-compat with older prompt versions; new prompts should emit `evidence` instead" (line 121–122 comment). The prompt `backend/prompts/sbom_system.md:81-82,122-124,145` instructs the LLM to emit the new `evidence: [{path, line}]` shape. The LLM does that correctly; Zod rejects the result.

The intent was clearly:
1. `evidence` (new shape, array of objects)
2. `evidence_paths` (deprecated, array of strings)
3. `evidence_path` (legacy, single string)

At least one of the three should be required; all three should be optional individually.

**Fix.**

```ts
const AddRecord = z.object({
  // ... existing fields ...
  evidence: z.array(z.union([
    z.string(),
    z.object({ path: z.string(), line: z.number().int().nullable().optional() }),
  ])).optional(),
  evidence_paths: z.array(z.string()).optional(),
  evidence_path: z.string().optional(),   // ← drop the required-ness
  // ... rest ...
}).refine(
  (r) => (r.evidence?.length ?? 0) > 0
      || (r.evidence_paths?.length ?? 0) > 0
      || !!r.evidence_path,
  { message: "must provide at least one of: evidence, evidence_paths, evidence_path" }
);
```

`normalizeEvidence` (llmSbomService.ts:611) already handles all three shapes correctly — no change needed there.

**Operator impact of NOT fixing.** Roughly 5–10% of LLM-discovered components are silently dropped per scan, depending on prompt-output variance. The dropped ones are typically the vendored JS/CSS libraries (raphael, jquery-ui, etc.) that operators *most* want to track. SBOM recheck partially compensates on repeat scans but not on cold first scans.

**Tests.** Add to `tests/llmSbomService.test.ts` (or create if absent): parse an AddRecord with just `evidence: [{path: "..."}]` → success. Parse one with no evidence at all → fails with refine message. Parse one with legacy `evidence_path: "..."` → success.

**Bonus cleanup.** Update the comments on lines 121–122 to remove "legacy" framing (now all three shapes are equal first-class inputs). And `backend/prompts/sbom_system.md:122-124,145` should be tightened to make `evidence` the only recommended shape — `evidence_paths` and `evidence_path` left as undocumented compat-only.

---

## Issue 3 — `metadata.timestamp` re-emit drift — DISSOLVED

**Status: NO LONGER AN ISSUE** as of the no-backfill posture decision (2026-05-22). The artifact file is now written exactly once by `sbom_emit` and never re-derived. The drift can't happen.

Keeping the section heading so the numbering stays stable across cross-references.

---

## Issue 4 — FSS LLM SAST detection failure — flaky infra, not a code bug

**Status:** the 2026-05-22 run hit `llm_sast_detection_failed` (claude -p exit 1 after 1205s). Re-run on the same date succeeded. This is LLM endpoint flakiness, not a SASTBot bug.

**No code change needed.** The trustworthiness gate (M6i `hasErrorWarnings`) correctly prevented `lastScanRunId` from advancing — exactly what the gate is for. Validated working.

**Operational note:** if these failures cluster, investigate the LiteLLM endpoint config in app settings. Not in scope for cleanup.

---

## Issue 5 — `mergedRowsRemoved: 1` on Gocator /GoWeb — is the merge logic correct?

**Symptom.** GOC scan reported `mergedRowsRemoved: 1` from the SBOM recheck (`worker.ts:~1463`). Final state: `sbom_components` has 2439 rows, `scope_components` has 2438 — one fewer in the scope. The artifact file (per-scan, from sbom_components) has 2439; the scope-level SBOM endpoint (from scope_components) has 2438.

**Root cause (likely).** Per the M7 design described in CLAUDE.md, the LLM SBOM recheck can issue a `merge` verdict that collapses two scope_components rows for the same logical component (e.g. when the LLM identified them as variants and one is the canonical). The merge deletes one of the scope_components rows but does NOT delete the historical `sbom_components` rows from past scans that referenced it. Per-scan sbom_components from the *current* scan also retain both rows because they were written by `persistAugmentedComponents` *before* the recheck merge ran.

This is structurally consistent with the M7 audit-vs-truth split, but it means the scan-page SBOM (artifact file) and the scope-page SBOM intentionally disagree by the merge delta. **That's working as designed but operator-visible and confusing**: "why does my scope show 2438 packages but the scan that just ran shows 2439?"

**Decision needed before fix.** Two valid postures:
- **(a) Accept the divergence as correct.** The scan page is the audit trail; the scope page is the operator-edited truth. Document the discrepancy in CLAUDE.md's "Two-table component model (M7)" section so the next maintainer doesn't think it's a bug.
- **(b) Re-emit the per-scan artifact after the merge logic settles.** I.e. move `sbom_emit` strictly after recheck *and* delete the pre-merge sbom_components row in the same step. This makes both endpoints agree (both show 2438) at the cost of losing the pre-merge audit trail.

**Recommended:** (a) is the cheapest and matches the M7 architecture. Adding a documentation note to CLAUDE.md is the entire fix.

**Tests.** None for (a). For (b) it'd be an integration test that triggers a merge and asserts both endpoints return the same component set.

---

## Process improvement — agent brief checklist (separate from issue queue)

The 2026-05-22 validation surfaced this as a recurring pattern. The B1–B4 sub-agent missed bumping `APP_VERSION` even though the brief listed both `package.json` files. Already addressed in commit `8aabf7e` (consolidated all version surfaces under `APP_VERSION`, updated CLAUDE.md policy, added explicit "3-file version bump" reminder to plan docs).

**No further action.** Just noted here so the post-Deploy-3 maintainer sees the cleanup history was actively curated, not accidental.

---

## How to use this doc

After Deploy 3 (B5+B6) ships AND the closure gate (`docs/M9_E2E_TEST_PLAN.md`) passes:

1. Read this doc.
2. Open one PR-shaped commit cluster titled `fix(m9-followups): post-deploy-3 cleanup`.
3. Address issues 1, 2, 5 (3 is dissolved, 4 is infra-not-code).
4. Delete this file in the same commit, OR retain it with a "✅ Closed YYYY-MM-DD" header and a one-line summary per issue.
5. Remove the pin from CLAUDE.md "For AI agents" section.
