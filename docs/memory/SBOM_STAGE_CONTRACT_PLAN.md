# Plan — Make the SBOM the full stage contract (provenance-blind vuln lookup)

**Status:** ready for implementation (0.24.0, unreleased — fold into the current
cycle, NO version re-bump; this supersedes the lockstep band-aid added in commit
`791f9a8`).

## Goal / principle

The scan flows through stages. Stage 1 discovers components and builds the SBOM.
A later stage looks up vulnerabilities for the components **in that SBOM**. The
glue between stages is the SBOM itself. **The vulnerability-lookup stage MUST NOT
alter its behavior based on how a component was discovered** (cdxgen direct, LLM
augmentation, or recheck recovery). Provenance is *data on the SBOM*
(`sbom_components.discoveryMethod`), never control flow in stage 2.

## Current (broken) flow — provenance leaks into stage 2

In `backend/src/worker.ts` (scan processor):

1. **3.9 `sbom_persist`** (~L1551): `persistComponentsFromMemory(...)` writes
   `sbom_components` from in-memory `finalComponents` — **direct observations only**
   (cdxgen + LLM augmentation).
2. **3.95** (~L1582): `let components = await prisma.sbomComponent.findMany({ where: { scanRunId } })`
   then `persistScanComponentsToScopeState(...)` lifts direct components → `scope_components`.
3. **3.97 `llm_sbom_recheck`** (~L1612): `runSbomRecheck` returns `recovered: string[]`
   (scope_component IDs confirmed still present via filesystem/LLM). `materializeRecoveredComponents`
   bumps ONLY `scope_components.lastSeenScanRunId` — it does **not** write `sbom_components`
   and does **not** extend the `components` list.
4. **`osv` / `nvd` / `eol`** (~L1746/1791/1817): all iterate `components` (= direct-only
   snapshot from 3.95). Recovered components are structurally invisible to stage 2.

Result: a recovered component is present (in `scope_components`, Components tab) but
never vuln-looked-up; its `sca_issues` go stale and the auto-fix sweep false-fixes them.
The M7 note even codifies the leak: *"OSV/NVD phases run against direct-observation
components only."*

## Target flow

Recheck runs **before** OSV/NVD, so let recovery **feed the SBOM** instead of bypassing it:

1. 3.9 `sbom_persist` — unchanged (direct observations, `discoveryMethod` as today:
   `"manifest"` / `"vendored_inspection"`).
2. 3.95 — unchanged (lift direct → scope; this establishes the active scope_component set
   the recheck needs).
3. 3.97 recheck — after `runSbomRecheck` returns `recovered` IDs, **synthesize an
   `sbom_components` row for each recovered `scope_component`** tagged
   `discoveryMethod = "recheck_recovery"`, and insert. Keep the existing
   `materializeRecoveredComponents` `scope_components.lastSeenScanRunId` bump.
4. **Re-read** `components = await prisma.sbomComponent.findMany({ where: { scanRunId } })`
   AFTER the recovered rows are inserted, so it now holds **direct + recovered**.
5. `osv` / `nvd` / `eol` iterate that unified `components` list — **no branching on
   `discoveryMethod`**. They already take `components: SbomComponent[]`, so this is
   transparent to them.

Net effects: the per-scan SBOM artifact + scan-detail page become *complete*; recovered
components get real vuln lookups every scan; their `sca_issues` refresh naturally
(`lastSeenScanRunId = current`), so the auto-fix sweep can no longer false-fix them —
**structurally**, which is why the lockstep band-aid is removed (below).

## Implementation tasks

### 1. Synthesize `sbom_components` for recovered components (new)
- Add a function — suggest `synthesizeRecoveredSbomComponents(recoveredScopeComponentIds: string[], scanRunId: string): Promise<{ inserted: number }>` in
  `backend/src/services/scopeComponentService.ts` (co-located with `materializeRecoveredComponents`).
- Read the recovered `scope_components` rows. For each, build an `sbom_components` row:
  - `scanRunId` = current; `name`, `version`, `purl`, `ecosystem`, `licenses`,
    `componentType`, `scope`, `isDevOnly`, `manifestFile`, `componentRoot`, `cpe`,
    `evidence`, `llmEvidence` ← copied from the `scope_component`.
  - `discoveryMethod = "recheck_recovery"`.
  - `occurrences` = `[]` (cdxgen emitted none this scan; evidence carries the path).
- Insert with `prisma.sbomComponent.createMany({ data, skipDuplicates: true })` — the
  unique key is `(scanRunId, purl)`; recovered components are by definition NOT in this
  run's direct set, but `skipDuplicates` guards against any purl collision.
- Return `{ inserted }`.

### 2. Wire into the worker (3.97 area, `backend/src/worker.ts`)
- After the existing `materializeRecoveredComponents(...)` call in the recheck block,
  call `synthesizeRecoveredSbomComponents(recheckResult.recovered, scanRunId)` and log
  `{ inserted }`.
- **Move / re-read** the `components` binding so OSV/NVD/EOL see the recovered rows.
  The cleanest: after the recheck block completes (recovered rows inserted), add
  `components = await prisma.sbomComponent.findMany({ where: { scanRunId } });` (the
  `components` var is already `let`, declared at 3.95). Ensure this re-read happens
  BEFORE the `osv` phase and AFTER recovery insertion. Guard for the
  `augmentationFailed` path (if augmentation failed, scope state wasn't persisted, so
  recovery is a no-op — re-reading is harmless but keep behavior identical to today on
  that path).
- Keep ordering: `sbom_persist` → `scope-state` → `llm_sbom_recheck` (+ synthesis +
  re-read) → `osv` → `nvd` → `eol` → `sbom_emit`. (`sbom_emit` already runs after
  osv/nvd/eol, so the emitted artifact will include recovered components — desired.)
- **scan_run_components join:** `materializeRecoveredComponents` does not currently
  create join rows for recovered components. Adding the synthesized `sbom_components`
  does not require join rows for the vuln path. Leave `scan_run_components` behavior as
  today UNLESS a test shows scope-state drift; if touched, keep it consistent with how
  `persistScanComponentsToScopeState` writes join rows. Note this explicitly in the PR.

### 3. Remove the lockstep CVE carry-forward (revert that part of `791f9a8`)
- In `materializeRecoveredComponents` (`scopeComponentService.ts`): remove the
  `prisma.scaIssue.updateMany(...)` carry-forward block, the `namesByScope` grouping, the
  `recovered` find for names, and the `scaCarried` return field. Return type goes back to
  `Promise<{ updated: number }>`. Restore the original log line/shape.
- In `worker.ts`: the `materializeRecoveredComponents` call site reverts to `const { updated } = ...`
  (drop `scaCarried`).
- In `backend/tests/scopeComponentService.test.ts`: remove the two
  `materializeRecoveredComponents — lockstep SCA recovery` tests (replace with a minimal
  test for the new synthesis function — see Tests).
- `TERMINAL_SCA_STATUSES` export in `scaAutoFix.ts`: it is still used by `scaAutoFix`
  itself. Keep it exported (harmless single-source) OR revert to a local `const` if no
  other module imports it after this change. Either is fine; prefer keeping it exported
  and used by the synthesis filter if relevant.
- **KEEP** `backfillReopenFalseFixedScaIssues` in `worker.ts` — it heals historical bad
  data and is still needed.

### 4. Docs
- **CLAUDE.md**: update the M7 two-table-model note. Change the invariant from
  *"`sbom_components` = per-scan, immutable audit of direct observations"* to
  *"`sbom_components` = all components this scan believes present, tagged by
  `discoveryMethod` (`manifest` | `vendored_inspection` | `recheck_recovery`); the
  vulnerability-lookup stage consumes the SBOM whole and never branches on
  `discoveryMethod`."* Remove/replace the "OSV/NVD run against direct-observation
  components only" wording. In the SCA auto-fix sweep note (added in 0.24.0), replace the
  "lockstep carry-forward" description with: recovered components flow into the SBOM and
  are re-queried by OSV/NVD like any other component, so the sweep can't false-fix them;
  `backfillReopenFalseFixedScaIssues` heals pre-0.24.0 data.
- **docs/PROGRESS.md**: update the 0.24.0 entry — the fix is now the SBOM-stage-contract
  realignment (recovered components flow into the SBOM; provenance-blind vuln lookup),
  superseding the lockstep approach; backfill heal retained. Note no version re-bump.

### 5. No schema migration
`discoveryMethod` already exists on `sbom_components` (nullable free-text String). Do NOT
add a migration.

## Tests (the test subagent will own end-to-end; implementer adds unit coverage)
- Unit: `synthesizeRecoveredSbomComponents` inserts one `sbom_components` row per recovered
  scope_component with `discoveryMethod="recheck_recovery"` and the copied identity fields;
  `skipDuplicates` honored; empty input → no-op `{ inserted: 0 }`.
- Keep all existing suites green: `pnpm test` (was 589 after 0.24.0; will change by the
  removed lockstep tests + new synthesis test).
- `pnpm exec tsc --noEmit -p tsconfig.json` clean.

## Verification (run in-container; host can't run vitest)
- Backend `pnpm test` + `tsc` green; frontend `tsc` green (no FE change expected).
- Optional empirical: trigger a scan on a scope with a known recovered component (e.g. FSS
  `extern/Cuda`) and confirm via DB that after the scan: (a) a `sbom_components` row exists
  for cuda-runtime with `discovery_method='recheck_recovery'` on the new scan, and (b) its
  `sca_issues` have `last_seen_scan_run_id = <new scan>` and are NOT `fixed`.

## Constraints
- Async/await; Zod/Prisma conventions; no `any` outside boundary adapters.
- Do NOT push, merge, tag, or deploy. Do NOT bump the version (stays 0.24.0).
- Commit is left to the reviewing (parent) agent — implementer leaves changes in the
  working tree with tests + tsc green and reports a summary + the list of files touched.
