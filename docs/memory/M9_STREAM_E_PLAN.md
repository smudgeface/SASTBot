# M9 Stream E — File-first scan artifact pipeline

> **Status:** plan, awaiting implementation. No code changes yet.
> **Scope:** architectural refactor of the SBOM and SAST scan pipelines so the artifact files (SBOM, SARIF) are the canonical immutable record of what each scan observed, and the per-scan DB tables are populated *from* those files.
> **Trigger:** 2026-05-22 closure-gate finding — the current per-scan SBOM (served by `/scans/:id/sbom`) is ~94% recheck-recovery rows on the test FSS scan, mixing "what this scan observed" with "what got inherited from prior scope state". The user's design principle: the per-scan artifact should reflect *direct observation only*; recheck/recovery is a scope-level concern.
> **Companion:** [M9 Stream B plan](M9_STREAM_B_PLAN.md) shipped the artifact-file infrastructure; Stream E flips the *direction of truth* so the file becomes the source rather than a derived view.

---

## 1. Motivation

The closure-gate session of 2026-05-22 verified the new per-scan SBOM endpoint works. While doing so it surfaced this query against the FSS test scan:

```
SELECT discovery_method, COUNT(*) FROM sbom_components
WHERE scan_run_id = '069a7f97-...' GROUP BY discovery_method;
 discovery_method | count
------------------+-------
 recheck_recovery |    30
 manifest         |     2
```

Of the 32 components the scan's SBOM file contains, only 2 came from this scan's direct observations (cdxgen + LLM augmentation). The other 30 were pulled in from prior scope state by the `materializeRecoveredComponents` step that runs after the LLM SBOM recheck verdicts. The file labeled "this scan's SBOM" is mostly inherited from scope history.

The same architectural conflation underlies several known issues:

- **Issue 1** (`scan_runs.component_count` denorm staleness) — written once by `persistAugmentedComponents`, then `sbom_components` keeps growing via downstream phases. The denorm goes stale on recheck recovery.
- **Issue 5** (scan vs scope SBOM divergence after merges) — scan-page SBOM has stale rows the recheck-merge already collapsed at the scope level. The two endpoints disagree by the merge delta.
- **Issue 7** (stale `ALLOWED_PHASES` allowlist) — orthogonal but compounds the visibility cost.

Each of these is a symptom of "multiple write paths into `sbom_components` for the same scan_run_id." The file-first invariant collapses to a single write path and the symptoms dissolve.

---

## 2. The file-first invariant

```
LLM analysis (in memory)
    │
    ▼
Artifact file emitted to ${ARTIFACT_DIR}/{sbom,sarif}/<scanRunId>.{json,sarif.json}
    │
    ▼  (← the file is the canonical, immutable record of what THIS scan observed)
DB ingest reads the file and populates per-scan tables (sbom_components, sast_issues w/
lastSeenScanRunId=this scan). The per-scan tables become derived index of the file.
    │
    ▼
Scope-update phases (persistScopeState, llm_*_recheck, materializeRecoveredComponents,
rebuildComponentsFromScopeState) operate on scope-level tables (scope_components and
sast_issue lifecycle fields) ONLY. They never touch the per-scan tables.
```

**Three rules:**

1. **File-first emit.** The artifact file is written from the in-memory LLM-augmented (or LLM-detected) record list. No DB read in the emit path.
2. **DB derives from file.** Per-scan tables (`sbom_components`, `sast_issues.lastSeenScanRunId=this scan`) are populated by an ingest step that reads the just-emitted file. The file is the canonical reference; if the DB and file ever disagree, the file wins.
3. **Scope update is scope-only.** Anything that runs after ingest — recheck verdicts, merges, recovery — mutates scope-level tables (`scope_components`, scope-level `sast_issue` triage state). It never mutates per-scan tables. Per-scan tables become immutable post-ingest.

**Cascade benefits:**

- Per-scan SBOM file = direct observation only (matches operator mental model).
- Scope-level SBOM file = integrated truth (post-recheck, post-merge).
- `scan SBOM ≤ scope SBOM` always, by exactly the recheck-recovery delta.
- `componentCount` denorm written once at ingest, never goes stale.
- Future external-upload flow (Stream B7, source=upload) uses the same pipeline as cdxgen — both go through `sbom_emit → sbom_ingest`. The `sbom_ingest` phase that B2 stubbed as a no-op for cdxgen becomes load-bearing for both sources.

---

## 3. Cross-commit sequencing

Two commits, ordered:

```
┌──────────────────────────┐
│ Commit 1: SBOM file-first│  v0.8.1 → v0.9.0  (MINOR — operator-visible:
│                          │   per-scan SBOM endpoint now returns direct
│                          │   observations only; was including recheck-recovery)
│                          │
│   ⏸ Verify: trigger      │
│   one scan; confirm      │
│   /scans/:id/sbom shows  │
│   only manifest +        │
│   llm_augmentation rows  │
│   (no recheck_recovery). │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ Commit 2: SAST file-first│  v0.9.0 → v0.9.1  (PATCH — internal refactor;
│                          │   no operator-visible content change since
│                          │   today's SARIF already filters to this scan's
│                          │   findings. The change is the implementation:
│                          │   in-memory buffer → emit → ingest instead of
│                          │   stream-and-regenerate.)
└──────────────────────────┘
```

Each commit is independently shippable and independently verifiable. The SBOM commit is the higher-impact one (changes endpoint content); the SAST commit aligns the SAST half with the new architecture so future maintenance has a single pattern.

---

## 4. Stream E1 — SBOM file-first refactor

### 4.1 Current shape (post-M9 Stream B)

```
cdxgen (shells out, in-memory CdxComponent[])
  → Stage-1 mechanical clean (in-memory)
  → llm_sbom phase: LLM SBOM augmentation (in-memory, via claude-p)
  → applySbomAugmentation → in-memory finalComponents: CdxComponent[]
  → ★ persistAugmentedComponents(scanRunId, finalComponents, ...)
        — writes sbom_components rows (discoveryMethod: "manifest" | "llm_augmentation")
        — writes scan_runs.componentCount = finalComponents.length
  → persistScanComponentsToScopeState(...)
        — upserts scope_components, writes scan_run_components join rows
  → llm_sbom_recheck phase: LLM judges scope-level changes
  → materializeRecoveredComponents(scanRunId)
        — for each scope_component the recheck verdict marked "still_present" but isn't
          in this scan's sbom_components yet → INSERTS a new sbom_components row with
          discoveryMethod="recheck_recovery"  ← THIS is the row inflation
  → rebuildComponentsFromScopeState(scanRunId)
        — additional sbom_components mutations (audit row reconciliation)
  → sbom_emit phase: emitSbomArtifact(scanRunId)
        — reads sbom_components for scanRunId → builds CycloneDX 1.7 doc → writes file
  → sbom_ingest phase (no-op for cdxgen flow today)
  → osv / nvd / eol / llm_detection / llm_recheck / sarif_emit / ...
```

### 4.2 Target shape

```
cdxgen
  → Stage-1 clean
  → llm_sbom (in-memory augmentation)
  → applySbomAugmentation → in-memory finalComponents: CdxComponent[]
  → ★ sbom_emit phase
      buildAugmentationSbom(finalComponents, sbomEvidenceMap, sbomCpeMap, sbomIdentityMap,
                            scanDir, scopePath, scanRunId, scopeId)
      → CycloneDX 1.7 doc (in memory)
      → writeArtifact(sbomPathFor(scanRunId), stableStringify(doc))
  → ★ sbom_ingest phase (now load-bearing for source=cdxgen)
      ingestSbomFromArtifact(scanRunId)
      → reads file → parses CycloneDX → upserts sbom_components rows
      → sets scan_runs.componentCount = components.length (the FILE's count)
      → discovery_method is read from the per-component property "sastbot:discovery_method"
        in the file (so the round-trip preserves it).
        Only "manifest" and "llm_augmentation" exist at this point.
  → persistScanComponentsToScopeState (unchanged — propagates THIS scan's observations to
                                       scope_components)
  → llm_sbom_recheck (scope-level only — mutates scope_components, NOT sbom_components)
  → materializeRecoveredComponents (REFACTORED — scope-level only:
                                    bumps lastSeenScanRunId on the scope_components rows
                                    the recheck judged "still_present"; does NOT write to
                                    sbom_components anymore)
  → rebuildComponentsFromScopeState (REFACTORED — scope-level only; no sbom_components writes)
  → osv / nvd / ...
```

### 4.3 New code

**`backend/src/services/sbomCurated.ts`** — add a new function alongside the existing `buildCuratedSbomJson(scanRunId)` (which builds from DB rows):

```ts
/**
 * Build the canonical CycloneDX 1.7 document from the in-memory post-augmentation
 * component list, WITHOUT touching the DB. This is the source of truth for the
 * per-scan SBOM file written by sbom_emit.
 *
 * Output is stable-stringified for ETag determinism (same input → same bytes).
 */
export function buildAugmentationSbom(input: {
  scanRunId: string;
  scopeId: string;
  scopePath: string;
  scanDir: string;
  components: CdxComponent[];          // post-augmentation final list
  sbomEvidenceMap: Map<string, SbomEvidence>;
  sbomCpeMap: Map<string, string>;
  sbomIdentityMap: Map<string, IdentitySources>;
  startedAt?: Date | null;
}): CuratedSbomDoc { ... }
```

Per-component properties to roundtrip via CycloneDX `properties[]`:

- `sastbot:discovery_method` = `"manifest" | "llm_augmentation"` (never `"recheck_recovery"` at this point — that comes later, scope-level only)
- `sastbot:component_root` (if present)
- `sastbot:is_dev_only` = `"true"` (if true; omit otherwise — false is the default)
- `sastbot:llm_evidence` = JSON-stringified `{path, excerpt, llmReason}` (if augmentation provided it)
- (anything else `persistAugmentedComponents` currently writes to `sbom_components` fields)

**`backend/src/services/sbomIngest.ts`** — extend the existing file (currently has the upload-flow skeleton) with the cdxgen-flow ingest:

```ts
/**
 * Read ${ARTIFACT_DIR}/sbom/<scanRunId>.json and populate sbom_components rows.
 * Idempotent: clears any existing rows for this scanRunId before insert.
 * Also writes scan_runs.componentCount from the file's component count.
 *
 * Used by both source=cdxgen (after sbom_emit writes the file in the new pipeline)
 * and source=upload (operator-uploaded SBOM, Stream B7 future work).
 */
export async function ingestSbomFromArtifact(scanRunId: string): Promise<void> { ... }
```

Implementation outline:
1. Read file via `tryReadArtifact(sbomPathFor(scanRunId))`. If missing → throw clear error (worker will record `sbom_ingest_failed` warning).
2. Parse as CycloneDX 1.7 doc.
3. In a transaction:
   - `tx.sbomComponent.deleteMany({ where: { scanRunId } })` (idempotency — re-running on the same file produces the same row set).
   - `tx.sbomComponent.createMany({ data: [...components mapped from doc.components...] })` with `skipDuplicates: true` (the `(scanRunId, purl)` unique index backstops bad data).
   - `tx.scanRun.update({ where: { id: scanRunId }, data: { componentCount: doc.components.length } })`.
4. The discovery_method, component_root, is_dev_only, llm_evidence, etc. fields are read from `sastbot:*` properties on each CycloneDX component.

### 4.4 Worker reorder

In `backend/src/worker.ts`, the SBOM section currently around lines 1300–1565 (post-cdxgen, pre-OSV) is the change site.

Replace the existing flow:

```ts
// OLD (delete):
let components = await prisma.$transaction(async (tx) => {
  await tx.scanRun.update({ where: { id: scanRunId }, data: { componentCount: finalComponents.length } });
  return persistAugmentedComponents(scanRunId, finalComponents, sbomEvidenceMap, tx, scanDir, scopePath, sbomCpeMap, sbomIdentityMap);
});
// ... persistScanComponentsToScopeState ...
// ... llm_sbom_recheck ...
// ... materializeRecoveredComponents ...
// ... rebuildComponentsFromScopeState ...
await setPhase(scanRunId, "sbom_emit");
const emitResult = await emitSbomArtifact(scanRunId).catch(...);
await setPhase(scanRunId, "sbom_ingest");
// (no-op for cdxgen)
```

With:

```ts
// NEW:
await setPhase(scanRunId, "sbom_emit");
const sbomDoc = buildAugmentationSbom({
  scanRunId, scopeId, scopePath, scanDir,
  components: finalComponents,
  sbomEvidenceMap, sbomCpeMap, sbomIdentityMap,
  startedAt: scanRun?.startedAt ?? null,
});
const sbomBody = stableStringify(sbomDoc, 2);
try {
  await writeArtifact(sbomPathFor(scanRunId), sbomBody);
} catch (err) {
  await appendWarning(scanRunId, { code: "sbom_emit_failed", severity: "error", message: ... });
}

await setPhase(scanRunId, "sbom_ingest");
try {
  await ingestSbomFromArtifact(scanRunId);  // populates sbom_components + componentCount from the file
} catch (err) {
  await appendWarning(scanRunId, { code: "sbom_ingest_failed", severity: "error", message: ... });
}
// At this point sbom_components has manifest + llm_augmentation rows only.

const components = await prisma.sbomComponent.findMany({ where: { scanRunId } });
await persistScanComponentsToScopeState({ scanRunId, scopeId, components, ... });

// llm_sbom_recheck phase — UNCHANGED (it only operates on scope_components)

await setPhase(scanRunId, "llm_sbom_recheck");
const recheckResult = await runSbomRecheck(...);

// REFACTORED: scope-only versions
await materializeRecoveredComponents_scopeOnly(scanRunId, recheckResult);
await rebuildComponentsFromScopeState_scopeOnly(scanRunId);

// OSV / NVD / EOL — still operates on sbom_components (which is now correctly scoped to direct observations)
```

### 4.5 Refactor `materializeRecoveredComponents` and `rebuildComponentsFromScopeState`

Both currently write to `sbom_components`. Audit the call sites:

```bash
rg -n 'sbomComponent\.create|sbomComponent\.upsert|INSERT.*sbom_components' backend/src
```

Every write into `sbom_components` outside `ingestSbomFromArtifact` must go away. The two functions:

- **`materializeRecoveredComponents`** — instead of inserting a `sbom_components` row for each "still_present"-verdicted scope_component, update the scope_component's `lastSeenScanRunId = scanRunId`. That's the only side-effect this function should have after E1.
- **`rebuildComponentsFromScopeState`** — its job was to reconcile per-scan audit rows after the recheck merges/dedups. After E1, the per-scan audit (sbom_components) is frozen at ingest time. Anything reconciling scope state stays in scope_components (or scan_run_components join rows). Read the function carefully and identify which lines need to move target tables; everything else stays the same.

The OSV / NVD / EOL phases that read `sbom_components.findMany({where: {scanRunId}})` will now see ONLY direct observations. That's the correct semantic: scan-level CVE matching against direct observations, scope-level state inherits via the existing scope_components → ScaIssue path.

### 4.6 Tests

New `backend/tests/sbomFileFirst.test.ts`:

1. **Serialize → ingest round-trip** — build a `CdxComponent[]` with all the SASTBot-specific augmentation metadata, call `buildAugmentationSbom`, write to disk, call `ingestSbomFromArtifact`, assert `sbom_components` rows match input shape exactly (purl, discoveryMethod, componentRoot, isDevOnly, llmEvidence).
2. **Idempotency** — call `ingestSbomFromArtifact` twice on the same file; assert same rows, no duplicates.
3. **componentCount written from file** — assert `scan_runs.componentCount` matches the file's component count post-ingest.
4. **No recheck_recovery rows post-pipeline** — set up a scenario where the recheck verdict would have written a recheck_recovery row pre-E1; after E1 assert `sbom_components` has zero such rows for this scan_run. (May need to mock the recheck phase.)

Extend `backend/tests/sbomEmit.test.ts` — if it still exercises `emitSbomArtifact(scanRunId)` (the DB-reading variant), keep that test for backwards-compat and add equivalents using `buildAugmentationSbom`.

### 4.7 Version bump

0.8.1 → 0.9.0 in all four canonical files (`backend/package.json`, `frontend/package.json`, `frontend/package-lock.json` top-level + nested, `backend/src/routes/version.ts` `APP_VERSION`). MINOR because the per-scan SBOM endpoint's *content* changes (recheck-recovery rows disappear) — that's operator-visible.

### 4.8 Deliverables checklist (E1)

- [ ] New `buildAugmentationSbom` in `sbomCurated.ts`
- [ ] New `ingestSbomFromArtifact` in `sbomIngest.ts` (cdxgen-flow path; the upload-flow stub already exists)
- [ ] Worker SBOM phase block reordered (sbom_emit → sbom_ingest → persistScope → recheck → ...)
- [ ] Delete `persistAugmentedComponents` (or repurpose if its in-memory normalization helpers are still needed — keep the helpers, drop the DB writes)
- [ ] `materializeRecoveredComponents` no longer writes to sbom_components — only updates scope_components.lastSeenScanRunId
- [ ] `rebuildComponentsFromScopeState` no longer writes to sbom_components — scope-only side effects
- [ ] Tests: serialize↔ingest round-trip, idempotency, componentCount from file, no recheck_recovery rows in sbom_components
- [ ] Version bump 0.8.1 → 0.9.0
- [ ] `docs/M9_POST_B_FOLLOWUPS.md` — mark Issues 1 and 5 as **DISSOLVED by Stream E** (already done in this plan-doc commit)
- [ ] `docs/PROGRESS.md` entry for Stream E1
- [ ] CLAUDE.md "For AI agents" pin removed (handled by the Stream E2 commit, since E1 alone doesn't close the milestone)

---

## 5. Stream E2 — SAST file-first refactor

### 5.1 Current shape

```
llm_detection phase
  → spawnClaudeAndStream yields SastRecords / SastAbsenceRecords / ReachabilityRecords
  → for each streamed sast record:
       upsertSastIssueFromDetection(...) — writes to sast_issues immediately
  → llm_recheck phase
  → apply recheck verdicts (still_present, fixed, file_deleted, duplicate_of) to sast_issues
  → ★ regenerateSastSarifForScan(scanRunId, scopeId, scopePath)
        — reads sast_issues where lastSeenScanRunId=scanRunId
        — builds SARIF
        — writes file via writeArtifact (B4 dual-write removed; just disk now)
```

Today's SARIF file already represents only THIS scan's findings (filtered by `lastSeenScanRunId=scanRunId`). So the operator-visible content doesn't change in E2. What changes is the *implementation direction*: emit before ingest, never re-emit after recheck.

### 5.2 Target shape

```
llm_detection
  → spawnClaudeAndStream yields records into an in-memory buffer
  → at stream end: detectionRecords: SastRecord[], absenceRecords: SastAbsenceRecord[],
                   reachabilityRecords: ReachabilityRecord[]
  → ★ sarif_emit phase (moved earlier)
      buildSastSarifFromDetection({
        records: detectionRecords,
        absences: absenceRecords,
        scanRunId, scopeId, scopePath, scopeDir,
        startedAt, endedAt,
        snippetReader: (file, startLine, endLine) => ... build from disk,
      })
      → SARIF v2.1.0 doc (in memory)
      → JSON.stringify(doc, null, 2)
      → writeArtifact(sarifPathFor(scanRunId), body)
  → ★ sast_ingest phase (NEW)
      ingestSastFromArtifact(scanRunId, scopeId, orgId)
      → reads SARIF file
      → for each result: upsert sast_issues (with lastSeenScanRunId=scanRunId)
      → idempotent: re-running on same file produces same row set
  → reachability records — handled separately (they update sca_issues, not sast_issues;
                          today these go through a different path; preserve that path)
  → llm_recheck phase (operates on sast_issues NOT seen this scan — i.e. lastSeenScanRunId != scanRunId)
  → apply recheck verdicts to sast_issues triage status (fixed, duplicate_of, file_deleted)
        — these are LIFECYCLE mutations on scope-level rows
        — do NOT re-emit SARIF
```

### 5.3 New code

**`backend/src/services/sarifService.ts`** (or whichever file currently hosts `buildSarifFromIssues`):

```ts
/**
 * Build a SARIF v2.1.0 document directly from in-memory detection records,
 * WITHOUT touching the DB. The source of truth for the SARIF file written by
 * the sarif_emit phase.
 */
export function buildSastSarifFromDetection(input: {
  records: SastRecord[];               // streamed from llm_detection
  absences: SastAbsenceRecord[];
  scanRunId: string;
  scopeId: string;
  scopePath: string;
  scopeDir: string;
  toolVersion: string;                 // APP_VERSION
  modelName: string;
  startedAt?: Date | null;
  endedAt?: Date | null;
  /** Reads a SOURCE_CONTEXT_LINES-canonical snippet from disk for a finding. */
  snippetReader?: (filePath: string, startLine: number, endLine: number | null) => Promise<{ text: string; firstLine: number } | null>;
}): SarifDocument { ... }
```

This mirrors `buildSarifFromIssues` (which queries DB) but reads from in-memory records. Reuses the same SARIF emitter helpers under the hood.

**`backend/src/services/sastIngest.ts`** (new file):

```ts
/**
 * Read ${ARTIFACT_DIR}/sarif/<scanRunId>.sarif.json and upsert sast_issues rows.
 * Sets lastSeenScanRunId=scanRunId on every matched issue.
 *
 * For NEW issues (no prior fingerprint match in this scope) → creates the row.
 * For EXISTING issues (fingerprint matches an existing sast_issues row in this
 * scope) → updates latest* denorm fields + bumps lastSeenScanRunId.
 *
 * Idempotent. Mirrors upsertSastIssueFromDetection's semantics but reads from
 * the SARIF file instead of the streamed records.
 */
export async function ingestSastFromArtifact(input: {
  scanRunId: string;
  scopeId: string;
  orgId: string | null;
  scopeDir: string;     // for snippet reads
  scopePath: string;    // for repo-relative path normalization
}): Promise<{ inserted: number; updated: number }> { ... }
```

### 5.4 Delete `regenerateSastSarifForScan`

After E2, the SARIF file is emitted exactly once per scan, immediately after `llm_detection`. It is never rewritten. The post-recheck regeneration step was needed because recheck verdicts could mutate the rendered SARIF — but recheck only changes triage status of existing rows (not the detection set), and SARIF's `result[]` shouldn't reflect triage state per the SARIF §3.27.23 split between producer and RMS concerns (CLAUDE.md M6j note).

Delete:
- `regenerateSastSarifForScan` function
- All its call sites
- The `backfillSastSarif` boot hook reference (already gone post-Deploy 3, but double-check)

### 5.5 Worker reorder

In `backend/src/worker.ts`, the SAST section (currently around lines 260–620). The changes:

1. `llm_detection` streams into in-memory buffer (instead of upserting row-at-a-time).
2. After stream ends, fire `sarif_emit` phase (writes file from buffer).
3. New phase `sast_ingest` fires next (parses file → upserts sast_issues).
4. `llm_recheck` unchanged in scope; operates on the post-ingest sast_issues set.
5. Recheck verdicts applied via the existing path (mutates triage status only).
6. Delete the old `regenerateSastSarifForScan(scanRunId, scopeId, scopePath)` call site at end of SAST flow.

### 5.6 Worker phase enum updates

The plan adds one new value: `sast_ingest`. Three places to update:

- `backend/src/schemas.ts:430-436` — Zod `current_phase` enum.
- `backend/src/services/mappers.ts:44-47` — `ALLOWED_PHASES` allowlist (also fixes part of Issue 7; the rest of Issue 7 still needs the bulk update).
- `frontend/src/api/types.ts` `SCAN_PHASE_LABELS` map.

`sast_ingest` should render as something like "Indexing SAST findings" in the UI.

### 5.7 Tests

New `backend/tests/sastFileFirst.test.ts`:

1. **Serialize → ingest round-trip** — build `SastRecord[]` with all field shapes (including the post-Stream-fix aliases handled by the schema), call `buildSastSarifFromDetection`, write to file, call `ingestSastFromArtifact`, assert `sast_issues` rows match.
2. **Idempotency** — call ingest twice; assert same row set, no duplicate fingerprints.
3. **`lastSeenScanRunId` is set on every matched issue.**
4. **Re-ingest after recheck doesn't happen** — assert there's no code path that calls `ingestSastFromArtifact` more than once per scan.

### 5.8 Version bump

0.9.0 → 0.9.1 in all four files. PATCH because the SARIF endpoint content doesn't change (already reflected only this scan's findings); the change is internal refactor.

### 5.9 Deliverables checklist (E2)

- [ ] New `buildSastSarifFromDetection` in `sarifService.ts` (alongside existing `buildSarifFromIssues`)
- [ ] New `backend/src/services/sastIngest.ts` with `ingestSastFromArtifact`
- [ ] Worker SAST phase block reordered: `llm_detection (buffered) → sarif_emit → sast_ingest → llm_recheck → apply verdicts`
- [ ] Delete `regenerateSastSarifForScan` + call sites
- [ ] Phase enum: add `sast_ingest` to Zod schema + mappers allowlist + frontend label map
- [ ] Tests: SAST serialize↔ingest round-trip, idempotency, lastSeenScanRunId set, no SARIF re-emit
- [ ] Version bump 0.9.0 → 0.9.1
- [ ] `docs/PROGRESS.md` entry for Stream E2
- [ ] CLAUDE.md "For AI agents" pin for Stream E removed in this commit (the closure trigger)

---

## 6. Followups cascade

After Stream E ships, the following entries in `docs/M9_POST_B_FOLLOWUPS.md` become moot:

- **Issue 1** (`component_count` denorm staleness) — written once at ingest from the file's count, never updated thereafter. The denorm is structurally aligned with the file.
- **Issue 5** (scan SBOM vs scope SBOM divergence) — scan SBOM is now direct-observation-only, scope SBOM is integrated truth. They're allowed to differ; the user-facing framing is "scan page = audit, scope page = current truth" without any merge-delta surprise.

Issue 7 (stale `ALLOWED_PHASES` allowlist) is *not* dissolved but is *expanded*: E2 adds `sast_ingest` as a new phase. The post-Deploy-3 followups cleanup commit (which will handle Issue 7 as a bulk fix) needs to account for the new phase value. Update the followups doc in the plan-doc commit to reflect this.

Issues 2, 6, 8, 9, 10, 11 are unaffected by Stream E.

---

## 7. Test strategy summary

E1 + E2 each ship with unit tests covering the new emit + ingest path. Closure-gate-style verification is the responsibility of the gate run that resumes AFTER Stream E lands — that test plan already exists at `docs/M9_E2E_TEST_PLAN.md` §4 Phase 1 ("artifact files written + diff scope vs scan SBOMs"). After E1 ships, the scope-vs-scan diff should show: scope ≥ scan, where the delta is exactly the recheck-recovery row count for that scan. Add a Phase 1.5b assertion to that effect.

---

## 8. Open questions

**E1-Q1: should the `buildAugmentationSbom` function ALSO be used by the future external-upload flow (source=upload), or does upload go through a different path?**

For source=upload, the operator uploads an arbitrary CycloneDX file. The file IS already the source of truth — no `buildAugmentationSbom` step needed; the worker just calls `ingestSbomFromArtifact(scanRunId)` directly. So `buildAugmentationSbom` is cdxgen-flow-specific. `ingestSbomFromArtifact` is shared between both flows. That answers the question.

**E2-Q1: what happens to reachability records (the `kind: "reachability"` LLM output) under file-first?**

Reachability records update `sca_issues` (SCA-issue reachability fields), not `sast_issues`. They're emitted by the same `llm_detection` LLM session that produces SAST records. Two options:

- (a) Include reachability data in the SARIF file as a custom property/extension, ingest from there. Adds non-standard SARIF content.
- (b) Keep reachability records on a separate in-memory buffer, processed at the same point as the SAST ingest but writing to `sca_issues` directly. SARIF file stays standard.

**Recommended: (b).** SARIF should stay standard. Reachability is a SCA concern, not a SAST one — the fact that the same LLM session emits both is an implementation detail. The worker can hold reachability records in a separate buffer and apply them after `sast_ingest` finishes.

---

## 9. Deliverables summary

| Commit | Branch / PR | Version | Touches |
|---|---|---|---|
| E1 | `m9-stream-e1-sbom-file-first` | 0.8.1 → 0.9.0 | `sbomCurated.ts`, `sbomIngest.ts`, `worker.ts` (SBOM block), `scopeComponentService.ts` (`materializeRecoveredComponents`, `rebuildComponentsFromScopeState`), new test file, **4-file version bump**, followups doc (mark 1, 5 dissolved), PROGRESS.md |
| E2 | `m9-stream-e2-sast-file-first` | 0.9.0 → 0.9.1 | `sarifService.ts`, `sastIngest.ts` (new), `worker.ts` (SAST block + phase enum), `schemas.ts`, `mappers.ts`, `frontend/src/api/types.ts`, new test file, **4-file version bump**, delete `regenerateSastSarifForScan`, PROGRESS.md, CLAUDE.md (remove Stream E pin) |
