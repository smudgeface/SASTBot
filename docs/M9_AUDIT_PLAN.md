# M9 — Scopes-feature audit & implementation plan

> **Status:** audit + plan only. **No code changes in this milestone yet.** This document captures findings against an architectural target the user articulated on 2026-05-22 and proposes a dependency-ordered implementation plan to close the gaps.

---

## 1. Architectural target

The user wants the following to be true of the scopes feature:

1. **Scope-page UI is driven exclusively by scope-level DB tables.**
   The scope detail page (`/scopes/:id`) and the scope list (`/scopes`) read **only** from:
   - `scope_components` (durable scope-level component truth set)
   - `sast_issues`, `sca_issues` (scope-level issue truth sets)
   - `scan_scopes` (scope state + denormalised severity counts + `lastScanRunId`)
   - Cross-domain helpers (`jira_tickets`)
   - A small allowance for `scan_runs` to surface "is there a scan running now?" status (an *operational* read, not a data read)

   Reading from scan-level data tables (`sbom_components`, `scan_findings`, `sast_findings`, `scan_run_components`, `scan_runs.sbom_json`, `scan_runs.sast_sarif`) for scope-page display is a **bug**.

2. **The SBOM downloaded from the scope page is deterministic.**
   Two downloads of the same scope's SBOM must be **byte-identical** unless a scan happened between them. No LLM call in the download path. No non-deterministic ordering. No freshly-minted UUIDs or timestamps generated at request time.

3. **Scan flow is artifact-centric.**
   The pipeline should be: SCA → canonical CycloneDX file on disk; SAST → canonical SARIF file on disk. Files are the source of truth and survive without regeneration. Files are then ingested into scan-level DB tables. Scan-level tables then update scope-level tables (the merge/dedup logic that already exists). Eventually (do not build yet) a "scan" should be creatable by uploading an external SBOM/SARIF file.

---

## 2. Findings — what violates the target

### F1 — `GET /api/scopes/:id/sbom-json` reads the scan-level `sbom_components` table

**Where:** `backend/src/routes/scopes.ts:989–1028` → `backend/src/services/sbomCurated.ts:78–175`.

The endpoint resolves `scope.lastScanRunId` then calls `buildCuratedSbomJson(scanRunId)`, which queries `prisma.sbomComponent.findMany({ where: { scanRunId } })` (sbomCurated.ts:93–96). `sbom_components` is the per-scan immutable audit table — exactly the kind of read the target forbids. CLAUDE.md already flags this as a known gap ("Raw vs curated SBOM endpoints (M6q review #15)").

**Operator-visible consequence:** the downloaded SBOM **does not reflect operator edits to scope_components** — renamed components, manual evidence, dedupes, soft-deleted rows are all invisible in the SBOM JSON. The Components tab and the SBOM viewer can show inconsistent data.

**Fix posture:** rebuild the curated SBOM from `scope_components` (joined to `repos` for the metadata header). The Components tab already does this — the SBOM builder should follow the same source.

### F2 — Curated SBOM has determinism gaps even without source-table changes

**Where:** `backend/src/services/sbomCurated.ts`.

- **F2.a — Missing `orderBy` tiebreaker.** Line 95: `orderBy: [{ ecosystem: "asc" }, { name: "asc" }]`. Two rows with identical `ecosystem + name` (different version, different purl) have undefined order. The `(scanRunId, purl)` unique index doesn't help — the query result order isn't constrained by it.
- **F2.b — `occurrences[]` array order not stable.** Lines 126–131: each component's `evidence.occurrences` is mapped straight out of the JSONB column with no sort. Order is whatever `sbomOccurrences.ts` happened to insert; LLM-driven phases (recheck, SBOM augmentation) can change insertion order across runs even when the underlying set is identical. Today this still produces a stable byte sequence *within* a scan run (the column is set once), but the moment the artifact migration writes the SBOM from a freshly-derived source, this becomes a real source of drift.
- **F2.c — `licenses[]` array order not sorted** (line 109). Same problem class as occurrences — currently stable because the column is set once at insert, but a per-download rebuild would expose ordering drift if license arrays are ever re-derived.
- **F2.d — `properties[]` insertion order is "stable by accident".** Lines 135–149 push properties conditionally in source-code order. Any future refactor that reorders the `if` blocks changes the JSON bytes. This is a maintainability hazard, not a current bug.
- **F2.e — No ETag / Last-Modified header.** scopes.ts:1023–1026. Clients have no efficient way to detect change.

**Not a bug (flagging as confirmed):**

- `metadata.timestamp = (run.finishedAt ?? run.createdAt).toISOString()` (sbomCurated.ts:160) is deterministic per scan run — `finishedAt` is write-once.
- `serialNumber: urn:uuid:${run.id}` (sbomCurated.ts:157) uses the scan run ID, not a freshly-generated UUID.
- Both will need a new identity when the SBOM source switches to `scope_components` — see Open Questions Q3.

### F3 — Scan-flow blobs live in JSONB columns, not as durable files

**Where:**
- Raw cdxgen SBOM: written to `scan_runs.sbom_json` (JSONB) at `worker.ts:1382`.
- SARIF: written to `scan_runs.sast_sarif` (JSONB) at `worker.ts:582`; backfilled at `worker.ts:880–912`.
- Post-Stage-2 augmented SBOM (the "after the LLM trimmed/added things" view): **not persisted as a single document anywhere.** It exists in-memory during the worker run and is then scattered across individual `sbom_components` rows. There is no canonical "augmented SBOM file" today.

**Operator-visible consequence:** the scan-detail SBOM viewer serves the **pre-augmentation** raw cdxgen JSON (per the M6q split documented in CLAUDE.md). Audit trail is intact, but the post-curation artifact isn't a portable file — it only exists as a database derivation. This blocks the eventual "upload an external SBOM file" feature (no symmetric file artefact to compare against) and forces every cross-version inspection to be a DB query rather than a `diff` on two files.

**Storage gap.** The compose stack defines only `sastbot_pgdata`, `sastbot_redisdata`, and `sastbot_repo_cache` (`docker/compose/docker-compose.yml:125–133`). There is no artifact volume.

### F4 — Worker phases are interleaved (LLM, DB writes, OSV, …) instead of file-emit → ingest

**Where:** `backend/src/worker.ts` processScan loop (the M6i `setPhase` chain — `clone → cdxgen → llm_sbom → osv → eol → llm_detection → llm_recheck → sca_summaries → finalizing`).

Today's flow (worker.ts):
1. cdxgen (in-memory CdxComponent[])
2. Stage-1 mechanical clean (in-memory)
3. LLM SBOM augmentation (in-memory) — claude-p reads a tmp file, emits JSONL
4. `persistAugmentedComponents` writes `sbom_components` rows + the **raw** cdxgen JSON to `scan_runs.sbom_json`
5. LLM SBOM recheck mutates rows
6. OSV/NVD/EOL — writes `scan_findings`
7. LLM SAST detection (in-memory records)
8. `persistDetection` writes `sast_findings` + `sast_issues`
9. LLM SAST recheck mutates rows
10. `buildSarifFromIssues` reads the now-final `sast_issues`, writes `scan_runs.sast_sarif`
11. SCA auto-fix / counters / finalising

The two artifact files the target wants (canonical CycloneDX, canonical SARIF) are derived **after** the merge logic that should ingest *from* them. The flow is "DB rows are primary, files are a side effect." Target is "files are primary, DB rows are ingested from files."

### F5 — `lastScanRunId` is the join key to all "latest" scope data, including the SBOM endpoint and the SARIF link

**Where:** scopes.ts:1015 (and several other places).

The scope page reaches scope-level data correctly for Components / SAST issues / SCA issues. But the SBOM endpoint (F1) and the SARIF viewer link on the scope page both anchor on `scope.lastScanRunId` to retrieve scan-level blobs. If artifacts move to disk (F3) keyed by scan run ID, the *scope page* will keep using `lastScanRunId` to find the file — which is fine for the SARIF (scan-output, immutable) but **inappropriate for the SBOM**, which the target wants derived from `scope_components` (operator-editable).

### F6 — `scope_components` has no notion of "latest manifest/version metadata" sufficient for SBOM derivation

**Verification needed during Stream C** (not blocking the audit). `scope_components` carries `name`, `version`, `purl`, `componentRoot`, `evidence[]`, `source`, `lifecycle`, `firstSeenScanRunId`/`lastSeenScanRunId`. It is missing fields that the current curated SBOM derives from `sbom_components`:

- `licenses` (string[]) — not on `scope_components` today
- `cpe` — not on `scope_components` today (lives on `sbom_components.cpe`)
- `discoveryMethod` — not on `scope_components`
- `isDevOnly` — *is* mirrored as `latestIsDevOnly` (per CLAUDE.md M6n)
- `llmEvidence` — not on `scope_components`
- `componentType` — partially, via `scope_components.type` (TBD on read)

**Implication:** porting the curated SBOM builder onto `scope_components` is not a one-line URL swap; some fields either need to be promoted onto `scope_components` during the scan → scope merge, or accepted as missing-from-SBOM, or read from the last `sbom_components` row keyed by component identity (which would still reach into scan-level data — defeating the goal). The cleanest answer is to promote the needed fields onto `scope_components` during merge.

### F7 — M8 restore tiering will need rework when artifacts move to disk

**Where:** `backend/src/services/restoreService.ts:52–81`.

`PRESERVE_BUCKET` (rows kept on `mode=runtime`) is admin-config: orgs, users, sessions, credentials, repos, app_settings, encryption_canary. `RESTORE_BUCKET` is everything scan-derived: `scan_scopes`, `scan_runs`, `sbom_components`, `scope_components`, `sast_issues`, `sca_issues`, `scan_findings`, `sast_findings`, `scan_run_components`, `jira_tickets`, `cve_knowledge`.

Today the SBOM and SARIF blobs travel inside `scan_runs` (a RESTORE row). Moving them to a server volume creates two problems:

- **Backup tarball:** must now also include the artifact directory, or backups become incomplete. `routes/adminBackup.ts` currently shells out to `pg_dump` only.
- **mode=runtime restore:** the schema-rename dance applies only to the DB schema. Artifact files on disk must be overlaid in parallel — restore the artifact set, drop any files newer than the dump's `exported_at` from the "after" snapshot, then resume.
- **mode=full restore:** simpler — wipe `/var/lib/sastbot/artifacts/` and re-extract from the backup tarball.

This is solvable but is **its own work stream**, not a side effect of the artifact migration.

---

## 3. Implementation plan

Streams are ordered by dependency, but A and D are independent of each other and can ship in either order. Stream C blocks on B in spirit (it's easier to migrate the SBOM source after the artifact pipeline emits the canonical doc), but is technically standalone — the migration can land first using `scope_components` directly.

### Stream A — Artifact storage on a server volume

**Goal:** introduce `sastbot_artifacts` named volume, mount into backend + worker, and define a stable on-disk layout for SBOM and SARIF files.

| Step | Detail |
|---|---|
| A1 | Add `sastbot_artifacts:/var/lib/sastbot/artifacts` to `docker/compose/docker-compose.yml` (backend + worker services, plus the named volume block). Same pattern as `sastbot_repo_cache`. |
| A2 | New `ARTIFACT_DIR` env var (default `/var/lib/sastbot/artifacts`), surfaced through `config.ts`. |
| A3 | New service `artifactStore.ts` with: `sbomPathFor(scanRunId)`, `sarifPathFor(scanRunId)`, `write(...)`, `read(...)`, `delete(...)`. Layout: `${ARTIFACT_DIR}/sbom/${scanRunId}.json` and `${ARTIFACT_DIR}/sarif/${scanRunId}.sarif.json`. Atomic write via `fs.rename` of a `.tmp` sibling. |
| A4 | Lifecycle: artifact files are deleted in lock-step with `scan_runs` rows. Add a Prisma `onDelete` mirror via the existing scan-delete service (`scanService.ts` already cascades to children — add a `deleteScanArtifacts(scanRunId)` call there). |
| A5 | Retention: keep all artifact files as long as the parent `scan_runs` row exists. There is no separate retention sweep — scan retention is already governed by app settings. |
| A6 | **M8 restore impact:** capture in a follow-up sub-plan (Stream A6 below). Until that lands, mode=runtime restore is internally consistent (no artifact references from PRESERVE rows) but will leave orphaned artifact files on disk for RESTORE rows that the dump didn't contain. Document this as a known gap until A6 ships. |

**M8 restore impact (sub-stream A6):**

| Step | Detail |
|---|---|
| A6.1 | Backup tarball: have `routes/adminBackup.ts` stream the artifact directory into the tarball alongside `pg_dump` output, under `artifacts/`. Update `BackupMetadata` to record the artifact file count + total bytes. |
| A6.2 | mode=full restore: clear `${ARTIFACT_DIR}/`, extract `artifacts/` from the tarball. Sequence after the DB restore so artifact files match the dumped scan_runs. |
| A6.3 | mode=runtime restore: after the runtime overlay transaction succeeds (`restoreService.applyRuntimeOverlay`), apply the artifact overlay — delete files whose `scanRunId` corresponds to a row that was just TRUNCATE'd from the live `public.scan_runs`, then restore files from the dump's `artifacts/` directory. Order matters: TRUNCATE happens inside the DB transaction; the file overlay runs after commit. A failure between the DB overlay and the artifact overlay leaves the DB authoritative — the operator can re-run the restore with the same dump. |
| A6.4 | Pre-flight: extend the existing FK check to include "every dump-side artifact file has a corresponding `scan_runs` row in the dump." Cheap because the dump's SQL is already on disk during the pre-flight phase. |

### Stream B — Refactor scan worker to emit files first, ingest second

**Goal:** make the canonical SBOM and SARIF the worker's *output*, with ingestion as a separate, idempotent pass that can also be run on an externally-uploaded file later.

| Step | Detail |
|---|---|
| B1 | New phase: `sbom_emit`. After Stage-2 LLM augmentation (`applySbomAugmentation` at worker.ts:1343), serialise the final augmented CdxComponent list + identity/CPE/evidence/llmEvidence maps into the canonical CycloneDX 1.7 doc and write to `artifactStore.sbomPathFor(scanRunId)`. **This is the new single source of truth** for "what the scan determined the SBOM to be." |
| B2 | New phase: `sbom_ingest`. Read the file back, populate `sbom_components` rows. Make this idempotent (re-running on the same file produces the same rows — the M7 `(scan_run_id, purl)` unique index already supports this). |
| B3 | OSV/NVD/EOL phases stay on `sbom_components` reads as today. The `sbom_components` table becomes the "indexed view" of the artifact file, not its origin. |
| B4 | New phase: `sarif_emit`. After SAST recheck completes (currently around worker.ts:555), build the final SARIF from the now-stable `sast_issues` rows and write to `artifactStore.sarifPathFor(scanRunId)`. Delete the `scan_runs.sast_sarif` JSONB column write — DB stops holding the blob. |
| B5 | Migration to drop `scan_runs.sbom_json` and `scan_runs.sast_sarif` columns. **Backfill first:** add a worker-boot backfill that, for every existing `scan_runs` row with non-null `sbom_json` / `sast_sarif`, writes the value to disk under the new layout. Same pattern as the existing `backfillSastSarif` (worker.ts:880). After backfill, run the column-drop migration. |
| B6 | The scan-detail page (`/scans/:id`) and its SBOM/SARIF viewer routes switch from "read JSONB column" to "stream file from artifactStore." Endpoints unchanged externally. |
| B7 | **Optional future-proofing (don't build, design for):** add a `source: 'cdxgen' | 'upload'` discriminator on `scan_runs` so the same ingest path can accept an external SBOM upload. The artifact file is the same shape either way; the only difference is whether `cdxgen` ran or the file came in via POST. |

### Stream C — Migrate the scope-level SBOM endpoint onto scope_components

**Goal:** close F1 + F6. The scope-page SBOM viewer + download should derive from `scope_components`, joined to `repos`/`scan_scopes`, with **no read of `sbom_components` or `scan_runs.sbom_json`**.

| Step | Detail |
|---|---|
| C1 | Schema change: promote the SBOM-relevant fields onto `scope_components`. Candidates: `latestLicenses` (string[]), `latestCpe` (text), `latestComponentType` (text), `latestDiscoveryMethod` (text), `latestLlmEvidence` (JSONB). All nullable. Migration adds the columns; backfill from the most-recent `sbom_components` row that matches each `scope_components` row via `componentMatch.ts` (read-only intersect). |
| C2 | Update `persistScanComponentsToScopeState` (the scan → scope merge) to also write these new "latest" fields on every UPDATE. Operator-edited rows (`source = 'manual_override'`) preserve operator values via `COALESCE`, same pattern as the existing `name` / `component_root` / `evidence` behaviour. |
| C3 | New function `buildCuratedSbomJsonForScope(scopeId)` in `sbomCurated.ts`. Reads `scope_components` (active lifecycle, plus optional `manual_override`), joined to `scan_scopes` + `repos` for metadata. Returns a `CuratedSbomDoc` with the same outer shape as today's, but the inner `serialNumber` and `metadata.component.version` derive from the *scope*, not from `lastScanRunId`. |
| C4 | Switch `GET /api/scopes/:id/sbom-json` (scopes.ts:989–1028) to call `buildCuratedSbomJsonForScope(scopeId)` instead of `buildCuratedSbomJson(scope.lastScanRunId)`. The old function stays — it's still the right call for the scan-detail page. |
| C5 | Update the OpenAPI types + frontend hook (`useScopeSbomJson`) so the frontend automatically picks up any shape change after `npm run gen:types`. |
| C6 | Smoke test: operator renames a component on the Components tab → downloads SBOM → renamed value is present in the JSON. |

### Stream D — Determinism pass on the SBOM download path

**Goal:** close F2.a–F2.e. Two downloads byte-identical when underlying data unchanged.

| Step | Detail |
|---|---|
| D1 | Add `{ purl: "asc" }` (and a final `{ id: "asc" }` insurance) as orderBy tiebreakers in both the scan-level and scope-level builders. |
| D2 | Sort `evidence.occurrences` deterministically: `(path asc, line asc nulls first)`. |
| D3 | Sort `licenses` lexicographically. |
| D4 | Sort `properties[]` by `(name, value)` after assembly — eliminates the "stable by source-code accident" problem. |
| D5 | Use a key-stable serializer for the top-level JSON. Pragmatic option: stringify with a fixed recursive key order (object keys sorted at each depth), then send. Optional `?stable=true` query param for opt-in early, default true once tested. Alternative: build the CycloneDX object with keys inserted in a fixed canonical order and add a lint rule. |
| D6 | Add an integration test `sbomCurated.deterministic.test.ts`: insert N scope_components in non-deterministic order, call the builder twice, assert byte equality. |
| D7 | Add ETag header (SHA-256 of the JSON body) on `GET /scopes/:id/sbom-json`. Cheap and gives the frontend "did this change?" semantics for free. |
| D8 | **Eliminate any LLM call in the download path** — verification only; the current builder has none, but assert this in the test by mocking `llmClient` and failing if it's invoked during the SBOM download path. |

### Cross-stream summary

| Stream | Depends on | M8 restore impact |
|---|---|---|
| A — Artifact volume | — | Forces A6 sub-stream (backup tarball + restore overlay) |
| B — Worker emit-first, ingest-second | A | Drops two JSONB columns → smaller dump; backfill phase needs the artifact volume already mounted |
| C — Scope-level SBOM source | — (C is independent of A/B but easier after B) | None — `scope_components` is already in RESTORE bucket |
| D — Determinism pass | C (or scan-level builder alone, if shipped earlier) | None |

**Suggested sequencing:** A → C → D → B. Reasoning: A is foundational and ships in isolation. C closes the smoking-gun violation the user already flagged. D is small and rounds out the SBOM correctness story. B is the largest change and benefits from A being settled first, plus it can be shipped in two halves (B1–B3 for SBOM, then B4–B6 for SARIF).

---

## 4. Open questions for the user before coding starts

### Q1 — What's the SBOM's identity when source is `scope_components`?

Today: `serialNumber = urn:uuid:${scanRunId}`, `metadata.timestamp = scanRun.finishedAt`, `metadata.component.version = repo.defaultBranch`. With scope-sourced derivation, none of these scan-run values are the right answer. Options:

- (a) `serialNumber = urn:uuid:${scopeId}` (stable forever, "this is the scope's SBOM"). `timestamp = max(scope_components.updatedAt)`. `version = scope.lastScanRunId` (semantic: "what scan last touched any component in this SBOM").
- (b) `serialNumber = urn:uuid:${scopeId}-${scopeContentHash}` (changes with content). Less stable.
- (c) Keep `serialNumber = urn:uuid:${scanRunId}` for continuity with prior downloads — accept that the *content* now diverges from the scan's `sbom_components`.

Recommendation: **(a)**. It's the most honest — this is the scope's curated artifact, not a scan's output.

### Q2 — Artifact retention vs. backup size

If we keep an SBOM + SARIF file per scan run forever (even after the user nuked the underlying `scan_runs` row via UI — wait, scope/run delete cascades, so this is moot), the artifact directory grows linearly. Per scope, typical SBOM is ~1MB, SARIF ~500KB. Across 50 scopes with 100 scans each, that's ~75GB. Is that acceptable, or do we need a "keep last N scans per scope" sweep distinct from the existing scan-retention policy?

### Q3 — External SBOM upload — how shapeable should we leave the door?

Stream B7 mentions adding a `source` discriminator. The user said "eventually, don't build it yet." Two flavours:

- (a) Bare-minimum design hook: just rename `scan_runs.id` semantics so an "upload" can produce a scan run too. Cheapest.
- (b) Add the `source` column now (default `cdxgen`), so future work flips a value rather than schema-migrating again.

Recommendation: **(b)**. Cheap to add, expensive to retrofit.

### Q4 — Should the curated *scope* SBOM also be persisted as a file, or built on-demand?

Target 2 (determinism) is satisfied either way. Target 3 says "files are the source of truth" for *scan output*. A scope SBOM is a *derived view* of `scope_components`, which is the scope's actual truth. Keeping it on-demand keeps `scope_components` authoritative; persisting it adds a sync hazard (the file lies after an operator edit unless re-emitted).

Recommendation: **on-demand**. If perf becomes an issue later, add a caching layer keyed on `scope_components.updatedAt`-max.

### Q5 — Do we drop `scan_runs.sbom_json` entirely after Stream B, or keep it as a fallback?

Dropping it is cleaner; the migration is one-way. Keeping it doubles storage during overlap. The boot-time backfill at B5 needs the column present until the migration runs. Order:

1. Ship Stream A (volume + artifactStore).
2. Ship Stream B except B5.
3. Wait one or two production scans to validate the file-emit path.
4. Backfill historical scans into files.
5. Drop the columns.

Confirm this five-step sequence is acceptable before B kicks off.

### Q6 — Where does the in-flight backfill of `scope_components.latest*` (Stream C1) run?

Two options:

- (a) Worker boot hook (`backfillScopeComponentLatestFields`), same pattern as existing backfills. Idempotent, safe to re-run.
- (b) One-off Prisma migration with raw SQL. CLAUDE.md says: "If a future migration needs to recompute scope-level state, prefer a one-off `prisma migrate` SQL pass over a worker hook" (post-M7 lesson).

Recommendation: **(b)**, per the CLAUDE.md guidance. Add the columns and the backfill in the same migration.

---

## 5. Files for the next session to read first

- `CLAUDE.md` — "Two-table component model (M7)", "Raw vs curated SBOM endpoints (M6q review #15)", "Scan trustworthiness gates remediation logic (M6i)"
- `backend/src/routes/scopes.ts` — the surface that has to change for Stream C
- `backend/src/services/sbomCurated.ts` — the function being forked
- `backend/src/services/scopeComponentService.ts` + `componentMatch.ts` — the scope-merge logic that Stream C2 extends
- `backend/src/services/restoreService.ts` + `routes/adminBackup.ts` / `routes/adminRestore.ts` — the M8 surface that Stream A6 extends
- `backend/src/worker.ts` — the orchestration loop that Stream B refactors
- `docker/compose/docker-compose.yml` — where Stream A adds the volume
