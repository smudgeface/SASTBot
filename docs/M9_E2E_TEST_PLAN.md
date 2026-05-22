# M9 — End-to-end closure-gate test plan

> **Purpose.** M9 is multi-stream, multi-deploy work that fundamentally changes the scan data flow (DB-as-truth → files-as-truth) and the operator's view of SBOMs (scan-level scaffolding → scope-level curated). Each stream has shipped or will ship with **unit-level tests of pure helpers only** — the existing house style across the repo. None of the streams ship integration tests that exercise the worker pipeline, the HTTP endpoints with real bodies, or the operator UI flows.
>
> This document is the **closure gate** for M9. After all streams (A, A6, B1–B7, C, D) have shipped, run the test round in §4 before declaring M9 done. The gaps in §3 are intentional — addressed by the gate, not by per-stream tests — but if a gap is ever closed by an actual test, move it from §3 to §2.
>
> **Pinned reference from `CLAUDE.md` "For AI agents" section** so this survives session clears.

---

## 1. Current state of testing — at a glance

| Surface | Test type | Count | Verdict |
|---|---|---|---|
| Backend unit / pure-function tests | vitest | 18 files, ~193 cases | Healthy coverage of helpers |
| Backend integration tests (real HTTP, real DB, real worker) | — | **0** | Gap |
| Frontend component tests | vitest + RTL | 2 files, 6 cases | Critical surfaces untested |
| Frontend integration / smoke (Chrome DevTools, Playwright, etc.) | — | **0** | Gap |
| Cross-service worker → DB → endpoint round-trip | — | **0** | Gap |

This is the house style. We accept the gap **provided** the closure gate in §4 actually runs before M9 is declared done.

---

## 2. What unit tests cover today (per stream)

### Stream A — artifact volume + `scan_runs.source` (commit `fa39449`)

**Covered:**
- `artifactStore.test.ts` (12 cases): `sbomPathFor` / `sarifPathFor`, atomic write+read round-trip for string + Buffer bodies, parent-dir auto-creation, `.tmp` file cleanup, `tryReadArtifact` returns null for missing files, `deleteArtifact` is force-true semantics, `deleteScanArtifacts` removes both SBOM + SARIF + is idempotent.

**Not covered:**
- The volume is actually mounted into both backend AND worker containers (compose-level).
- `repoService.deleteRepo` actually calls `deleteScanArtifacts` for every cascaded scan run (only the unit functions are tested).
- `scan_runs.source` defaults to `'cdxgen'` on real inserts.

### Stream C — scope SBOM from `scope_components` (commit `e23d41b`)

**Covered:**
- `sbomCurated.test.ts` (3 cases): `buildCuratedSbomJsonForScope` returns operator-edited names; mocks `prisma.sbomComponent.findMany` to throw if invoked, proving the function **never reads scan-level data** (this is the load-bearing test for closing F1). Null for missing scope / no active components.
- The Stream C migration's backfill SQL (`20260522090000_add_scope_component_latest_fields/migration.sql`) populated `latest*` fields from `sbom_components` once at deploy time.

**Not covered:**
- `persistScanComponentsToScopeState` actually writes the new `latest*` fields on subsequent scans (the merge step's `COALESCE`-aware update).
- An operator UI edit (rename via PATCH `/api/scopes/:id/components/:componentId`) is visible in the next SBOM download.
- The backfill migration handled every existing scope_component correctly across the production DB (the migration ran in dev/local; never replayed against prod data).

### Stream D — determinism + ETag (commit `6a2a8ca`)

**Covered (14 cases in `sbomCurated.deterministic.test.ts`):**
- Two consecutive calls produce byte-identical output for both scope-level and scan-level builders.
- Per-component array order (occurrences, licenses, properties) is insertion-order-independent.
- Occurrences sort `(path asc, line asc nulls-first)`, licenses sort lexicographically.
- `sbomCurated.ts` source contains zero LLM / network imports (D8 lint).
- `stableStringify` sorts keys at every depth, preserves array order, handles primitives + nested objects.

**Not covered:**
- The HTTP endpoint actually returns the ETag header.
- `If-None-Match: <etag>` actually returns 304 (the route logic — only the hash primitive is tested).
- The same SBOM downloaded via curl twice is byte-identical (the test mocks Prisma; the actual endpoint isn't exercised).

### Stream A6 — backup/restore artifact overlay (commit `e74b7c8`)

**Covered (~12 new cases across 4 files):**
- `summarizeArtifactDir`: missing dir / empty dir / populated-recursive size+count.
- `MetadataSchema`: old-format backwards-compat (no `artifact_*` fields), new-format with fields, integer validation.
- Tarball allowlist: `{"dump.pgcustom","metadata.json","artifacts"}` accepted; arbitrary entries rejected; old + new tarball shapes both pass the filter.
- `checkArtifactOrphans`: null input (old-format), empty `sbom/` + `sarif/` dirs, missing dirs — filesystem-paths-only.

**Not covered:**
- **Backup endpoint:** pre-create files under `ARTIFACT_DIR`, hit `GET /admin/db/backup`, untar response, assert `artifacts/sbom/<uuid>.json` is in the archive.
- **Restore mode=full:** pre-create live artifact files, restore a tarball with different artifact files, assert live dir matches tarball after restore.
- **Restore mode=runtime:** same as above + 422 when an orphan UUID is in the tarball's `artifacts/`.
- **Old-format tarball compat at the endpoint level** (the unit tests only prove the schema/allowlist accept it).
- **`checkArtifactOrphans` DB path** — the actual `SELECT id FROM restore_temp.scan_runs` against a live `restore_temp` schema.

### Streams B1–B4 — emit + ingest + SARIF emit (planned, Deploy 2)

**Will be covered (per `docs/M9_STREAM_B_PLAN.md` §13):**
- `sbomEmit.test.ts`: round-trip + idempotent byte-equality.
- `sbomIngest.test.ts`: source=cdxgen no-op, source=upload populates rows, missing-file throw.
- `sarifEmit.test.ts`: writes file, records warning on failure.

**Won't be covered (gap to be closed at the gate):**
- **End-to-end scan run.** Trigger a real scan via the worker; confirm `sbom_emit` produces the file AND that file matches the curated SBOM from `GET /api/scopes/:id/sbom-json`.
- **Phase enum surfaces in the UI.** New `sbom_emit` / `sbom_ingest` / `sarif_emit` values render with the right labels in the scope detail page banner + scopes list cell.
- **Warning surfacing.** `sbom_emit_failed` (error severity) actually shows up in the operator UI and gates the SCA auto-fix sweep correctly.

### Streams B5/B6 — column drop + endpoint switch (planned, Deploy 3)

**Will be covered:**
- `backfillArtifacts.test.ts`: pre-populate JSONB columns, run script, assert files appear; re-run idempotent; columns-already-dropped → no-op.
- Endpoint switch: `GET /scans/:id/sbom` reads from disk, ETag round-trip, 404 on missing file.

**Won't be covered (gap to be closed at the gate):**
- **Migration applies cleanly** against a database with non-trivial historical data (prod-shaped, not just local).
- **Backfill processes a realistic row count** without OOM / timeout.
- **Side-effect: `backfillSbomManifestFiles` and `backfillSbomOccurrences`** still work after they're repointed from JSONB column to artifact file.
- **Worker JSONB writes are actually removed** — easy to leave a dead `.update({ sbomJson: ... })` somewhere; only end-to-end will catch it.

### Side task — `DELETE /api/scans/:id`

**Will be covered (per the plan §15):**
- 200 path / 409 lastScanRunId guard / 404 / 400 still-running / 403 non-admin.

**Won't be covered:**
- Artifact files actually gone from disk (filesystem assertion).
- `sast_issues` / `sca_issues` with stale `lastSeenScanRunId` don't 500 anything on subsequent reads (we deliberately leave them stale per the plan; verify UI tolerates it).

---

## 3. Behavioral gaps — only verifiable end-to-end

Grouped by feature area. Each entry: **what's not tested**, **why it matters**, **how the gate verifies it**.

### 3.1 Worker scan pipeline → artifact files

**What's not tested.** The full chain: trigger scan → cdxgen → augmentation → recheck → `sbom_emit` → OSV/NVD/EOL → SAST detection/recheck → `sarif_emit` → finalize. Every per-step test mocks its neighbors.

**Why it matters.** The whole point of B1–B4 is reshaping this chain. If `sbom_emit` runs at the wrong point (e.g. before recheck mutations settle) the file will be stale relative to `sbom_components` and `/api/scopes/:id/sbom-json` will disagree with `/scans/:id/sbom` for the same scan.

**Gate (§4 Phase 1):** real scan on a known small repo → diff `/scans/:id/sbom` against `/api/scopes/:id/sbom-json` → expect identical component set, similar metadata (different `serialNumber` + `version` per design).

### 3.2 Operator UI edits → curated SBOM download

**What's not tested.** Open Components tab → rename a component → click "Download SBOM" → renamed value present in file.

**Why it matters.** This is the headline use case Stream C exists for. Unit test proves the *function* reads from `scope_components`; it does not prove the *UI flow* writes to `scope_components` correctly via the PATCH route, AND that the download endpoint serves the just-written value.

**Gate (§4 Phase 2):** scripted UI / curl sequence — PATCH a component, immediately GET the SBOM, grep for the renamed identifier.

### 3.3 ETag stability over real HTTP

**What's not tested.** `curl -i /api/scopes/:id/sbom-json` twice → ETag header identical. Add `If-None-Match` → 304 No Content with no body.

**Why it matters.** Stream D's whole determinism contract is "two downloads byte-identical." That's an HTTP contract, not just a function contract. The unit test mocks Prisma; only end-to-end proves the hash header + 304 round-trip work in the route.

**Gate (§4 Phase 2.3):** curl with `--include` two times against an unchanged scope.

### 3.4 Backup ↔ restore round-trip with real artifact files

**What's not tested.** Trigger a scan, wait for `sbom_emit` to write a file → backup → wipe everything → restore mode=full → file present at same path, identical bytes. Same for mode=runtime.

**Why it matters.** A6 unit tests prove the helpers; they do not prove the actual `tar -xzf` extraction produces a usable directory structure, or that the `fs.cp` in mode=runtime overlay handles existing files, permissions, and symlinks correctly.

**Gate (§4 Phase 3, full matrix).**

### 3.5 Mode=runtime orphan rejection

**What's not tested.** Construct a tarball with `artifacts/sbom/<bogus-uuid>.json` whose UUID is NOT in the dump's `scan_runs` → restore mode=runtime → 422 with the orphan message.

**Why it matters.** The pre-flight is the entire safety guarantee — without it, a corrupted backup could overlay garbage artifact files onto a healthy DB.

**Gate (§4 Phase 3.4).**

### 3.6 Backwards compatibility — old-format tarballs

**What's not tested.** A tarball produced **before** A6 (no `artifacts/` dir, no `artifact_*` metadata fields) → restore mode=full / mode=runtime against current code → succeeds, leaves artifact dir empty (mode=full) or untouched (mode=runtime).

**Why it matters.** Operators may have pre-A6 backups they want to restore later. We promised this works; nothing actually exercises the path.

**Gate (§4 Phase 5.1).**

### 3.7 Backwards compatibility — historical scan_runs

**What's not tested.** A `scan_runs` row from before B1 (so no artifact file on disk, but `sbom_json` column populated) → after B5 backfill runs → file appears on disk, endpoint serves it.

**Why it matters.** This is the entire purpose of B5. If the backfill doesn't catch every historical row, those scans become un-downloadable when the columns drop.

**Gate (§4 Phase 5.2).**

### 3.8 Phase enum surfacing in the operator UI

**What's not tested.** The frontend's `SCAN_PHASE_LABELS` map covers `sbom_emit` / `sbom_ingest` / `sarif_emit`; the live scopes-page banner displays the right label while a scan is mid-phase.

**Why it matters.** Easy to drift the backend enum and forget the frontend map. Symptom would be "unknown" or blank phase text in production.

**Gate (§4 Phase 1.4):** during the test scan, watch the scopes list — every new phase should render its human label, not a raw enum value.

### 3.9 Trustworthiness gates after `sbom_emit_failed` / `sarif_emit_failed`

**What's not tested.** Force an artifact write to fail (e.g. read-only filesystem). Confirm the warning shows up in the scan detail, `hasErrorWarnings` returns true, the SCA auto-fix sweep skips that scan.

**Why it matters.** Per CLAUDE.md M6i, degraded scans must not destroy real findings. Adding two new error-severity warning codes (`sbom_emit_failed`, `sarif_emit_failed`) without verifying the gate sees them is a regression hazard.

**Gate (§4 Phase 4.2).**

### 3.10 Delete scan → artifact cleanup

**What's not tested.** `DELETE /api/scans/:id` → DB row gone + both artifact files gone from disk.

**Why it matters.** Filesystem leak — silently fills the disk over time.

**Gate (§4 Phase 6.1).**

### 3.11 Worker startup backfills (already-shipped) still work post-B5

**What's not tested.** `backfillSbomManifestFiles` and `backfillSbomOccurrences` currently read `scan_runs.sbom_json`. B5 deletes that column and repoints them at the artifact file. The function reads from disk → parses CycloneDxDocument → rewrites the row. Test that this still produces correct paths.

**Why it matters.** These two hooks fix historical path bugs. If they silently no-op after B5 (e.g. file format mismatch, missing field), legacy data quietly stays broken.

**Gate (§4 Phase 5.3).**

---

## 4. The M9 closure gate — final E2E test round

Run **AFTER Deploy 3 (B5+B6) ships** and **BEFORE declaring M9 done**. Set up a fresh homelab Dokploy stack with prod-shaped fixtures (3–5 repos, ≥10 historical scans).

Estimated time: ~3 hours hands-on, longer if the orchestration tooling isn't already in place.

### Phase 1 — Clean-slate scan round-trip (~30 min)

1. **Bring up a clean stack:** `docker compose down -v && docker compose up --build`. Wait for backend healthy.
2. **Bootstrap + onboard one small repo** (e.g. a fresh public Node project — 50–100 components).
3. **Trigger a scan via the UI.** Watch the scopes-page banner cycle through phases. Confirm every phase label renders human-readable (no raw enum values, no "unknown"). **Gap 3.8.**
4. **After scan completes, inspect the artifact directory:**
   ```sh
   docker compose exec backend ls -la /var/lib/sastbot/artifacts/sbom/
   docker compose exec backend ls -la /var/lib/sastbot/artifacts/sarif/
   ```
   Expect: one `<scanRunId>.json` and one `<scanRunId>.sarif.json`. Files non-zero size. **Gap 3.1.**
5. **Diff the two SBOM endpoints for the same scan:**
   ```sh
   curl -s /api/scopes/<id>/sbom-json > scope.json
   curl -s /scans/<id>/sbom > scan.json
   diff <(jq -S '.components | length' scope.json) <(jq -S '.components | length' scan.json)
   # Component counts should match.
   diff <(jq -S '[.components[].purl] | sort' scope.json) <(jq -S '[.components[].purl] | sort' scan.json)
   # Component identity sets should match.
   ```
   **Gap 3.1.**
6. **Confirm trustworthiness counters look sane:** scope row shows correct severity counts; `scan_runs.warnings` has no `error`-severity entries.

### Phase 2 — Scope-level operator edits (~20 min)

1. **Rename a component** via the Components tab pencil icon.
2. **Immediately download the scope-level SBOM** (no new scan). Grep for the renamed identifier — must be present. **Gap 3.2.**
3. **Delete a component** via the trashcan icon.
4. **Download SBOM again** — deleted component must be absent.
5. **ETag round-trip on the unchanged endpoint:**
   ```sh
   ETAG=$(curl -sI /api/scopes/<id>/sbom-json | grep -i '^etag:' | awk '{print $2}' | tr -d '\r')
   curl -i -H "If-None-Match: $ETAG" /api/scopes/<id>/sbom-json
   # Expect: 304 No Content, empty body.
   curl -sI /api/scopes/<id>/sbom-json | grep -i '^etag:'
   # Expect: identical ETag value.
   ```
   **Gap 3.3.**

### Phase 3 — Backup/restore matrix (~45 min)

1. **Baseline state snapshot:** `pg_dump` row counts per table; `ls -la` artifact dir.
2. **Backup full:** `curl -OJ /admin/db/backup`. Inspect tarball:
   ```sh
   tar -tzf sastbot-backup-*.tar.gz | head
   # Expect: dump.pgcustom, metadata.json, artifacts/sbom/..., artifacts/sarif/...
   tar -xzf sastbot-backup-*.tar.gz -C /tmp/peek
   jq '.artifact_count, .artifact_bytes_total' /tmp/peek/metadata.json
   # Expect: non-zero count, non-zero bytes.
   ```
3. **Restore mode=full from this tarball:**
   - Wipe `ARTIFACT_DIR` first: `docker compose exec backend rm -rf /var/lib/sastbot/artifacts/*`.
   - POST the tarball with `?mode=full`.
   - Confirm: row counts match baseline; artifact dir contents byte-identical to the snapshot (sha256sum every file). **Gap 3.4.**
4. **Restore mode=runtime:** add a new repo via UI (PRESERVE-bucket mutation) → restore the same tarball with `?mode=runtime` → confirm new repo survives AND scan-output rows + artifacts match baseline.
5. **Restore mode=runtime with orphan tarball:**
   - Mangle the tarball: extract, add a bogus file `artifacts/sbom/00000000-0000-0000-0000-000000000000.json`, re-tar.
   - POST with `?mode=runtime`.
   - Expect: 422, response detail mentions the orphan UUID. **Gap 3.5.**

### Phase 4 — Failure modes (~20 min)

1. **Force `sbom_emit_failed`:**
   - Mount `/var/lib/sastbot/artifacts/sbom` as read-only (`chmod a-w`) on the worker container.
   - Trigger a scan.
   - Confirm: scan finishes; scope detail shows an error warning chip; SCA auto-fix sweep does NOT mark prior findings as fixed. **Gap 3.9.**
   - Restore write permissions before next phase.
2. **Force `sarif_emit_failed`:** same drill on the `sarif` subdir.
3. **Worker artifact-store DELETE failure:** delete a scan via `DELETE /api/scans/:id` while the artifact files are open by another process. The DB row should still be deleted; the artifact-cleanup is best-effort with a logged warning. Confirm log entry.

### Phase 5 — Backwards compatibility (~30 min)

1. **Old-format tarball restore (pre-A6):**
   - Grab a backup tarball saved before A6 deployed (or synthesize one: extract a current tarball, delete `artifacts/` and the artifact fields from `metadata.json`, re-tar).
   - Restore mode=full → succeeds; `ARTIFACT_DIR` is empty afterwards.
   - Restore mode=runtime → succeeds; `ARTIFACT_DIR` is untouched (DB rows overlaid, FS not touched). **Gap 3.6.**
2. **Historical `scan_runs` backfill (pre-B1):**
   - Before Deploy 3 ships, snapshot the DB with several scan_runs that have `sbom_json` / `sast_sarif` but no artifact file on disk.
   - Deploy 3 (B5 backfill + column drop).
   - For every historical scan_run, confirm: artifact file appears; `/scans/:id/sbom` serves it; ETag stable; content matches what was in the column (or, for SBOM, matches what `buildCuratedSbomJson` would produce from `sbom_components`). **Gap 3.7.**
3. **Worker boot backfills (`backfillSbomManifestFiles`, `backfillSbomOccurrences`):**
   - Inject a `sbom_components` row with a known-broken `manifest_file` path.
   - Restart the worker.
   - Confirm: the backfill picks the row up, reads the artifact file, rewrites the manifest path. **Gap 3.11.**

### Phase 6 — Lifecycle (~15 min)

1. **`DELETE /api/scans/:id` happy path:**
   - Pick a scan that is NOT the scope's lastScanRunId.
   - Note the artifact file paths.
   - Hit the endpoint as admin.
   - Confirm: row gone; both artifact files gone from disk; scope page loads without 500. **Gap 3.10.**
2. **409 guard:**
   - Try to delete the scope's `lastScanRunId`. Expect 409 with the guidance message. Row + files still present.
3. **Cascade:** delete a repo with retained scans. Confirm: every scan's artifact files gone (filesystem walk).

---

## 5. After the gate passes

1. **Update this doc:** add a "✅ Gate passed on YYYY-MM-DD" header at top with a short note on what failed (if anything) and how it was patched.
2. **PROGRESS.md M9 closure entry** references this doc by name + the gate-pass date.
3. **Remove the pin from CLAUDE.md** "For AI agents" — the gate is no longer a pending obligation.
4. **Archive opportunity:** if any §3 gap turned into a permanent unit/integration test during the gate work, move it to §2 and note the test file.

---

## 6. Pinning this doc so it isn't forgotten

After this commit, add a one-line pointer to **`CLAUDE.md`** in the "For AI agents" section:

```
- 🚦 **M9 closure gate is pending.** Before declaring M9 done, run
  the E2E test round in `docs/M9_E2E_TEST_PLAN.md`. Per-stream unit
  tests deliberately do not cover end-to-end behaviour.
```

When the gate passes, remove that line in the same commit that updates §5 above.
