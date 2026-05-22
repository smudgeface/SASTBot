# M9 Stream B — Artifact-centric worker refactor

> **Status:** plan, awaiting sign-off. No code changes yet.
> **Scope:** sub-stream A6 (artifact backup/restore) + B1–B7 from `docs/M9_AUDIT_PLAN.md` §3.
> **Companion:** the parent audit doc; Streams A, C, D shipped on `main` in commits `fa39449`, `e23d41b`, `6a2a8ca`.
> **Side task tracked here:** `DELETE /api/scans/:id` route.

---

## 1. What's already in place

| Surface | State |
|---|---|
| `sastbot_artifacts` named volume mounted into backend + worker at `/var/lib/sastbot/artifacts` | shipped (Stream A, `fa39449`) |
| `ARTIFACT_DIR` env + `config.artifactDir` | shipped |
| `services/artifactStore.ts` — `sbomPathFor / sarifPathFor / writeArtifact / readArtifact / tryReadArtifact / deleteArtifact / deleteScanArtifacts` | shipped |
| `repoService.deleteRepo` calls `deleteScanArtifacts` for every cascaded scan run | shipped |
| `scan_runs.source` discriminator, default `'cdxgen'` | shipped (Stream A) |
| `scope_components.latest*` (licenses / cpe / componentType / discoveryMethod / llmEvidence) | shipped (Stream C) |
| `buildCuratedSbomJsonForScope(scopeId)` + `stableStringify` + ETag on the scope SBOM endpoint | shipped (Streams C/D, `6a2a8ca`) |

What's **not** in place yet (= scope of this plan):

- No `${ARTIFACT_DIR}/sbom/${scanRunId}.json` is ever written. `artifactStore` exists but no producer calls it.
- No `${ARTIFACT_DIR}/sarif/${scanRunId}.sarif.json` is ever written.
- The two scan-page endpoints still read from `scan_runs.sbom_json` / `scan_runs.sast_sarif` (JSONB).
- Backup tarball contains `dump.pgcustom` + `metadata.json` only — no `artifacts/` directory.
- Restore (both modes) doesn't touch the artifact volume.

---

## 2. Locked decisions (from prior session + this session)

| ID | Decision | Source |
|---|---|---|
| Q1 | Scope SBOM identity = `urn:uuid:${scopeId}` | prior session (shipped) |
| Q3 | `scan_runs.source` lives now with default `'cdxgen'` | prior session (shipped) |
| Q5 | Five-step column-drop sequence: A6 → B1–B4 → 1–2 prod scans → B5 backfill → B5 column drop | prior session |
| Q6 | `scope_components` recompute backfills go in Prisma migrations, **not** worker boot hooks | prior session |
| B-Q1 | `/scans/:id/sbom` serves curated only post-B6; raw cdxgen audit trail is dropped | this session |
| B-Q2 | `sbom_emit` runs **once** at scan end, post-recheck; `sbom_ingest` in the cdxgen flow is a no-op (reserved for the future upload path) | this session |
| B-Q3 | B5 backfill is a CLI script invoked from the entrypoint **before** `prisma migrate deploy` | this session |
| B-Q4 | `DELETE /api/scans/:id` is admin-only and **refuses with 409** when the target is the scope's `lastScanRunId` | this session |

---

## 3. Cross-deploy sequencing

This is multi-PR work. Three commit clusters, ordered:

```
┌──────────────────────────┐
│ Deploy 1: A6 (backup/    │  v0.5.1 → v0.6.0
│   restore overlay)       │  ships before any new artifact file exists;
│                          │  tarball just has an empty artifacts/ dir
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ Deploy 2: B1 + B2 + B4   │  v0.6.0 → v0.7.0
│   (sbom_emit, sbom_ingest│  worker starts writing files on every new scan;
│   sarif_emit)            │  scan-page endpoints still read JSONB columns
│   B7: nothing to ship    │  (B6 not yet flipped)
│                          │
│   ⏸ Validate: trigger    │
│   1-2 production scans,  │
│   verify SBOM/SARIF      │
│   files appear on disk   │
│   and the JSONB columns  │
│   contain matching data  │
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ Deploy 3: B5 + B6        │  v0.7.0 → v0.8.0
│   - backfillArtifacts    │  entrypoint runs backfill before migrate;
│     CLI                  │  migration drops sbom_json + sast_sarif;
│   - migration: drop      │  endpoints switch to artifact reads;
│     scan_runs.sbom_json  │  remove the worker's JSONB writes from
│     + sast_sarif         │  the worker (now redundant).
│   - endpoints switch     │
│     to artifactStore     │
│   - worker stops writing │
│     JSONB columns        │
└──────────────────────────┘
```

**Side task `DELETE /api/scans/:id`** is independent — drop into any of the three deploys, or its own. The `deleteScanArtifacts` helper is already wired, so it composes cleanly with whatever B-cluster ships alongside it.

---

## 4. Stream A6 — backup tarball + restore overlay

### A6.1 — Backup tarball includes `artifacts/`

**Touches:** `routes/adminBackup.ts`, `services/backupMetadata.ts`.

Today the tarball layout is:

```
dump.pgcustom
metadata.json
```

After A6 it becomes:

```
dump.pgcustom
metadata.json
artifacts/
  sbom/
    <uuid>.json
    ...
  sarif/
    <uuid>.sarif.json
    ...
```

**Implementation:**

- In `adminBackup.ts`, after the `pg_dump` and metadata write but before spawning `tar`, copy the contents of `config.artifactDir` into `<tmpdir>/artifacts/` using `fs.cp(src, dst, { recursive: true })`. (If `ARTIFACT_DIR` doesn't exist yet — fresh install with no scans — skip the copy; `tar` will get only `dump.pgcustom` + `metadata.json`, which is the current behavior.)
- Extend the `tar` argv to include `artifacts` when it exists.
- Update `BackupMetadata` (`services/backupMetadata.ts`) to record an `artifact_count` (int) and `artifact_bytes_total` (int) summary. These are surfaced in the restore endpoint's log lines for sanity; the restore doesn't *gate* on them, just compares vs what's extracted.
- Bump `SASTBOT_DUMP_FORMAT_VERSION` in `routes/version.ts` by 1 (currently the constant is exported from there) so the restore endpoint can tell new-format tarballs from old ones.

**Old-format tarball compatibility (restore):** if `metadata.sastbot_dump_format_version` is the prior value (or missing), the extractor MUST NOT require `artifacts/` to exist. Old tarballs restore exactly as today (artifact dir left untouched in mode=runtime, wiped-and-empty in mode=full).

### A6.2 — `mode=full` restore: wipe + extract `artifacts/`

**Touches:** `routes/adminRestore.ts`.

After `pg_restore` succeeds (the existing tarball path), do the artifact overlay synchronously **before** sending the 200 response:

```ts
// 1. Wipe live artifact dir (mode=full = "exactly as backup")
await fsPromises.rm(config.artifactDir, { recursive: true, force: true });
await fsPromises.mkdir(config.artifactDir, { recursive: true });

// 2. If extractedEntries includes "artifacts", copy it in
const tarballArtifacts = path.join(extractDir, "artifacts");
if (await fsPromises.access(tarballArtifacts).then(() => true).catch(() => false)) {
  await fsPromises.cp(tarballArtifacts, config.artifactDir, { recursive: true });
}
```

If the wipe fails: 500, leave temp dir for inspection (operator can recover by restoring the volume from a snapshot).

If the copy fails after the wipe: 500 with explicit message — DB is restored but the artifact dir is now empty. Operator can re-run mode=full with the same dump.

### A6.3 — `mode=runtime` restore: artifact overlay after the DB transaction

**Touches:** `services/restoreService.ts`, `routes/adminRestore.ts`.

The runtime overlay's contract: scan-output rows (RESTORE bucket) come from the dump; admin-config (PRESERVE bucket) stays live. Artifacts are scan-derived, so they must be overlaid in lock-step with the RESTORE bucket.

**Sequence:**

1. `runRuntimeRestore` does its rename dance + `applyRuntimeOverlay` (existing code).
2. **After** the DB transaction commits (so `public.scan_runs` is now the dump's set):
   - Wipe `config.artifactDir`.
   - Copy `extractDir/artifacts/` into `config.artifactDir`.
3. The artifact overlay runs **outside** the DB transaction — it's a filesystem operation, can't be transactional. If it fails between DB-commit and copy-complete, the DB is authoritative; operator re-runs the restore with the same dump (idempotent — same DB state, same artifact set ends up on disk).

Wiping is the safest mental model: the dump's `artifacts/` is the source of truth, current disk state is stale relative to the new RESTORE bucket. Mirrors mode=full.

**Plumbing:** `runRuntimeRestore` currently takes `{ dumpPath, pgEnv }`. Extend to `{ dumpPath, pgEnv, artifactSourceDir, artifactTargetDir }`. The route passes `extractDir/artifacts` + `config.artifactDir`. The service handles the filesystem step after the DB step succeeds.

### A6.4 — Pre-flight: every artifact file in the dump corresponds to a `scan_runs` row in the dump

**Touches:** `services/restoreService.ts`.

Per the locked constraint. Implementation: after the rename dance (so `restore_temp.scan_runs` contains the dump's rows), enumerate `extractDir/artifacts/sbom/*.json` and `extractDir/artifacts/sarif/*.sarif.json`, parse the UUIDs out of the filenames, and run:

```sql
SELECT array_agg(id::text) FROM restore_temp.scan_runs
WHERE id = ANY($1::uuid[]);
```

If the returned set is a strict subset of the input UUIDs, abort with 422 listing the orphans. Same error envelope as the existing `formatFkViolationMessage`.

This runs only in mode=runtime (the only mode that uses the rename dance). For mode=full, skip the check — the dump is the source of truth for both DB and FS in one shot, and pg_restore will fail if anything is structurally wrong.

### A6 deliverables checklist

- [ ] `routes/adminBackup.ts`: tar includes `artifacts/`
- [ ] `services/backupMetadata.ts`: `artifact_count` + `artifact_bytes_total` fields
- [ ] `routes/version.ts`: bump `SASTBOT_DUMP_FORMAT_VERSION`
- [ ] `routes/adminRestore.ts`: mode=full wipes + extracts artifacts; mode=runtime passes the artifact dir to `runRuntimeRestore`
- [ ] `services/restoreService.ts`: extended signature; runs artifact overlay post-commit; A6.4 pre-flight
- [ ] Backwards-compat: old-format tarballs (missing `artifacts/` or older format version) still restore cleanly
- [ ] Version bump (**three files**, see CLAUDE.md ⚠️ Versioning policy): `backend/package.json` + `frontend/package.json` + `APP_VERSION` in `backend/src/routes/version.ts` — all to 0.6.0
- [ ] `docs/PROGRESS.md` entry for A6

---

## 5. Stream B1 — `sbom_emit` worker phase

**Goal:** after the recheck phase settles, serialize the canonical CycloneDX 1.7 doc from `sbom_components` and write it to `${ARTIFACT_DIR}/sbom/${scanRunId}.json`.

**Touches:** `backend/src/worker.ts`, `backend/src/services/sbomCurated.ts` (new export `emitSbomArtifact`).

### Where it slots in the worker

Current `worker.ts` SBOM flow (lines ~1300–1565):

```
cdxgen (in-memory)
  → Stage-1 mechanical clean (in-memory)
  → LLM SBOM augmentation (in-memory, claude-p)
  → tx: write scan_runs.sbom_json (raw cdxgen) + persistAugmentedComponents
  → persistScanComponentsToScopeState
  → SBOM recheck (mutates sbom_components, scope_components)
  → materializeRecoveredComponents, rebuildComponentsFromScopeState
  → ★ B1 INSERT POINT: emitSbomArtifact(scanRunId)
  → OSV / NVD / EOL ...
```

The `sbom_emit` phase fires **once**, after `rebuildComponentsFromScopeState` settles. At this point `sbom_components` is the final post-recheck state — exactly what the file should reflect.

### New service function

```ts
// services/sbomCurated.ts
export async function emitSbomArtifact(scanRunId: string): Promise<{ written: boolean; path: string }> {
  const doc = await buildCuratedSbomJson(scanRunId);
  if (!doc) return { written: false, path: sbomPathFor(scanRunId) };
  const body = stableStringify(doc, 2);
  const filePath = sbomPathFor(scanRunId);
  await writeArtifact(filePath, body);
  return { written: true, path: filePath };
}
```

Uses the existing `buildCuratedSbomJson` (already determinism-cleaned in Stream D) and `stableStringify` (Stream D5). Atomic write via `artifactStore.writeArtifact` (already does `.tmp` + rename).

### Worker integration

After `rebuildComponentsFromScopeState`, before OSV:

```ts
await setPhase(scanRunId, "sbom_emit");
const emitResult = await emitSbomArtifact(scanRunId).catch((err) => {
  log.error({ err: (err as Error).message }, "[worker] sbom_emit failed");
  return null;
});
if (!emitResult?.written) {
  await appendWarning(scanRunId, {
    code: "sbom_emit_failed",
    severity: "error",
    message: `Failed to write canonical SBOM artifact for this scan. ${
      emitResult === null ? "(emit threw)" : "(no components to emit)"
    }`,
  });
}
```

**Trustworthiness gate:** per CLAUDE.md M6i, `sbom_emit_failed` is an `error`-severity warning. The SCA auto-fix sweep already gates on `hasErrorWarnings`, so a scan with a missing SBOM file won't mark old findings as fixed. Same treatment as `cdxgen_failed` and `llm_sast_detection_failed`.

### `scan_runs.sbom_json` during Deploy 2

Keep writing the raw cdxgen output to `scan_runs.sbom_json` throughout Deploy 2 (unchanged from today). This gives us a parallel-truth window: file-on-disk = post-augmentation canonical; column = raw cdxgen. Validation phase compares the two (sanity that the worker is writing the right thing). The column is dropped in Deploy 3 (B5).

---

## 6. Stream B2 — `sbom_ingest` worker phase

**Goal:** define the phase that reads a canonical CycloneDX file from disk and populates `sbom_components` rows. For the `source='cdxgen'` flow (the only flow today) this is a **no-op** — the rows are already populated by `persistAugmentedComponents`. The phase exists to give the future external-upload path (B7) a place to live.

**Touches:** `backend/src/worker.ts`, new file `backend/src/services/sbomIngest.ts`.

### Phase semantics

```ts
await setPhase(scanRunId, "sbom_ingest");
const run = await prisma.scanRun.findUnique({
  where: { id: scanRunId },
  select: { source: true },
});
if (run?.source === "upload") {
  await ingestSbomFromArtifact(scanRunId);
} else {
  log.debug({ scanRunId }, "[worker] sbom_ingest: source=cdxgen, sbom_components already populated");
}
```

For the cdxgen flow, we run the phase (so the UI sees it tick by) but skip the body. Total latency added: one `prisma.scanRun.findUnique` call.

### `sbomIngest.ts` skeleton (called only for source=upload)

```ts
export async function ingestSbomFromArtifact(scanRunId: string): Promise<void> {
  const body = await tryReadArtifact(sbomPathFor(scanRunId));
  if (!body) throw new Error(`No SBOM artifact found for scan ${scanRunId}`);
  const doc = JSON.parse(body.toString("utf8")) as CuratedSbomDoc;

  // Idempotent: clear any existing sbom_components for this scanRunId, then
  // insert from the doc. The (scan_run_id, purl) unique index (M7) ensures
  // re-running on the same file produces the same row set.
  await prisma.$transaction(async (tx) => {
    await tx.sbomComponent.deleteMany({ where: { scanRunId } });
    await tx.sbomComponent.createMany({
      data: doc.components.map((c) => ({
        scanRunId,
        name: c.name,
        version: c.version ?? null,
        purl: c.purl,
        // ... extract from c.evidence / c.properties / c.licenses
      })),
      skipDuplicates: true,
    });
  });
}
```

Full extraction logic deferred to whoever ships the upload path. For Deploy 2 we ship the phase plumbing + the skeleton with a `TODO(M9 B7)` comment.

---

## 7. Stream B3 — OSV/NVD/EOL stay on `sbom_components`

**Goal:** verify (not change) that the downstream phases keep reading from `sbom_components` rather than from the artifact file directly.

**Touches:** none. This is a documentation step in the plan.

`osvService`, `nvdService`, `eolService` all query `prisma.sbomComponent.findMany` keyed on `scanRunId`. They run AFTER `sbom_emit` + `sbom_ingest` in the new order, so the row set they see is identical to today (cdxgen flow) or identical to the file contents (upload flow). No code change required.

---

## 8. Stream B4 — `sarif_emit` worker phase

**Touches:** `worker.ts`, `services/sarifService.ts` (new export `emitSarifArtifact`).

Mirror of B1 but for SARIF. Current write site is `regenerateSastSarifForScan` in `worker.ts:561–584`. After B4 it becomes:

```ts
async function regenerateSastSarifForScan(scanRunId, scopeId, scopePath) {
  const issues = await prisma.sastIssue.findMany({...});
  const run = await prisma.scanRun.findUnique({...});
  const sarif = buildSarifFromIssues(issues, {...});

  // Deploy 2: dual-write — disk AND column. Column write goes away in Deploy 3.
  const body = JSON.stringify(sarif, null, 2);
  await writeArtifact(sarifPathFor(scanRunId), body);
  await prisma.scanRun.update({
    where: { id: scanRunId },
    data: { sastSarif: sarif as Prisma.InputJsonValue },
  });
}
```

In Deploy 3 the `prisma.scanRun.update` line gets deleted along with the column.

**Trustworthiness gate:** add `sarif_emit_failed` (error severity) if the disk write throws — same pattern as B1.

**Phase plumbing:** wrap the body in `setPhase(scanRunId, "sarif_emit")` so the UI sees it.

**Determinism note:** SARIF builder doesn't use `stableStringify` today. We're not adding determinism to SARIF in Stream B — operators don't compare SARIF byte-for-byte the way they compare SBOMs. Plain `JSON.stringify(..., null, 2)` is fine.

---

## 9. Stream B5 — backfill + drop JSONB columns

This is the irreversible deploy. Three discrete steps, all in one PR/commit cluster but careful about ordering inside the entrypoint:

### B5.1 — CLI backfill script

**New file:** `backend/src/cli/backfillArtifacts.ts`

**Algorithm:**

```ts
async function main() {
  // Probe information_schema — if columns are gone, exit 0 (already done).
  const hasSbomJson = await columnExists("scan_runs", "sbom_json");
  const hasSastSarif = await columnExists("scan_runs", "sast_sarif");
  if (!hasSbomJson && !hasSastSarif) {
    logger.info("[backfillArtifacts] columns already dropped — no-op");
    return;
  }

  // SBOM: rebuild canonical doc from sbom_components, not from sbom_json
  // (which is raw cdxgen — wrong shape for the curated artifact).
  if (hasSbomJson) {
    const runs = await prisma.$queryRawUnsafe<{ id: string }[]>(
      `SELECT id FROM scan_runs WHERE sbom_json IS NOT NULL`
    );
    for (const { id } of runs) {
      const filePath = sbomPathFor(id);
      if (await fileExists(filePath)) continue;  // idempotent: skip
      const doc = await buildCuratedSbomJson(id);
      if (!doc) continue;
      await writeArtifact(filePath, stableStringify(doc, 2));
    }
  }

  // SARIF: byte-copy from sast_sarif column (it's already the final doc).
  if (hasSastSarif) {
    const runs = await prisma.$queryRawUnsafe<{ id: string; sarif: unknown }[]>(
      `SELECT id, sast_sarif AS sarif FROM scan_runs WHERE sast_sarif IS NOT NULL`
    );
    for (const { id, sarif } of runs) {
      const filePath = sarifPathFor(id);
      if (await fileExists(filePath)) continue;
      await writeArtifact(filePath, JSON.stringify(sarif, null, 2));
    }
  }
}
```

**Asymmetry note:** SBOM backfill **re-derives** the file from `sbom_components`. This is necessary because `scan_runs.sbom_json` holds raw cdxgen output, not the post-augmentation curated form. SARIF backfill is a straight byte copy because `sast_sarif` already holds the final SARIF.

**Failure mode:** per-row failures are logged and skipped (don't block deploy). The next scan will overwrite anything missing — the backfill is best-effort for historical data, not a hard requirement.

**`package.json` script:** add `"backfill-artifacts": "tsx src/cli/backfillArtifacts.ts"`.

### B5.2 — Entrypoint ordering

**Touches:** `docker/compose/docker-compose.yml` (backend `command`) and `docker/backend-entrypoint.sh` if one exists (M8 added pre-deploy backup via the entrypoint per commit `04aa959`).

Current backend command: `pnpm prisma migrate deploy && pnpm dev`.

New command: `pnpm run backfill-artifacts && pnpm prisma migrate deploy && pnpm dev`.

Why this order:
- Backfill reads columns while they still exist.
- Migration drops the columns.
- Dev/prod server starts with the columns gone.

If the backfill takes too long for a deploy window: it's idempotent + safe — the next deploy picks up where it left off. The columns aren't dropped until the migration runs, and we don't run the migration if backfill exits non-zero (`&&` short-circuit).

Worker entrypoint stays unchanged (worker doesn't run migrations, doesn't need to backfill — the backend has already handled it before the worker boots).

### B5.3 — Migration: drop the columns

Per CLAUDE.md ("Compose stack has no TTY for `prisma migrate dev`"), generate manually:

```bash
pnpm prisma migrate diff \
  --from-schema-datasource prisma/schema.prisma \
  --to-schema-datamodel <(sed -e '/sbomJson/d' -e '/sastSarif/d' prisma/schema.prisma) \
  --script > prisma/migrations/<timestamp>_drop_scan_run_sbom_sast_jsonb/migration.sql
```

The generated SQL will be:

```sql
ALTER TABLE "scan_runs" DROP COLUMN "sbom_json";
ALTER TABLE "scan_runs" DROP COLUMN "sast_sarif";
```

Per `docs/MIGRATIONS_CHECKLIST.md` (column drop): no row backfill required (we did it in B5.1), but worth confirming no code path still reads the columns.

### B5.4 — Cleanup: remove worker JSONB writes + boot backfills + service reads

Same PR as the migration:

| Site | Change |
|---|---|
| `worker.ts:582` (regenerateSastSarifForScan column write) | delete the `prisma.scanRun.update({...sastSarif...})` line |
| `worker.ts:1382` (raw cdxgen column write) | delete the `sbomJson: sbomDoc as object` line from the `scanRun.update` call inside `persistAugmentedComponents`'s preamble; the rest of that tx still runs |
| `worker.ts:880–912` (backfillSastSarif) | delete the boot hook entirely |
| `services/sbomService.ts:842–910` (backfillSbomManifestFiles) | this reads `sbom_json` to repair manifest paths in `sbom_components`. **Keep the function but switch the read source to the new artifact file via `tryReadArtifact(sbomPathFor(run.id))` and parse as CycloneDxDocument.** The function is idempotent and only runs on boot; the file IS the canonical replacement. |
| `services/sbomOccurrences.ts:170,416,433,440,451,458` (backfillSbomOccurrences) | same surgery as above — read from disk, not the JSONB column |
| `services/osvService.ts:439` (comment only — no actual column read) | no change |
| Prisma schema | delete `sbomJson` and `sastSarif` fields on `ScanRun` model |

---

## 10. Stream B6 — endpoint switch from JSONB to artifact files

**Touches:** `backend/src/routes/scans.ts:237–308`.

Two endpoints, both currently reading the JSONB columns. Switch to `tryReadArtifact`:

### `GET /scans/:id/sbom`

```ts
// Before
const run = await prisma.scanRun.findFirst({
  where: { id: params.id, orgId: orgId ?? null },
  select: { id: true, sbomJson: true, repo: { select: { name: true } } },
});
if (!run.sbomJson) return reply.code(404).send(...);
const pretty = stableStringify(run.sbomJson, 2);

// After
const run = await prisma.scanRun.findFirst({
  where: { id: params.id, orgId: orgId ?? null },
  select: { id: true, repo: { select: { name: true } } },
});
if (!run) return reply.code(404).send({ detail: "Scan run not found" });
const body = await tryReadArtifact(sbomPathFor(run.id));
if (!body) return reply.code(404).send({ detail: "SBOM not yet available for this scan" });
const pretty = body.toString("utf8");  // file is already stableStringify-formatted
```

ETag computation stays the same (`createHash("sha256").update(pretty).digest("hex").slice(0, 32)`); since the file was written deterministically by `stableStringify`, two reads with no scan in between will produce the same ETag.

**Semantic shift to flag in PROGRESS.md:** before B6, this endpoint served the raw cdxgen audit-trail doc. After B6, it serves the post-augmentation curated doc. Per locked decision B-Q1, this is intentional — the raw cdxgen audit trail goes away.

Suggested doc-string update for the endpoint, replacing the existing "Raw cdxgen output for this scan..." comment:

```ts
// Post-augmentation canonical CycloneDX 1.7 SBOM for this scan run, served
// from the artifact file at ${ARTIFACT_DIR}/sbom/${scanRunId}.json. Written
// by the worker's sbom_emit phase using stableStringify so two reads of an
// unchanged scan return byte-identical output (ETag stable).
//
// This is the scan-level (per-run) artifact. For the scope-level view that
// reflects operator edits to scope_components, use
// GET /api/scopes/:id/sbom-json.
```

### `GET /scans/:id/sast-sarif`

Same pattern. Add an ETag header for parity with the SBOM endpoint (cheap, gives the frontend "did this change?" semantics for free).

### Open question for B6 — empty-artifact 404 message

If `tryReadArtifact` returns null (file missing on disk), do we 404 or 410? The file might be missing because:
- Scan is still running (sbom_emit hasn't fired yet) → 404 is correct.
- Scan ran but `sbom_emit_failed` warning was recorded → arguably 410. But operators reading the file path expect 404, and the warning is surfaced in the scan-detail UI separately, so 404 with the existing "SBOM not yet available" detail is fine.

Recommended: keep 404, no behavior change.

---

## 11. Stream B7 — design hook only

**Goal:** confirm that the `source` discriminator can carry a future external-upload flow without further schema changes.

**Status:** the discriminator (`scan_runs.source`, default `'cdxgen'`, values `'cdxgen' | 'upload'`) is already in the schema as of Stream A. The B2 `sbom_ingest` phase plumbing is what makes upload-flow practical:

- An upload route would `POST /api/scans/:scopeId/upload` (multipart), accept the file, create a `scan_runs` row with `source='upload'`, write the file directly via `writeArtifact(sbomPathFor(run.id), body)`, and enqueue a BullMQ job that runs **only** phases `sbom_ingest → osv → nvd → eol → sca_summaries → finalizing`. The SAST half is skipped (no source code to scan).
- No new tables; no new columns; no schema migration.

**No code in this milestone.** Document the design above as a comment on the `source` field in `schema.prisma` and in `docs/PROGRESS.md`.

---

## 12. Worker phase enum updates

Three new phase values across two locations:

### Backend: `backend/src/schemas.ts:430–434` + `worker.ts:122`

```ts
type ScanPhase =
  | "cloning"
  | "cdxgen"
  | "llm_sbom"
  | "llm_sbom_recheck"
  | "sbom_emit"     // NEW (B1)
  | "sbom_ingest"   // NEW (B2)
  | "osv"
  | "nvd"
  | "eol"
  | "llm_detection"
  | "llm_recheck"
  | "sarif_emit"    // NEW (B4)
  | "sca_summaries"
  | "finalizing";
```

Both the Zod enum and the worker's TypeScript union need the new values.

### Frontend: `frontend/src/api/types.ts:293–338`

Same union + label map + units map + caps set:

```ts
export const SCAN_PHASE_LABELS: Record<ScanPhase, string> = {
  // ...existing...
  sbom_emit: "Writing SBOM artifact",
  sbom_ingest: "Indexing SBOM",
  sarif_emit: "Writing SARIF artifact",
};
```

`SCAN_PHASE_UNITS` and `SCAN_PHASE_CAPS` get no entries for the three new phases — they're sub-second instantaneous operations, no progress counter to show. The label alone is enough.

After bumping, run `npm run gen:types` from the frontend container to regen the OpenAPI types (the enum literal updates flow through automatically).

---

## 13. Test strategy

### A6 — backup/restore overlay

Extend `tests/adminBackup.test.ts`:
- Existing test verifies tarball contains `dump.pgcustom` + `metadata.json`.
- Add: pre-create some files under `ARTIFACT_DIR/sbom/` and `ARTIFACT_DIR/sarif/`, run the backup endpoint, untar the response, assert `artifacts/sbom/*.json` and `artifacts/sarif/*.sarif.json` are present with correct contents.
- Add: empty artifact dir → tarball still works (no `artifacts/` entry).

Extend `tests/adminRestore.test.ts`:
- mode=full: pre-create live artifact files, restore a tarball with different artifact files, assert live dir matches tarball after restore.
- mode=runtime: same as above, plus assert mode=runtime fails 422 when tarball's `artifacts/` contains a scan_run_id not in the dump's `scan_runs.id` set.
- Old-format (no `artifacts/`, old `sastbot_dump_format_version`): restore should leave live artifact dir untouched (mode=runtime) / wiped-empty (mode=full).

Extend `tests/restoreService.test.ts`:
- A6.4 pre-flight orphan detector returns the right violation list.

### B1 — `sbom_emit`

New `tests/sbomEmit.test.ts`:
- Insert a scan_run + scope + 10 sbom_components rows. Call `emitSbomArtifact(scanRunId)`. Assert the file exists at `sbomPathFor(scanRunId)`, parses as valid JSON, has 10 components in the right order (Stream D determinism).
- Round-trip: call `emitSbomArtifact` twice on unchanged data. Assert byte equality (the file's whole point).
- Empty scan: no sbom_components → returns `{ written: false }`, file not written.

### B2 — `sbom_ingest`

New `tests/sbomIngest.test.ts`:
- For source=cdxgen: phase runs, sbom_components row count unchanged.
- For source=upload: write a canonical doc to disk, call `ingestSbomFromArtifact`, assert sbom_components matches the doc. Re-run, assert idempotent (rows still match, no duplicates).
- Missing file: throws with clear error.

### B4 — `sarif_emit`

New `tests/sarifEmit.test.ts`:
- Insert sast_issues, call `regenerateSastSarifForScan`, assert file exists and contains the SARIF doc.
- Failure mode: pre-make the artifact dir read-only, assert the worker records the `sarif_emit_failed` warning.

### B5 — backfill

New `tests/backfillArtifacts.test.ts`:
- Pre-populate a scan_run with `sbomJson` (raw cdxgen) and `sastSarif`. Run the CLI script in-process. Assert files appear on disk with curated content for SBOM, raw bytes for SARIF.
- Re-run the script: no new writes (idempotent).
- Drop the columns programmatically (test fixture), re-run: exits 0 cleanly.

### B6 — endpoint switch

Extend the existing scan-detail test file (or add `tests/scansSbomEndpoint.test.ts`):
- Pre-create artifact files, call `GET /scans/:id/sbom`, assert body matches file.
- ETag round-trip: send `If-None-Match` with the right hash, assert 304.
- Missing file: 404 with the existing detail message.

### Phase enum

No new test — the existing schema tests + integration tests cover Zod validation of the enum. Adding three values is a non-breaking change to existing callers (no removed values).

### Side task: `DELETE /api/scans/:id`

New `tests/scansDelete.test.ts`:
- Happy path: scan that's NOT the scope's lastScanRunId → 200 + row gone + artifact files gone.
- 409: scan IS the scope's lastScanRunId → no deletion happens, response includes the guidance message.
- 404: unknown id / wrong org.
- 400: scan still pending/running → refuse.
- Auth: non-admin → 403.

---

## 14. Open questions

Before sign-off, two things to confirm:

### B-Q5 — Should `sbom_emit` re-emit when an operator edits a scope_component via the PATCH endpoint?

Today the scope-page SBOM endpoint (`GET /api/scopes/:id/sbom-json`) re-derives from `scope_components` on every call, so operator edits flow through automatically. The **scan-level** SBOM file (B1) is a snapshot of `sbom_components` at scan-end and **does not** reflect operator edits to `scope_components` (which would be the wrong semantic anyway — the scan-level file is per-scan immutable audit).

**Recommendation:** no re-emit on operator edit. Scan-level file = scan-time snapshot. Operator edits → scope-level endpoint. This matches the M7 "scope vs scan" separation. Confirm.

### B-Q6 — What's the upgrade path for clusters already at A6 but not B1–B4?

Between Deploy 1 and Deploy 2, no artifact files are being written. A6's tarball will include an `artifacts/` directory with whatever pre-existing files are there (probably none for a fresh A6 deploy). A6 restore-runtime's orphan pre-flight (A6.4) will pass trivially.

**Not a blocker** — A6 is internally consistent without B1. Just worth noting in the PROGRESS.md entry for Deploy 1 so the next maintainer doesn't expect to see artifact files appear immediately.

---

## 15. Side task: `DELETE /api/scans/:id`

**Touches:** `backend/src/routes/scans.ts`, `backend/src/services/scanService.ts`.

### Behavior (locked B-Q4)

```
DELETE /api/scans/:id   (admin only, requireAdmin preHandler)

1. Load scan_runs row, scoped to org. 404 if not found.
2. If status in ('pending','running'): 400, suggest /scans/:id/cancel first.
3. Look up scope.lastScanRunId for this scan's scope.
   If scope.lastScanRunId === scan.id:
     409 Conflict {
       detail: "Cannot delete the scan currently anchoring this scope's
                truth set (it's scope.lastScanRunId=<id>). Trigger a new
                scan first, then delete this one."
     }
4. prisma.scanRun.delete({ where: { id } })
   — cascades sbom_components, scan_findings, sast_findings, scan_run_components
5. deleteScanArtifacts(scanRunId) — best-effort, log warnings on failure
6. 204 No Content
```

### What about sast_issues / sca_issues whose `lastSeenScanRunId === scan.id`?

These are scope-level rows (not FK'd through scan_runs.id; the column is just a denorm). After the scan_run is gone, their `lastSeenScanRunId` points at a dangling UUID. Two options:

- **(a) Leave them.** The next scan will re-anchor or re-merge. UI may show "last seen in scan: <missing>" briefly. Cheap.
- **(b) Re-anchor.** Find the next-most-recent scan_run for the same scope that has this issue, update `lastSeenScanRunId` + `lastSeen*` denorms. More correct but ~2x query cost per deleted scan.

Per the locked guard ("refuse delete if it's lastScanRunId"), option (a) is the safer call: the deleted scan is by definition not the latest, so most rows already point to a newer scan. Only `sast_issues` / `sca_issues` whose newest sighting is the deleted scan are affected, and they should arguably be soft-removed anyway (their newer state hasn't been confirmed). Recommended: **(a)** for v1; revisit if it causes UI confusion.

### Service signature

```ts
// services/scanService.ts
export class ScanIsCurrentLatestError extends Error {
  constructor(public readonly scopeId: string, public readonly scanRunId: string) {
    super("Scan is the scope's lastScanRunId");
  }
}

export async function deleteScanRun(scanRunId: string, orgId: string | null): Promise<void> {
  const run = await prisma.scanRun.findFirst({
    where: { id: scanRunId, orgId: orgId ?? null },
    select: { id: true, scopeId: true, status: true },
  });
  if (!run) throw new ScanRunNotFoundError();
  if (run.status === "pending" || run.status === "running") {
    throw new Error(`Scan is still ${run.status}; cancel it first.`);
  }
  const scope = await prisma.scanScope.findUnique({
    where: { id: run.scopeId },
    select: { id: true, lastScanRunId: true },
  });
  if (scope?.lastScanRunId === run.id) {
    throw new ScanIsCurrentLatestError(scope.id, run.id);
  }
  await prisma.scanRun.delete({ where: { id: run.id } });
  await deleteScanArtifacts(run.id).catch((err) => {
    logger.warn({ err, scanRunId: run.id }, "[scanService] artifact cleanup failed");
  });
}
```

### Route handler

Standard Zod-typed endpoint in `routes/scans.ts`. 204 on success; 409 (ScanIsCurrentLatestError), 400 (still-running), 404 (not found), 403 (non-admin) error envelopes.

---

## 16. Deliverables summary

| Deploy | Branch / PR | Version | Touches |
|---|---|---|---|
| 1 | `m9-stream-a6-backup-restore-artifacts` | 0.5.1 → 0.6.0 | adminBackup, adminRestore, restoreService, backupMetadata, version, **3-file version bump** |
| 2 | `m9-stream-b1-b4-emit-ingest` | 0.6.0 → 0.7.0 | worker, sbomCurated, sarifService, sbomIngest (new), schemas, frontend types, **3-file version bump** |
| 3 | `m9-stream-b5-b6-drop-jsonb` | 0.7.0 → 0.8.0 | cli/backfillArtifacts (new), prisma schema + migration, docker-compose, worker (cleanup), scans routes, sbomService + sbomOccurrences (read source switch), **3-file version bump** |
| Side | `m9-side-delete-scan` | bundle with any of the above | scans routes, scanService, tests |

Each deploy is its own PR-shaped commit cluster, with one or more commits per deploy. `docs/PROGRESS.md` gets an entry per deploy.

**3-file version bump** = `backend/package.json` + `frontend/package.json` + `APP_VERSION` in `backend/src/routes/version.ts`. Agents have repeatedly missed `APP_VERSION` (B1–B4 sub-agent did) — list it explicitly in the brief. After bumping, restart the backend and verify with `curl -s http://localhost:8000/version | jq .app` showing the new value.
