# M9 — pre-existing bugs to address after Deploy 3

> **Trigger:** these are validation-round findings from real scans (FSS + Gocator Classic /GoWeb, 2026-05-22) that are **not** in Stream B scope. Address as a single cleanup commit cluster after Deploy 3 (B5+B6) ships and the E2E closure gate in `docs/M9_E2E_TEST_PLAN.md` is run.
>
> **Pinned reference from `CLAUDE.md` "For AI agents" section** so the post-Deploy-3 maintainer can't miss it.

Numbered to match the validation report so cross-references stay stable.

---

## Issue 1 — `scan_runs.component_count` denorm goes stale on recheck recovery

**Status: ✅ DISSOLVED by M9 Stream E** (see `docs/M9_STREAM_E_PLAN.md`). After E1 ships, `componentCount` is written once at ingest from the file's component count, and downstream phases (recheck-recovery, rebuildComponentsFromScopeState) no longer touch `sbom_components` for this scanRunId — so the denorm cannot drift. Keeping the section heading + original write-up so the post-E1 maintainer has the historical context.

---

(Original write-up below — kept for context.)

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

**Status: ✅ FIXED 2026-05-22** in commit to follow (fix(m9): LLM prompt/schema mismatch dropping SAST + SBOM findings; bump 0.8.1)

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

**Status: ✅ DISSOLVED by M9 Stream E** (see `docs/M9_STREAM_E_PLAN.md`). After E1 ships, the scan-page SBOM is built from this scan's direct observations only (file-first emit, before any recheck/merge runs). The scope-page SBOM continues to integrate recheck verdicts. Divergence between the two endpoints becomes meaningful and expected: `scan SBOM ≤ scope SBOM`, with the delta being exactly the recheck-recovery + merge work done by scope-update phases. No documentation patch needed because the architecture now matches operator mental model. Keeping the section + original write-up so the post-E1 maintainer has the historical context.

---

(Original write-up below — kept for context.)

**Symptom.** GOC scan reported `mergedRowsRemoved: 1` from the SBOM recheck (`worker.ts:~1463`). Final state: `sbom_components` has 2439 rows, `scope_components` has 2438 — one fewer in the scope. The artifact file (per-scan, from sbom_components) has 2439; the scope-level SBOM endpoint (from scope_components) has 2438.

**Root cause (likely).** Per the M7 design described in CLAUDE.md, the LLM SBOM recheck can issue a `merge` verdict that collapses two scope_components rows for the same logical component (e.g. when the LLM identified them as variants and one is the canonical). The merge deletes one of the scope_components rows but does NOT delete the historical `sbom_components` rows from past scans that referenced it. Per-scan sbom_components from the *current* scan also retain both rows because they were written by `persistAugmentedComponents` *before* the recheck merge ran.

This is structurally consistent with the M7 audit-vs-truth split, but it means the scan-page SBOM (artifact file) and the scope-page SBOM intentionally disagree by the merge delta. **That's working as designed but operator-visible and confusing**: "why does my scope show 2438 packages but the scan that just ran shows 2439?"

**Decision needed before fix.** Two valid postures:
- **(a) Accept the divergence as correct.** The scan page is the audit trail; the scope page is the operator-edited truth. Document the discrepancy in CLAUDE.md's "Two-table component model (M7)" section so the next maintainer doesn't think it's a bug.
- **(b) Re-emit the per-scan artifact after the merge logic settles.** I.e. move `sbom_emit` strictly after recheck *and* delete the pre-merge sbom_components row in the same step. This makes both endpoints agree (both show 2438) at the cost of losing the pre-merge audit trail.

**Recommended:** (a) is the cheapest and matches the M7 architecture. Adding a documentation note to CLAUDE.md is the entire fix.

**Tests.** None for (a). For (b) it'd be an integration test that triggers a merge and asserts both endpoints return the same component set.

---

## Issue 6 — SBOM `tools.components.SASTBot.version` hardcoded to milestone tag, not `APP_VERSION`

**Symptom.** Closure-gate Phase 1.5 (2026-05-22): the canonical SBOM served by `/scans/:id/sbom` (and the file written by `sbom_emit`) reports `metadata.tools.components[0].version = "M6q"`. APP_VERSION is `0.8.0`. SARIF correctly reports the running APP_VERSION; only the SBOM is wrong. CRA-evidence consumers cannot tell which app version produced a given SBOM file.

**Root cause.** `backend/src/services/sbomCurated.ts:140`:

```ts
const SBOM_TOOLS_COMPONENTS: Array<{ name: string; version?: string; type: string }> = [
  { type: "application", name: "SASTBot", version: "M6q" },
  { type: "application", name: "cdxgen", version: "12.2" },
];
```

The literal `"M6q"` was a milestone tag committed long before the version-consolidation commit (`8aabf7e`). CLAUDE.md explicitly forbids hardcoded version strings outside `routes/version.ts` ("Every runtime version surface ... imports from `APP_VERSION`"). The 0.7.0 → 0.8.0 bump in Deploy 3 missed this site because the `M6q` literal doesn't grep as a version number.

**Fix.** Import `APP_VERSION` into `sbomCurated.ts` and inline it: `version: APP_VERSION` (or, since both builders share the constant, lift it to a getter so the value can't drift across two bumps).

```ts
import { APP_VERSION } from "../routes/version.js";
// ...
const SBOM_TOOLS_COMPONENTS = [
  { type: "application", name: "SASTBot", version: APP_VERSION },
  { type: "application", name: "cdxgen", version: "12.2" },
];
```

Note: this changes the SBOM byte output on every version bump. The determinism contract (Stream D) is about *same scan, two reads* — bumping APP_VERSION between reads legitimately changes the file. ETag will re-compute; that's the right semantic.

**Tests.** Add an assertion to `sbomCurated.deterministic.test.ts`: the emitted SBOM's `tools.components[0].version` equals `APP_VERSION`. Catches the next milestone-tag-hardcoding mistake at unit time.

---

## Issue 7 — Stale `ALLOWED_PHASES` allowlist swallows new phase names in the API

**Symptom.** Closure-gate Phase 1.4 (2026-05-22): the API returns `current_phase: null` whenever the worker is in `llm_sbom`, `llm_sbom_recheck`, `sbom_emit`, `sbom_ingest`, `sarif_emit`, or `nvd`. The DB column has the correct value (verified via direct psql query). The Zod response schema (`backend/src/schemas.ts:430-436`) lists all the new phases correctly. Only the mapper layer drops them.

**Root cause.** `backend/src/services/mappers.ts:44-47`:

```ts
const ALLOWED_PHASES: ReadonlyArray<ScanPhase> = [
  "cloning", "cdxgen", "osv", "eol",
  "llm_detection", "llm_recheck", "sca_summaries", "finalizing",
];

function toPhase(value: string | null): ScanPhase | null {
  if (value === null) return null;
  return (ALLOWED_PHASES as ReadonlyArray<string>).includes(value)
    ? (value as ScanPhase)
    : null;
}
```

When the M6p Stage 2 work (`llm_sbom` / `llm_sbom_recheck`), M9 B1/B2/B4 (`sbom_emit` / `sbom_ingest` / `sarif_emit`), and the NVD addition were shipped, the Zod enum + frontend label map were both updated — but this allowlist was missed. Result: the scopes-list "Last Scan" cell and the scope detail page banner show blank/empty during ~80% of a scan's wall-clock time.

**Fix.** Replace the hardcoded array with a derivation from the Zod enum so the two can't drift again:

```ts
import { ScanRunOutSchema } from "../schemas.js";

const ALLOWED_PHASES: ReadonlyArray<ScanPhase> =
  ScanRunOutSchema.shape.current_phase.unwrap().options as ReadonlyArray<ScanPhase>;
```

(Or, if circular imports get in the way, copy the union literal but add a unit test that asserts equality with the Zod enum.)

**Tests.** Add a unit test asserting `toPhase("sbom_emit") === "sbom_emit"` for every value in `ScanRunOutSchema.shape.current_phase`. Catches the next phase addition that misses the allowlist.

---

## Issue 8 — Named `sastbot_backend_node_modules` volume shadows freshly-built Prisma client

**Symptom.** Closure-gate pre-flight (2026-05-22, immediately after the Deploy-3 image rebuild): the `/api/scans` list endpoint 500s with `Invalid prisma.scanRun.findMany() invocation ... The column scan_runs.sbom_json does not exist in the current database.` The image was rebuilt cleanly (`pnpm prisma generate` ran in the Dockerfile per `docker/backend.Dockerfile:72`), but the running container served stale TypeScript types AND a stale generated client that still referenced the dropped columns.

**Root cause.** `docker/compose/docker-compose.yml:67`: `sastbot_backend_node_modules` is a named volume mounted over `/app/backend/node_modules`. The container image's freshly-regenerated client lives at that path inside the image — but the named volume, populated on FIRST container creation, shadows the image's contents every time the container restarts. Same volume is reused across `docker compose up --build`.

The user-facing fix (which I executed manually): `docker compose exec backend pnpm prisma generate && docker compose restart backend worker`. That writes the new client into the named volume.

The systemic fix: either drop the named volume (let node_modules ride in the image, accept slower bind-mount development) OR have the entrypoint script always regenerate Prisma on boot:

```sh
# Add to docker/backend-entrypoint.sh BEFORE prisma migrate deploy:
pnpm prisma generate || true
```

The `pnpm prisma generate` step is ~300ms, so the cost is negligible and it idempotently aligns the client with `schema.prisma` every time.

**Operator impact of NOT fixing.** Every future schema migration will require manual `pnpm prisma generate` after rebuild, and the failure mode is silent (no error during build/restart — the broken Prisma calls only surface when end-users hit the endpoint). Multiple agents have re-discovered this same trap historically; the named-volume / image-baked-client interaction is non-obvious.

**Tests.** Not unit-testable. The fix is operational (entrypoint script change).

---

## Issue 9 — LLM SAST parse errors silently zero out a scan's SAST findings

**Status: ✅ FIXED 2026-05-22** in commit to follow (fix(m9): LLM prompt/schema mismatch dropping SAST + SBOM findings; bump 0.8.1)

**Symptom.** Closure-gate Phase 1 (2026-05-22, FSS scan `37d42b21-e54b-44d5-bdd0-d4ad78c78d18`): scan completed with `status=success` but `sast_finding_count=0` (vs. 42 on the prior FSS scan). Single warning: `llm_sast_parse_errors` (info severity) — 74 unparseable records. The dropped records contain real, critical findings the LLM clearly identified — examples from the warning details:

- `CWE-22` path traversal in `kFireSync/kFireSync/Sensor/Internal/Web/kSnHttpServer.cpp:212-213`, severity **critical**
- `CWE-347` unverified firmware update in `kFireSync/kFireSync/Upgrade/kUpgrader.cpp:220-240`, severity **critical**
- `CWE-345` insufficient verification of data authenticity in `kSnHttpServer.cpp:307-316`, severity **critical**
- `CWE-327` broken crypto in `kApi/kApi/Crypto/kBlowfishCipher.cpp:318-324`, severity medium

All have full CVSS vectors and start/end lines. None made it into `sast_issues` because Zod rejected them.

**Root cause.** `backend/src/services/llmSastService.ts:39-54` — the `SastRecord` schema requires:

```ts
file_path: z.string(),          // ← LLM emitted `file` instead
summary: z.string(),            // ← LLM emitted `title` instead (or omitted)
confidence: z.number().min(0).max(1),  // ← LLM omitted
reasoning: z.string(),          // ← LLM omitted
```

The prompt `backend/prompts/sast_detection.md:77,145` correctly instructs the LLM to emit `file_path`/`summary`/`confidence`/`reasoning`. On this run (Opus 4.7 with `xhigh` effort) the LLM drifted to a more concise schema: `file`, `title`, no confidence, no reasoning. Output is real and valuable; schema rejected it wholesale.

Same class of bug as [[Issue 2]] (SBOM `evidence_path: Required`). LLM output isn't deterministic — the schema needs to be defensively forgiving of common name aliases and missing soft fields.

**Operator impact of NOT fixing.** Highest-severity item in this followup queue. A scan can complete with `status=success`, zero SAST findings, only an `info` warning to flag the problem. Operators looking at the scope page see "great news, no SAST issues" — falsely. The bug is non-deterministic: the same repo, same prompt, same model produces 42 findings one scan and 0 the next.

**Fix.**

```ts
const SastRecord = z.object({
  kind: z.literal("sast"),
  cwe: z.string(),
  severity: SeverityEnum,
  cvss_vector: z.string().optional(),
  // Accept both names; normalize to file_path downstream.
  file_path: z.string().optional(),
  file: z.string().optional(),
  start_line: z.number().int().nonnegative(),
  end_line: z.number().int().nonnegative(),
  // Accept both names; normalize to summary downstream.
  summary: z.string().optional(),
  title: z.string().optional(),
  snippet: z.string().optional(),
  // Soft fields — sensible defaults if the LLM didn't emit them.
  confidence: z.number().min(0).max(1).default(0.5),
  reasoning: z.string().default(""),
}).refine(
  (r) => !!(r.file_path || r.file),
  { message: "must provide file_path or file" },
).refine(
  (r) => !!(r.summary || r.title),
  { message: "must provide summary or title" },
).transform((r) => ({
  ...r,
  file_path: r.file_path ?? r.file!,
  summary: r.summary ?? r.title!,
}));
```

Apply the same defensive pattern to `SastAbsenceRecord` (already requires `summary`, `confidence`, `reasoning`) and `ReachabilityRecord`.

**Bonus:** tighten `sast_detection.md` to explicitly forbid `file`/`title` aliases and add a "VALIDATION FAILURES" section that shows the LLM how its output gets parsed, so future drift is more visible to the model. (Same treatment as recommended in Issue 2's bonus cleanup.)

**Tests.** Extend `tests/llmSastService.test.ts` (or create): parse a record with `file`/`title` → succeeds, normalizes to `file_path`/`summary`. Parse with neither `file_path` nor `file` → refine fails with clear message.

---

## Issue 10 — `llm_*_parse_errors` warnings should be error-severity when they drop a non-trivial fraction of records

**Symptom.** Both `llm_sbom_parse_errors` ([[Issue 2]]) and `llm_sast_parse_errors` ([[Issue 9]]) emit at **info** severity regardless of how many records were dropped. On the FSS 2026-05-22 scan, 74 / 74 SAST records and 19 / N SBOM records were dropped — 100% and ~60% — yet `hasErrorWarnings(scanRunId)` returned false. The M6i trustworthiness gate let `scope.lastScanRunId` advance to the degraded scan; the SCA auto-fix sweep also ran on this degraded snapshot.

**Why it matters.** Per CLAUDE.md M6i: "When adding new remediation logic that mutates issue state, gate it on `hasErrorWarnings`." That gate's whole purpose is to prevent a scan with no real signal from re-anchoring the scope's truth set. A scan that parsed zero of N SAST records is by definition a no-signal scan — it MUST flip to error severity.

**Fix.** Two options, recommended together:

1. **Emit a count-aware severity in the warning code path.** In `worker.ts` where `llm_sast_parse_errors` / `llm_sbom_parse_errors` warnings are appended, compute `droppedRatio = errors / (records + errors)` and emit at `error` severity when `droppedRatio >= 0.5` (or any other operator-tunable threshold). Below that, keep `info`.
2. **Emit at `error` severity unconditionally when the parsed-records count is zero.** Belt-and-braces: a scan that emitted zero records of a given kind shouldn't anchor the scope, period.

**Operator impact of NOT fixing.** Combined with [[Issue 9]] and [[Issue 2]], a single bad LLM response can quietly destroy the scope's SAST findings AND its SBOM by re-anchoring `lastScanRunId` to a near-empty snapshot. Two failure modes stack: schema rejects records, *and* the gate doesn't catch the degraded result.

**Tests.** Unit test on the appendWarning code path: simulate 100% parse failure → severity is `error`. Simulate 5% → severity is `info`.

---

## Issue 11 — Settings page credential pickers display blank for already-selected credentials

**Symptom.** Closure-gate session (2026-05-22): opening `/admin/settings` against a stack with all three credentials wired (jira, llm, nvd) shows three blank-looking `Select` widgets. Operator can't tell what's selected, and naturally worries that "Save" will write nulls.

**Verified-safe behaviour.** `SettingsPage.tsx:75-93` `useEffect` correctly hydrates `jiraCredId` / `llmCredId` / `nvdCredId` state from the settings query. `buildPayload` at lines 147-161 sends those state values (deliberately *omitting* the key when state is empty, not setting it to null). `settingsService.ts:35,46,57` uses `Object.prototype.hasOwnProperty.call(input, "...")` to detect mutation intent, so a missing field preserves the existing connection. **Saving is safe** — only the display is broken. This is structurally different from the `ReposPage.tsx:528` bug (which uses `|| null`).

**Root cause.** Radix UI `Select` (which shadcn wraps) can't resolve `value="<uuid>"` to a matching `<SelectItem>` if the SelectItem hasn't mounted yet. Race: `useSettings` resolves first (small payload) and hydrates the state; `useCredentials` is still in flight; the Select renders with a `value` but no matching options. When credentials arrives, the trigger's displayed label doesn't refresh — a known Radix quirk.

**Fix shipped locally during closure-gate session.** `SettingsPage.tsx` — added `isLoading?: boolean` prop to `CredentialPicker`, plumbed `credentials.isLoading` through all three pickers, and render a disabled `<Select>` with `"Loading credentials…"` placeholder while loading. Once credentials arrives the real Select mounts with options already present, so the value-to-SelectItem match succeeds on first render. Local edit; pending commit in this followup cluster.

**Same pattern in `ReposPage.tsx`.** Apply the equivalent fix there. The repo page has the harder-to-recover variant of the bug because its `buildPayload` sends `credential_id || null` — meaning if the Select state were ever empty at save time, the credential would be cleared. The display fix is the same; consider also tightening `ReposPage` to mirror `SettingsPage`'s "omit instead of null" pattern.

**Tests.** Add a component test mounting `SettingsPage` with a delayed `useCredentials` response, asserting the picker shows the loading placeholder and then the correct credential name after credentials resolves.

---

## Issue 12 — `deleteRepo` leaks `/app/clones/<repoId>` for retained-clone repos

**Status: open.** Surfaced by closure-gate Phase 6.3 on 2026-05-23.

**Symptom.** `DELETE /api/admin/repos/:id` against a repo with
`retain_clone=true` (and a populated `/app/clones/<repoId>` on the worker
volume) correctly cascades the DB rows (`scan_runs`, `scan_scopes`,
`scope_components`, `sast_issues`, `sca_issues`, `sbom_components`) AND
removes the per-scan artifact files at `/var/lib/sastbot/artifacts/{sbom,sarif}/<scanRunId>.*`.
But the retained clone directory at `/app/clones/<repoId>` is left
untouched. Other repos' clones are unaffected (no blast radius), so this
is a strictly-additive disk leak.

**Root cause.** `repoService.ts:221-238` (`deleteRepo`) only calls
`deleteScanArtifacts` per scan run. It never touches the clone cache.
The clone-cache writer (`repoCache.ts`) and the clone-cache purge code
that exists for the toggle path (`retain_clone: true → false`) both know
about the path; they just aren't invoked by repo deletion.

**Operator impact.** Slow disk leak in any deployment that uses
`retain_clone=true`. Per-repo footprint scales with repo size (FSS-class:
~100MB; large monorepo: GBs). Doesn't break anything functionally —
filesystem just fills up over time.

**Fix.** After the `Promise.allSettled(...deleteScanArtifacts...)` line
(repoService.ts:237), add a best-effort `fs.rm(path.join(CLONE_CACHE_DIR,
id), {recursive, force})`. Mirror the existing artifact-cleanup pattern:
log a warning on failure but don't roll back the DB delete. The DB row is
already gone — the clone path is reachable only via the deleted ID, so
it's strictly orphaned once the delete commits.

**Tests.** Add a `repoService.deleteRepo` test that pre-creates a fake
directory at `<tmpCloneDir>/<repoId>`, runs deleteRepo, and asserts the
directory is gone. Pure-function — no DB needed if the path resolution
is extracted (or mock `prisma.repo.delete` + `prisma.scanRun.findMany`).

**Operator workaround until shipped.** After deleting a repo with
`retain_clone=true`, manually `rm -rf` the matching directory on the
worker:

```sh
docker compose exec worker rm -rf /app/clones/<repoId>
```

---

## Process improvement — agent brief checklist (separate from issue queue)

The 2026-05-22 validation surfaced this as a recurring pattern. The B1–B4 sub-agent missed bumping `APP_VERSION` even though the brief listed both `package.json` files. Already addressed in commit `8aabf7e` (consolidated all version surfaces under `APP_VERSION`, updated CLAUDE.md policy, added explicit "3-file version bump" reminder to plan docs).

**No further action.** Just noted here so the post-Deploy-3 maintainer sees the cleanup history was actively curated, not accidental.

---

## How to use this doc

After Deploy 3 (B5+B6) ships AND the closure gate (`docs/M9_E2E_TEST_PLAN.md`) passes:

1. Read this doc.
2. Open one PR-shaped commit cluster titled `fix(m9-followups): post-deploy-3 cleanup`.
3. Address Issues 6, 7, 8, 10, 11, 12. (2 and 9 fixed in v0.8.1; **1 and 5 dissolved by M9 Stream E** — see `docs/M9_STREAM_E_PLAN.md`; 3 dissolved with the no-backfill posture; 4 is infra-not-code.) Issue 10 is the highest-priority remaining item — it can let the scope re-anchor to a near-empty result when parse-error drop ratio is high. Issue 7 (`ALLOWED_PHASES` allowlist) needs the `sast_ingest` phase added when Stream E2 ships, in addition to the existing phases it's missing. Issue 12 (clone-cache leak on repo delete) is small and standalone — easy starter from this list.
4. Delete this file in the same commit, OR retain it with a "✅ Closed YYYY-MM-DD" header and a one-line summary per issue.
5. Remove the pin from CLAUDE.md "For AI agents" section.

**Note on Issues 6–12 origin.** Issues 6–11 surfaced by the 2026-05-22 closure-gate run; Issue 12 by the 2026-05-23 continuation:
- 6 — `SASTBot.version` hardcoded to `"M6q"` in `sbomCurated.ts`
- 7 — `ALLOWED_PHASES` allowlist stale in `mappers.ts`
- 8 — named-volume Prisma client shadowing on rebuild
- 9 — LLM SAST schema rejects valid records (sibling of Issue 2)
- 10 — parse-error warning severity should escalate to `error` when drop ratio is high
- 11 — Settings page credential picker shows blank for already-selected credentials (display fix shipped locally as part of this cluster's pending commit)
- 12 — `deleteRepo` leaks `/app/clones/<repoId>` for retained-clone repos (closure-gate Phase 6.3 finding)

They are documented here rather than fixed inline to keep Deploy 3 surgical and to bundle all post-Deploy-3 work into one cluster as planned.
