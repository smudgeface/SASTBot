# Architecture notes & invariants

Subsystem-level knowledge and hard-won invariants for contributors and AI agents.
These used to live inline in `CLAUDE.md`; they were moved here to keep the agent
guide lean. When you touch one of these subsystems, read the matching note first —
most encode a bug we already paid for once.

Companion docs: [`SCAN_LIFECYCLE.md`](SCAN_LIFECYCLE.md) (scan-run state machine),
[`MIGRATIONS_CHECKLIST.md`](MIGRATIONS_CHECKLIST.md), [`OPERATIONS.md`](OPERATIONS.md).

---

## Routing & request conventions

- **All domain routes live under `/api/*`.** Route files (`backend/src/routes/*.ts`) use
  **bare paths** in their `typed.METHOD("/foo", …)` calls — the parent register in
  `server.ts` adds the `/api` prefix to the whole bundle. `/healthz`, `/version`,
  `/openapi.json`, and `/docs` stay at the root. New routes: pick the existing file that
  fits (`scopes.ts` for issue/scope work, `adminRepos.ts` for repo CRUD, etc.) or add a
  new file and register it inside the `/api` block in `server.ts`. Frontend call sites can
  use either bare paths or `/api/`-prefixed paths — `apiFetch` normalises both. The Vite
  dev proxy + production nginx both route `/api/*` to backend `:8000`.
- The `backend/` and `worker` compose services share the same image; they differ only by
  `command`.
- The scan detail page (`/scans/:id`) is a demoted audit view since M5b. Primary UX is
  `/scopes`.
- Jira integration is read-only. No ticket creation. `jiraClient.ts` handles all Jira HTTP.
- **`StatusBadge` always shows the true status.** No "implicit" overrides based on Jira
  linkage or anything else. Transitions are explicit — either through the link/unlink flow
  (which only auto-transitions `pending`/`confirmed` → `planned`) or through the
  next-status buttons in the expanded row.
- **Source URL template** on the repo (`repos.source_url_template`, supports `$FILE` and
  `$LINE` placeholders) drives the `<FileLink>` component in the SAST/SCA detail views.
  Wrap any path span in `<FileLink template={scope.source_url_template} file=… line=…>`;
  with no template it's a plain span.

## Worker-startup backfills

`worker.ts` runs idempotent backfills on boot: `backfillLlmSummaries`,
`backfillCvssScores` (vector→score, plus re-queries OSV for rows missing both),
`backfillReachability`, `backfillManifestOrigin`, `backfillManifestPathPrefixes`,
`backfillScanRunSeverities`, `backfillDevOnlyScaIssues` (M6n — sets
`dismissedStatus='suppressed', dismissedReason='dev_tree_policy'` on dev-only SCA issues
for repos with `includeDevDeps=false`), `backfillReopenFalseFixedScaIssues` (0.24.0 —
reopens auto-`fixed` SCA issues (`dismissed_at IS NULL`) whose component is still
active+present in the scope's latest scan, healing the pre-0.24.0 sweep/recovery
false-fix bug; see the SCA auto-fix note below). Each filters its own work and is safe to
re-run.

Adding a new column that needs to be filled in for existing data? Mirror this pattern
instead of forcing users to re-scan — **but** if the backfill touches `scope_components`,
use a one-off Prisma migration instead. M7 deleted `backfillScopeComponentsFromLatestScans`
after it silently duplicated version-NULL rows on every worker restart; scope-level state
is now bootstrapped natively by the scan flow. M9 Deploy 3 deleted `backfillSastSarif`,
`backfillSbomManifestFiles`, and `backfillSbomOccurrences` — all three read from
`scan_runs.sbom_json`/`sast_sarif` columns that were dropped in that deploy.

## Live scan progress (M6i)

`scan_runs.current_phase` (TEXT) + `phase_progress` (JSONB `{done, total, label?}`)
populated by `setPhase(scanRunId, phase, progress?)` at every worker phase boundary.
Cleared on terminal status. UI surfaces: scope detail page banner, scopes list "Last Scan"
cell, scan detail page card. `useScopes()` polls every 3s while any scope has an active
scan. Phase enum: `cloning | cdxgen | llm_sbom | llm_sbom_recheck | sbom_persist |
sbom_emit | osv | nvd | eol | llm_detection | sarif_emit | sast_ingest | llm_recheck |
sca_summaries | finalizing`. When adding a new phase, update the enum in `schemas.ts` AND
`SCAN_PHASE_LABELS` in the frontend types.

## Failed scans don't affect the scope (M6i + M12)

`ScanWarning` carries `severity: "info" | "error"`. Any `error`-severity warning emitted
during the scan causes the worker to set `status = "failed"` at finalize. Failed scans do
NOT update the scope: `lastScanRunId` doesn't advance, `lastScanCompletedAt` doesn't
advance, the SCA auto-fix sweep is skipped, and the SAST recheck `fixed`/`file_deleted`
verdict branches no-op (still_present is unaffected — confirming an existing issue isn't
destructive). The single helper is `hasErrorWarnings(scanRunId)` in
`backend/src/services/scanWarnings.ts`, checked at three places: SCA sweep gate
(worker.ts), SAST recheck gate (passed into `applyRecheckVerdicts` as `untrustworthy`),
and finalize (sets `status: untrustworthy ? "failed" : "success"`). Per-scan data written
before the failure (sbom_components, sca_issues, sast_issues with
`lastSeenScanRunId = failed_scan_id`) is kept for audit and visible on the failed scan's
detail page only — the scope's default issue filter pivots off `lastScanRunId` so
operators see the last successful scan's state. There is NO separate "untrustworthy"
surface (no chips, no banner) — the lifecycle `status` is the only signal. **When adding a
new remediation path that closes / hides findings, gate it on `hasErrorWarnings`.**

## Worker pre-flights & typed clone-failure warnings (M6q review)

Before the cdxgen phase, the worker `stat`s the configured scope dir; if missing, it emits
a typed `scope_path_missing` error warning and aborts. Catch block also maps
`RemoteUnreachableError` → `remote_unreachable`, `GitCloneError` with "Remote branch X not
found" → `branch_not_found`, auth-failed stderr → `auth_failed`, generic clone failure →
`clone_failed`. Each carries an operator-facing fix instruction. Without these, the
failures bubbled up as misleading "spawn cdxgen ENOENT" (Node's spawn returns ENOENT on a
missing `cwd` and blames the executable) and free-text `scan_runs.error` values that the
GUI didn't surface.

---

## SAST is LLM-driven (M6 onward)

`worker.ts` invokes `llmSastService.runDetection` (claude-p agentic pass) followed by
`runRecheck` (verifies any non-detected issue is genuinely fixed). Prompts live as text
files under `backend/prompts/`. The legacy Opengrep + `llmTriageService` code paths were
removed in M6g; if needed back, cherry-pick from the `c2c03e8` tree.

### Worker builds SAST snippets from disk (M6k)

The LLM identifies WHERE a problem is (`file_path` + `start_line` + `end_line`); the worker
reads the file via `sourceSnippet.readSourceSnippet` and produces a canonical
`SOURCE_CONTEXT_LINES` (3) lines before / problem region / 3 lines after window.
`SastRecord.snippet` and `RecheckVerdictRecord.current_snippet` are accepted but never
trusted. `sast_issues.latest_end_line` is nullable (legacy rows are NULL → treated as
single-line). The frontend `ContextSnippet` is a straight offset-based renderer — it
assumes the canonical layout. Don't reintroduce keyword-search fallbacks in the renderer;
if a row's snippet looks anomalous, fix the data via `backfillSastSnippets` (worker startup
hook). The same pattern applies to `reachability.call_sites[].snippet`.

### SARIF v2.1.0 export (M6j, M9 Stream B4/B6)

Every successful scan writes a SARIF document to `${ARTIFACT_DIR}/sarif/${scanRunId}.sarif.json`
by `regenerateSastSarifForScan` in the `sarif_emit` worker phase. Exposed via
`GET /scans/:id/sast-sarif` (download, with ETag) and the `/scans/:id/sast-sarif` viewer
route. Legacy scans (run before M9 Stream B) have no artifact file and the endpoint returns
404 with a re-run hint. Producer-shape only: no `fingerprints`, no triage / lifecycle
fields — those are RMS concerns per SARIF §3.27.23. CWE references go on the rule descriptor
via `relationships: [{target: CWE-N, kinds: ["relevant"]}]` against `runs[0].taxonomies[0]`
(the CWE taxonomy); results dereference through `ruleId`. **Don't emit `result.taxa[]` or
`result.fingerprints` or `properties.cwe` from this builder** — that's a redundant duplicate
of what's already on the rule. `region.startLine/endLine` is the problem location;
`contextRegion` carries the snippet text + the file-line range it spans.

### Per-repo, per-phase LLM effort (M6m)

`Repo.llmSastEffort` and `Repo.llmRecheckEffort` (enum text:
`low | medium | high | xhigh | max`, defaults `xhigh` and `medium`) are passed verbatim to
`claude -p --effort` from `spawnClaudeAndStream`. **Always pass `--effort` explicitly** —
Claude Code's product default differs by model (xhigh on Opus 4.7, high on Sonnet 4.6 per
the 4.7 release notes) and could change in future releases; relying on it makes scans
non-reproducible. `xhigh` is Opus-only; Sonnet silently degrades it. Per-phase split
because detection is open-ended search (wants depth) and recheck is narrow verification
(medium is fine). `AppSettings.llmTriageTokenBudget` was dropped in the same migration —
its `llmTriageService` was removed in M6g and the field had been orphaned since.

### Sibling-scope exclusions + `ignore_paths`

When a repo has overlapping scan paths or per-repo ignore paths,
`computeScopeExclusions(currentPath, [...scanPaths, ...ignorePaths])` yields the subdirs to
exclude (relative to the current scope's working dir). `runCdxgen` accepts the result as
`excludes: string[]`. The LLM SAST pass receives the excluded paths via the `IGNORE_PATHS`
block in `sast_detection.md`.

---

## SCA / SBOM

### Repo-level dependency-scope flags

`repos.reachability_enabled` (default true) gates the LLM SCA reachability portion of the
detection prompt. `repos.includeDevDeps` (DB column `include_dev_deps`, default false —
renamed from `reachabilityIncludeDevDeps` on 2026-05-28 because its role grew well beyond
reachability) gates **six consumers**: (1) the OSV/NVD query (dev-only components skipped
before the batch call), (2) the UI Components tab default view, (3) the UI SCA Issues tab
default view, (4) the LLM SCA hint set, (5) the SBOM component recheck
(`llmSbomRecheckService` drops dev-only from the candidate set entirely when false — they're
invisible everywhere, so rechecking them is token waste), and (6) the curated SBOM artifact
(`sbomCurated.ts` both builders exclude `isDevOnly=true` rows when false, so the SBOM matches
the Components tab). When false (the default), components/issues with `isDevOnly=true` are
hidden from all six by default; the UI exposes "Show dev-tool packages / CVEs" toggles, and
the Components/SCA tab hide-default tracks the flag via `scope.include_dev_deps` on the scope
payload. Driven by cdxgen 12.2+'s `cdx:npm:package:development=true` property, mirrored onto
`SbomComponent.isDevOnly` and `ScaIssue.latestIsDevOnly`. npm-only signal: non-npm
components have `isDevOnly=false` and stay in all six regardless of the flag. Caveat: cdxgen
issue #3927 — `devOptional: true` lockfile entries miss the marker. A per-repo
SBOM-inclusion control independent of this flag is deferred future scope.

### "Dev" badge sourcing

The "Dev" badge is sourced from `is_dev_only` / `latest_is_dev_only` — a truthful npm-only
classifier (cdxgen 12.2+ `dev: true` lockfile marker). Surfaces on the SCA issue row chip
strip and the Components tab. Do NOT key new badges on `scope === "optional"` — cdxgen lumps
both devDeps and transitive runtime deps into `optional`, so it's not a clean dev signal. The
raw scope value is still shown in the SCA expanded metadata for completeness only.

### Canonical package names include the group prefix

cdxgen splits scoped packages into `group` + `name` (e.g. `@types/node` arrives as
`group="@types", name="node"`). `sbomService.persistComponents` combines them via
`canonicalPackageName(c, ecosystem)` — `/` for npm (`@types/node`), `:` for maven
(`groupId:artifactId`). Storing the bare `name` collides with unrelated packages (e.g. `node`
was matching `eolService`'s Node.js runtime slug). When adding a new ecosystem, update the
joiner there.

### SCA auto-fix sweep (0.24.0)

The SCA auto-fix sweep (`scaAutoFix.ts`) marks every `sca_issue` with
`lastSeenScanRunId != currentScan` (and non-terminal status) as `fixed` — "a manifest entry
that disappeared IS the resolution". But component detection is non-deterministic for
generic/LLM-augmented libs (e.g. vendored `extern/Cuda`), so a component can flake out of one
scan's *direct* detection yet still be present. The `llm_sbom_recheck` phase recovers such
components: `materializeRecoveredComponents` bumps their `scope_components.lastSeenScanRunId`
and `synthesizeRecoveredSbomComponents` writes `sbom_components` rows tagged
`discoveryMethod="recheck_recovery"`. The worker then **re-reads** the `components` list
before OSV/NVD/EOL, so recovered components are queried for vulnerabilities in the same pass
as direct-observation components — their `sca_issues.lastSeenScanRunId` advances naturally
and the sweep cannot false-fix them. `backfillReopenFalseFixedScaIssues` heals pre-0.24.0
data (auto-`fixed`, `dismissed_at IS NULL`, component still active+present in the scope's
latest scan). The terminal-status set is the `TERMINAL_SCA_STATUSES` const (`scaAutoFix.ts`)
— mirror it anywhere that must not clobber operator/terminal decisions.

CycloneDX VEX `analysis.state` mapping lives in `sbomCurated.ts:analysisState`
(fixed→resolved, suppressed→not_affected, false_positive→false_positive,
confirmed/planned→exploitable, pending→in_triage); the curated SBOM keeps ALL issues
(resolved included) so the VEX record is complete and the per-component "linked issues" UI
list matches it.

### LLM SBOM augmentation pass (M6p Stage 2)

A new `llm_sbom` worker phase runs between cdxgen+Stage-1 and OSV. It invokes
`llmSbomService.runSbomAugmentation`, which writes the Stage-1-cleaned SBOM to a tmp file and
asks claude-p to emit keep/drop/add JSON-Lines records. `applySbomAugmentation` then applies
them to the in-memory CdxComponent list before `persistAugmentedComponents` writes to the DB.
Three repo fields control the pass:

- `repos.firstPartyNamespaces` (string[], default `[]`) — name prefixes the LLM treats as
  first-party and drops (e.g. `["GoSdkNet", "kApiNet", "LMI"]`). **Set this on every LMI repo
  at onboarding** — leaving it empty forces the LLM to drop first-party components via content
  inspection alone, which is more expensive and less deterministic.
- `repos.vendoredDirs` (string[], default `["extern/","third-party/","vendor/"]`) —
  directories the LLM scans for vendored libs cdxgen missed.
- `repos.llmSbomEffort` (enum text, default `medium`) — effort for the augmentation claude-p
  pass.

Components the LLM added or kept-with-rationale have `sbom_components.llmEvidence` (JSONB
`{path, excerpt, llmReason}`) populated. The Components tab in ScopeDetailPage shows an
info-icon tooltip on those rows. Failure mode: if the LLM pass errors, the worker emits an
`error`-severity warning (`llm_sbom_augmentation_failed`) and falls back to the Stage-1-only
component list — the scan still completes. Prompts: `backend/prompts/sbom_system.md` +
`backend/prompts/sbom_augmentation.md`.

### LLM-emitted version strings (M7 hardening)

The `AddRecord` Zod schema coerces `version` values of `"unknown"`, `"*"`, or `""` (trimmed,
case-insensitive) to `null` at parse time. Without this, the LLM could produce twin rows
(`pkg:generic/yaffs2` vs `pkg:generic/yaffs2@unknown`) that bypassed the
`(scan_run_id, purl)` unique index because their purls differed. Mirrors the same logic in
`nvdService.sanitizeVersion`. Catches LLM-output drift at the boundary instead of letting it
pollute DB state.

### SBOM endpoints (M9 Stream B6, locked decision B-Q1)

Two surfaces, different scopes:

- `GET /scans/:id/sbom` → **post-augmentation curated CycloneDX 1.7** for that specific scan
  run, served from `${ARTIFACT_DIR}/sbom/${scanRunId}.json`. Written by the worker's
  `sbom_emit` phase. Legacy scans (run before M9 Stream B) have no artifact file and return
  404 with a "re-run to produce artifact" message — the UI renders this as a friendly inline
  state, not an error toast. ETag is stable (file was written with `stableStringify`).
- `GET /api/scopes/:id/sbom-json` → **scope-level curated CycloneDX 1.7** built on demand by
  `sbomCurated.ts:buildCuratedSbomJsonForScope()` from `scope_components` rows, reflecting any
  operator edits. This is the primary CRA-compliance artifact. **TODO**: M7 moved the
  scope-page Components tab off `sbom_components` onto `scope_components`; the scope SBOM
  endpoint hasn't been migrated yet and may drift from the Components tab until it is.

The two endpoints serve the same content shape but different scopes: scan-run snapshot vs
operator-edited scope state. Don't unify them — the per-run vs per-scope distinction is
semantically meaningful.

---

## Two-table component model (M7)

Two related tables, separated by lifetime + mutability:

- `sbom_components` is **all components this scan believes present**, tagged by
  `discoveryMethod` (`manifest` | `vendored_inspection` | `recheck_recovery`). FK to
  `scan_runs`. Cascaded on scan delete. Holds `occurrences jsonb` (per-scan locations with
  optional line numbers). Read by the scan-detail page (`/scans/:id`). Has a unique index on
  `(scan_run_id, purl)` (added M7) so the rebuild step is genuinely idempotent. **The
  vulnerability-lookup stage (OSV/NVD/EOL) consumes the SBOM whole and never branches on
  `discoveryMethod`** — provenance is data, not control flow.
- `scope_components` is **scope-level durable state**. One row per logical component for the
  lifetime of the scope. Has `dismissedStatus` lifecycle (`active` | `not_found` | `ignored`)
  and orthogonal `source` (`scan` | `manual_override`). `not_found` = worker decision
  (evidence file missing or LLM-confirmed absent). `ignored` = operator decision
  (soft-suppress; sticky across scans). `firstSeenScanRunId` / `lastSeenScanRunId`,
  `componentRoot` (M7 dedup identity — shallowest repo-relative directory exclusively owned by
  the upstream library, e.g. `extern/Xenomai`), `evidence jsonb` (M7 — array of
  `{path, line?}` for the operator UI's clickable evidence list). Read by the scope-page
  Components tab. Mutated by the LLM merge step in recheck, the trashcan delete, the
  ignore/unignore routes, and the inline edit form.
- **Invariant: data flows scan → scope, never reverse.** Reading sbom_components →
  scope_components is allowed (`persistScanComponentsToScopeState` lifts data via the
  componentMatch chain). The reverse — a scan page query reaching into scope_components — is a
  bug.

### Deterministic component matcher (M7)

`componentMatch.ts` exports a 7-tier identity chain used for dedup in two places:

1. `applySbomAugmentation` (intra-scan): each LLM `add` is matched against cdxgen survivors
   AND prior accepted adds before synthesis. When two adds collapse, `pickCanonicalName` keeps
   the more-kebab-case form.
2. `persistScanComponentsToScopeState` (vs DB): each emitted sbom_component is matched against
   active scope_components for the scope. Tier hit drives an UPDATE; full miss inserts a new
   row with the strict `(scope_id, name, version, purl)` ON CONFLICT clause as a backstop.

The chain: (1) component_root exact, (2) component_root prefix containment, (3) CPE exact,
(4) CPE vendor+product (version-agnostic), (5) PURL exact, (6) normalized name (lowercase +
strip `[-_\s]` + drop `lib`) + version, (7) manifest_file + name. First match wins. **Never
assume `ON CONFLICT DO NOTHING` is meaningful without a matching unique constraint** — that
gap is what caused most of the M7 cleanup work.

### Operator-driven scope_components edits (M7)

Two routes, both admin-only:

- `DELETE /api/scopes/:id/components/:componentId` — hard delete; trashcan icon on each
  Components row triggers this. Next scan re-emits real components and the matcher collapses
  them, so it's safe to use freely.
- `PATCH /api/scopes/:id/components/:componentId` — accepts `name`, `component_root`,
  `evidence`. Marks row `source='manual_override'`. The persist-flow UPDATE uses `COALESCE` /
  array-empty checks so operator-set values aren't overwritten by future scans. Rename
  collisions return 400 with a guidance message. Inline edit form in the Components tab;
  pencil icon next to the Evidence section opens it. Evidence textarea accepts `path:N` suffix
  on each line → parsed into `{path, line: N}` objects.

### No more scope_components boot backfill

The `backfillScopeComponentsFromLatestScans` worker hook was deleted in M7. Its legacy ON
CONFLICT used Postgres NULL-distinct semantics and quietly duplicated every version-NULL row
(Boost, OpenGL, …) on every worker restart. Boot backfills that read-then-insert from
sbom_components into scope_components are inherently fragile — the in-flight scan flow
(`persistScanComponentsToScopeState` + componentMatch) handles bootstrap natively. If a future
migration needs to recompute scope-level state, prefer a one-off `prisma migrate` SQL pass
over a worker hook.

---

## Diagnostic CLIs

Under `backend/src/cli/` — useful when investigating LLM or scan-pipeline behaviour without
burning a full scan:

- `dry-run-llm-sast.ts` — run the LLM SAST detection + recheck flow against a real scope
  without writing to the DB. `pnpm run dry-run-llm-sast --scope-id <id>` inside the worker
  container.
- `probe-claude-structured-output.ts` — empirically verify what `claude -p` emits with
  `--output-format json|stream-json` and `--json-schema`. Built during M13 Phase B design to
  settle Open Question #3 (does `setPhase` progress survive structured-output mode?). Costs
  ~$0.10–0.30 per run. Invoke:
  `docker compose exec worker pnpm exec tsx src/cli/probe-claude-structured-output.ts [json|stream-json]`.
  Re-run when the `claude` CLI version changes or when adding a new SDK flag — assumptions
  about event ordering have already bitten this codebase once.
