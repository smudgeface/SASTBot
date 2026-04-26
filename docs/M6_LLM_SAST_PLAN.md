# M6 — LLM-first SAST (replace Opengrep with Claude Code CLI)

Implementation plan for Milestone 6. Read this entire document before writing
code.

## Context

M5 shipped a working SAST + SCA pipeline driven by Opengrep (SAST), cdxgen +
OSV.dev (SCA), an LLM triage pass over Opengrep findings, and an LLM
reachability pass over high+critical SCA issues.

A side-by-side experiment on the Gocator Classic repo (16K files, ~40K
including VE and FSS) revealed that Opengrep with `--config auto` fired only
16 distinct rules across the codebase and missed several findings the user's
reference Claude-Code-driven CRA audit found — most notably the CWE-798
super-user password macros in `GsHostProtocol.h:68-69`. Adding a small custom
rule pack closes that specific gap, but the broader gap (whatever the
codebase has that we haven't *yet* encoded a rule for) remains. Hand-curated
rules are inherently retrospective.

The Claude-Code-driven audit produced a strict superset of Opengrep's
findings on the same codebase, plus vendored-library identification cdxgen
cannot do at all (no manifest = invisible to manifest-based SBOM tools). It
did so in <200K total tokens for three repos, by orchestrating
`grep`/`find`/`cat` rather than reading every file end-to-end.

M6 migrates SAST to the same model: Claude Code CLI (`claude -p`) becomes
the SAST engine, runs in the worker container, and emits structured
JSON-Lines findings parsed and persisted into the existing `SastIssue`
table. cdxgen + OSV.dev is preserved for SCA — manifest-based dep
extraction with canonical CVE lookup is a solved problem and shouldn't be
re-invented in an LLM. Reachability and vendored-lib identification are
folded into the same LLM pass as SAST detection. A targeted re-check pass
verifies in place any previously-active issues that the new detection
didn't re-report, before they're marked fixed.

See `docs/PROGRESS.md` for the M5 retrospective. See `CLAUDE.md` for
conventions.

## Decisions already locked — do not re-debate

1. **Claude Code CLI inside the worker container, authed from
   `AppSettings`.** Worker image gains the `claude` binary
   (`npm install -g @anthropic-ai/claude-code`). At scan time the worker
   reads `AppSettings.llmBaseUrl` and decrypts the credential at
   `AppSettings.llmCredentialId` (same path `llmClient.ts` already uses),
   then injects them into the `claude -p` subprocess env as
   `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`. The model name comes
   from `AppSettings.llmModel`, passed via `claude -p --model <name>`.
   No container-wide secrets in compose; no `~/.claude/settings.json`
   sync. The configured LLM endpoint must speak the Anthropic Messages
   format (LiteLLM's `/anthropic` passthrough qualifies; pure OpenAI-
   format endpoints do not). At scan-start the worker validates
   `AppSettings.llmApiFormat == "anthropic-messages"` and fails fast with
   a clear warning if not.
2. **Read-only tool gating.** Always invoke as
   `claude -p --allowed-tools "Bash Read Glob Grep" --permission-mode bypassPermissions
    --output-format stream-json`. The model can explore but cannot modify the
   working tree. Bash is restricted further if needed via the model's
   environment, not via prompt instructions.
3. **Three prompts, kept as text files** under `backend/prompts/`:
   `sast_system.md`, `sast_detection.md`, `sast_recheck.md`. Loaded at
   runtime via `fs.readFileSync` with `{{KEY}}` substitution; missing
   variable throws at load time.
4. **Output schema = JSON-Lines.** Record kinds: `sast`, `sast_absence`,
   `reachability`, `vendored_lib`, `complete`. The LLM emits only these;
   the orchestrator parses and persists.
5. **Fingerprint computed orchestrator-side, not by the LLM.** The LLM
   does NOT emit `rule_id` or `fingerprint`.
   - Per-location findings: `sha256(normalized_snippet)[0:16]`.
   - Absence findings: `sha256("__absence__:" + cwe)[0:16]`.
   CWE drift between siblings (e.g., CWE-352 vs CWE-862) for absence
   findings is a known duplication risk; accepted for v1.
6. **CVSS-bucketed severity.** Prompt instructs the LLM to mentally walk
   the CVSS v3.1 metrics and pick the corresponding band. Optional
   `cvss_vector` field carries the vector when the LLM can produce one
   confidently.
7. **Re-check pass behavior on `error` triage status:** include `error`
   issues in the recheck. If recheck says still-present, advance
   `lastSeenScanRunId` but leave `triageStatus = "error"` (next run's
   detection + triage will retry). If recheck says fixed/file_deleted,
   mark `fixed` normally.
8. **Re-check verdict logic:** `still_present | fixed | file_deleted`.
   When the original file is missing, the model searches the rest of the
   codebase for the distinctive snippet content before declaring
   `file_deleted`.
9. **Persist all findings; no confidence threshold filter.** UI shows
   a `Confidence` column on the SAST views and supports sort/filter.
10. **Feature flag per repo:** `repos.sast_engine: 'opengrep' | 'llm'`.
    Default `opengrep` until rollout. Migrate scopes one repo at a time.
11. **First repo to flag-flip: `test-vuln-repo`.** Then `Gocator Classic /`
    once we trust the plumbing. We do NOT cut over without a side-by-side
    comparison run.
12. **cdxgen + OSV.dev stays for SCA.** No change to SCA detection.
    Reachability and vendored-lib identification move into the LLM SAST
    pass.
13. **Token budget per scope per pass.** `repos.llm_sast_token_budget`
    default 300_000 for detection, 50_000 for recheck. Configurable per
    repo. Exhaustion emits a structured warning, same as today's triage
    budget.

## Conceptual model

```
                                cdxgen + OSV.dev          (unchanged)
                                       │
                                       ▼
                                  ScaIssue rows
                                       │
   high+critical SCA list ─────────────┤
                                       ▼
   Repo + branch + ignore_paths ──► claude -p (detection prompt)
                                       │
                                       ▼
                       JSON-Lines stream: sast / sast_absence /
                                          reachability / vendored_lib
                                       │
                                       ▼
                       Orchestrator: parse, fingerprint, upsert
                                       │
                          ┌────────────┼────────────┐
                          ▼            ▼            ▼
                     SastIssue    ScaIssue     SbomComponent
                                  (reach.)     (vendored)
                                       │
                                       ▼
                       Issues this scan didn't re-detect
                                       │
                                       ▼
                                claude -p (recheck prompt)
                                       │
                                       ▼
                       Orchestrator: still_present / fixed /
                                     file_deleted
                                       │
                                       ▼
                                  Triage marks
```

## Schema changes

Minimal. Existing `SastIssue` shape is reused as-is. Two additions:

```prisma
model Repo {
  // ...existing fields...
  sastEngine             String   @default("opengrep") @map("sast_engine")
  // "opengrep" | "llm"
  llmSastTokenBudget     Int      @default(300000) @map("llm_sast_token_budget")
  llmRecheckTokenBudget  Int      @default(50000)  @map("llm_recheck_token_budget")
}

model SbomComponent {
  // ...existing fields...
  discoveryMethod   String   @default("manifest") @map("discovery_method")
  // "manifest" (cdxgen) | "vendored_inspection" (LLM)
  evidenceLine      Int?     @map("evidence_line")
  // for vendored libs, line in evidenceFile where version was identified
}
```

`SastIssue` already has `triageConfidence` — we reuse it for the LLM's
detection-time confidence (it was previously used only by triage).
That's a semantic shift worth documenting in `CLAUDE.md`.

Migration: `m6_llm_sast_engine`. Pure additions, no data backfill.

## Phases

Each phase ends in a manual gate. Don't proceed until the gate is clear.

### Phase 6a — Container + binary plumbing

- Add `claude` to `docker/backend.Dockerfile` (worker shares the same
  image): `RUN npm install -g @anthropic-ai/claude-code`.
- Add `ANTHROPIC_API_KEY` and optional `ANTHROPIC_BASE_URL` to compose
  env (passthrough from `.env`).
- Add `.env.example` entries.
- Sanity check: `docker compose exec worker claude --version` returns a
  version. `docker compose exec worker claude -p "echo hello"` runs and
  returns text.

**Gate:** the binary is in the image and authenticated. Don't move on
until a smoke `claude -p "summarize this directory" < /tmp/dir` works
inside the worker.

### Phase 6b — Prompt loader + orchestrator skeleton

- New file `backend/src/services/llmSastService.ts`.
- New helper `backend/src/services/promptLoader.ts`:
  loads `backend/prompts/<name>.md`, validates that all `{{KEY}}`
  placeholders in the file are satisfied by the supplied vars, throws on
  any unresolved `{{...}}` after substitution.
- Skeleton `runDetection({ scanRunId, scopeId, scopeDir, ... })` that:
  - Builds the SCA input file at
    `/tmp/sastbot-<scanRunId>/sca_high_critical.jsonl`.
  - Renders the system + detection prompts via `promptLoader`.
  - Spawns `claude -p` with `cwd = scopeDir`,
    `--output-format stream-json`, `--allowed-tools "Bash Read Glob Grep"`,
    `--permission-mode bypassPermissions`, system prompt via stdin or
    `--system`, user prompt via stdin.
  - Streams stdout, parses message events, extracts `text` content,
    splits into JSON-Lines, validates each via Zod against the record
    schemas.
  - Logs every parse error as a warning on the scan run.
- No persistence yet — log records to stdout only. Run against
  `test-vuln-repo`, eyeball the output.

**Gate:** stream-json output parses cleanly into typed records on
`test-vuln-repo`. No silent parse failures.

### Phase 6c — Persistence

- Reuse the existing `issueService.upsertSastIssue` path. Map the LLM's
  `sast` record into the upsert shape. Fingerprint =
  `sha256(normalized_snippet).slice(0, 16)`.
- For `sast_absence`: synthesize a snippet of the form
  `__absence__:CWE-XXX` and upsert via the same path. The
  `latestFilePath` becomes `evidence_file`; `latestStartLine` becomes
  `evidence_line`.
- For `reachability`: update the corresponding `ScaIssue` row's
  reachability fields (same shape as today's reachabilityService).
- For `vendored_lib`: insert into `SbomComponent` with
  `discoveryMethod = "vendored_inspection"`. Generate a synthetic PURL
  if possible (`pkg:generic/<name>@<version>`); leave OSV lookup to a
  follow-on pass through `osvService` (already idempotent).
- After detection completes, run the existing worker-end logic: any
  `SastIssue` not detected this run + still in pending/confirmed/planned
  status → candidate for the recheck pass.

**Gate:** scan `test-vuln-repo` end-to-end. Verify SastIssue rows
upsert correctly across two consecutive scans (same fingerprint, no
duplicates). Verify reachability fields populate on existing
ScaIssue rows. Verify vendored_lib rows surface in the SBOM endpoint.

### Phase 6d — Recheck pass

- New helper `runRecheck({ scanRunId, scopeId, scopeDir, missingIssues })`
  in `llmSastService.ts`.
- Builds `/tmp/sastbot-<scanRunId>/recheck_issues.jsonl` from
  `missingIssues`.
- Spawns `claude -p` with the recheck prompt.
- Parses verdicts; applies them:
  - `still_present` → advance `lastSeenScanRunId` to current; do NOT mark
    fixed; preserve current `triageStatus` (including `error`).
  - `fixed` → mark `triageStatus = "fixed"`; advance `lastSeenScanRunId`.
  - `file_deleted` → mark `triageStatus = "fixed"`; advance
    `lastSeenScanRunId`; note in `triageReasoning`.
- Recheck only runs when `missingIssues.length > 0` AND token budget
  allows.

**Gate:** introduce a synthetic "missing" issue in the DB, scan
`test-vuln-repo`, verify the recheck correctly identifies it as
still-present (not auto-fixed). Then actually fix the underlying
code, scan again, verify the issue gets marked fixed via recheck.

### Phase 6e — Feature flag + side-by-side run

- Migration adds `repos.sast_engine` and the two budget fields.
- `worker.ts` branches on `repo.sastEngine`:
  - `opengrep` → existing path (unchanged).
  - `llm` → new `llmSastService.runDetection` + `runRecheck`.
- Frontend Repo edit form: add an "SAST engine" dropdown (Opengrep /
  LLM) with a help line. Default opengrep.
- Add a `Confidence` column to the SAST table on the scope detail and
  scan detail pages. Sort-by-confidence option.
- Add a one-shot admin endpoint `POST /admin/repos/:id/run-comparison`
  that triggers two scans on the same scope (one with each engine, in
  separate scan runs) and produces a side-by-side diff report.

**Gate:** flip `test-vuln-repo` to `sast_engine = "llm"`. Run a scan.
Compare against the most-recent opengrep scan. The LLM scan should
catch the lodash template / minimist / axios findings (already in the
test repo) plus add at least one finding opengrep missed. No
hallucinated findings (every CWE / file / line / snippet must verify
in source).

### Phase 6f — Cutover on Gocator Classic

- Flip `Gocator Classic` repo to `sast_engine = "llm"`.
- Run side-by-side comparison via the admin endpoint. Manual review of
  the diff:
  - Every Opengrep finding from the last scan should be present in the
    LLM scan (or trigger a recheck verdict — never silently lost).
  - LLM scan should surface vendored libraries (extern/openssl,
    extern/jquery, etc.) that cdxgen never could.
  - LLM scan should catch the `GsHostProtocol.h` super-user password
    finding (the original motivating example).
- Document the comparison in `docs/PROGRESS.md`.

**Gate:** human review of the comparison report. If LLM mode looks
right, leave Gocator Classic on `llm`. If not, flip back, file the
gaps, iterate.

### Phase 6g — Opengrep deprecation ✅ landed 2026-04-25

- Removed `OPENGREP_BIN` install step from `docker/backend.Dockerfile`.
- Deleted `sastService.ts` and `llmTriageService.ts` (per-finding triage
  was opengrep-only; LLM-mode does it inline during detection).
- Dropped the opengrep branch from `worker.ts`. Dispatch is now: if
  `analysis_types` includes "sast", run `runLlmSastPipeline` — no
  per-engine dispatch.
- Removed the `repos.sast_engine` column (migration
  `20260425200000_m6g_drop_sast_engine`) and the `SAST engine` dropdown
  from the Repo edit form.
- `backfillSastContextSnippets` worker-startup hook removed.
- Updated `CLAUDE.md` repo-layout notes.

**Rollback path** if a hybrid or fallback ever needed: cherry-pick the
removed pieces from commit `c2c03e8`'s tree (sastService, llmTriageService,
the worker dispatch, the Dockerfile install). Roughly 10 minutes of
mechanical work; no schema migration needed since `repos.sast_engine` can
be re-added with a default of `'llm'`.

## Pitfalls — read before each phase

1. **claude-p stream-json shape.** Each event is a JSON object; the
   model's text content is in `event.message.content[].text` (or
   similar — verify against the actual stream). Extract text, then
   split text into JSON-Lines. Don't assume one event = one finding.
2. **Stream cuts off mid-event.** Watch for incomplete final lines.
   Buffer until you see a newline; treat trailing partial JSON as
   parse error and log it.
3. **Token budget overshoot.** The LLM is told to self-pace, but it
   can blow past the budget on long codebases. Track usage from the
   stream-json `usage` events; on threshold, kill the subprocess and
   continue with whatever was emitted so far. Worker emits a warning,
   doesn't fail the scan.
4. **`/tmp` cleanup.** Always remove `/tmp/sastbot-<scanRunId>/` in a
   finally block, even on error. Worker has `tmpfs` mounted; cleanup
   matters less for containers but matters for repeat runs that
   share state.
5. **Re-detection vs recheck race.** A finding might be detected by
   the new run AND also be in the missing-issues list (because the
   fingerprint shifted slightly). Resolve by running detection
   persistence first, then computing missing issues *after*. An issue
   the new detection re-detected won't appear in the missing list.
6. **Fingerprint collisions.** Two genuinely different findings with
   identical normalized snippets collide. Accepted for v1. If it
   bites, add a tiebreaker on `(cwe, file_basename)` — but only after
   we see real collisions in the wild.
7. **CWE drift on absence findings** (the discussed weakness). When
   reviewing the comparison run, watch for the same absence finding
   appearing under two different CWEs in consecutive scans. If
   common, file a follow-up to introduce the dedicated `AbsenceIssue`
   table.
8. **`triageConfidence` semantic shift.** Was triage-time confidence;
   becomes detection-time confidence in LLM mode. Document in
   `CLAUDE.md` and consider renaming to a neutral `confidence` in a
   later cleanup migration.
9. **Vendored-lib OSV lookup.** `osvService` is idempotent and
   filters by ecosystem. Generic-PURL components (`pkg:generic/...`)
   may not match OSV records — that's fine; they show up in the SBOM
   without CVEs. If a vendored lib has a known ecosystem (npm-style
   `extern/jquery-1.11.0.min.js`), prefer the appropriate PURL
   (`pkg:npm/jquery@1.11.0`) so OSV finds it.
10. **`claude -p` permission prompts.** With
    `--permission-mode bypassPermissions` and explicit
    `--allowed-tools`, no prompts should appear. If they do, the
    process hangs. Always pipe `</dev/null` on stdin or use
    `--print` to ensure non-interactive behavior. Test under
    `docker compose exec -T` (no TTY).
11. **Snippet bytes vs JSON encoding.** The LLM is told to emit raw
    bytes copied from the file, encoded as a JSON string. Quotes and
    backslashes inside the snippet need proper escaping. Trust the
    LLM to produce valid JSON; on parse error, log and discard the
    record (don't try to repair).
12. **CWE format.** The LLM emits `"CWE-798"` format (with the prefix
    and hyphen). Persistence layer normalizes to that exact format
    (uppercase, hyphenated). The existing schema's `latestCweIds`
    array stays as-is.

## Open questions — decide at implementation time

1. **System prompt delivery.** `claude -p` accepts `--system` flag or
   stdin; spec says inline. We'll measure both for clarity.
2. **Multi-scope batching.** Current model: one detection pass per
   scope per scan. If a repo has 5 scopes, that's 5 LLM passes per
   scan trigger. Acceptable for v1; if cost is high, consider a
   scope-batched mode with one prompt covering all scopes — but the
   token costs may not actually go down.
3. **Streaming-friendly UI.** Today the scope page polls scan
   progress every 3s. With LLM scans we could surface live findings
   as they stream. Defer to M6.5; not blocking for cutover.
4. **Local model fallback.** When `ANTHROPIC_API_KEY` is missing or
   `claude -p` exits non-zero, scan fails with a clear error and
   falls back to opengrep if `sast_engine = "llm"`. Or scan just
   fails. TBD; lean toward fail-clear so we notice outages.

## Shipped: cdxgen 12.2 dev marker (M6h, 2026-04-25)

The first cut at filtering optional-scope SCA hints was based on a borrowed proxy (CycloneDX `scope: "optional"`) that cdxgen v10.x overloaded — `optional` lumped npm devDependencies in with transitive runtime deps. With cdxgen 12.2.1's real npm dev marker (`cdx:npm:package:development=true`, sourced from `package-lock.json`'s `dev: true` entries) we now have a truthful classifier. See PROGRESS.md M6h entry for the full retrospective.

**What landed:**

- `@cyclonedx/cdxgen` bumped to `^12.2.1`. SBOM shape compatible — no extraction code changes needed.
- `SbomComponent.isDevOnly` and `ScaIssue.latestIsDevOnly` columns persist the marker. `sbomService.extractIsDevOnly` reads the cdxgen property; `issueService` denormalizes it onto the issue.
- Repo flag renamed `reachability_include_optional_deps` → `reachability_include_dev_deps` (manual SQL rename to preserve existing values). Worker filter switched from `latestComponentScope` to `latestIsDevOnly`.
- "Dev" badge restored on SCA issue rows and Components tab, keyed on the truthful column.
- Repo edit form copy rewritten to explain the npm-only signal and the cdxgen #3927 caveat.
- Follow-up `b4043e7`: `sbomService.persistComponents` now stores canonical package names with the group prefix (`@types/node` not bare `node`) — fixes a collision in `eolService.ts`'s slug map that was mis-flagging `@types/node` as the Node.js runtime. Per-ecosystem joiner: `/` for npm, `:` for maven. Add new ecosystems' joiners in `canonicalPackageName` as they land.

**Carried-forward limitations:**

- cdxgen issue [#3927](https://github.com/cdxgen/cdxgen/issues/3927) — `devOptional: true` lockfile entries don't get the marker yet. A small fraction of dev-only npm packages will read as `false`. Revisit if it bites.
- npm-only signal. Python (poetry/pip), Java (maven/gradle), Go, etc. stay `is_dev_only=false` for everything. Per-ecosystem extractor work would be required to expand:
  - Python: `poetry.lock` `category = "dev"` or `pip-tools` separate compile passes
  - Java: maven `scope: test|provided`, gradle `testImplementation` configurations
  - Go: standard go.mod has no dev/test concept; would need `_test.go` import-graph reachability instead

The deprecated `hide_dev` query param on the SCA list endpoint is still a no-op, kept for back-compat. Safe to remove if/when we audit unused query params.

## Future improvements (post-cutover)

These are not part of the M6 critical path. File once core LLM-mode
SAST is stable on real repos; revisit when we have data on what
actually hurts.

1. **"Deep reasoning" model option.** Add a second model field to
   `AppSettings` — alongside `llmBaseUrl` / `llmModel` /
   `llmCredentialId`, introduce `llmDeepModel` (e.g. an Opus-tier
   model). Surface in the UI as a per-scan "Run with deep reasoning"
   action on the Scope detail page (not a per-repo flag) so operators
   can opt into the higher-cost model for ad-hoc deep audits — initial
   CRA baseline review, post-incident triage, quarterly recall spot
   checks — without changing the cost profile of normal scans.
   - **Scope:** worker reads the per-job model override, falls back to
     `llmModel` when not set. The credential and base URL stay shared;
     deep model just routes to a different `--model` arg.
   - **UI:** primary "Scan now" button stays one-click; "Scan with
     deep reasoning" lives in the same dropdown menu as the existing
     scope actions. Tooltip notes the higher cost.
   - **Why a separate setting and not just per-repo override:** the
     cost/quality choice is per-invocation, not per-repo. A repo
     doesn't have a stable "this needs Opus" property; specific scans
     do. Keeping LLM model config in one place + opt-in usage is also
     a cleaner UX than burying it in repo-edit forms.

2. **Non-destructive `cloneOrRefresh`** on transient network failure.
   Today: any exception from `git fetch` triggers a wipe + re-clone,
   so a VPN drop nukes the cache. Should distinguish
   `RemoteUnreachableError` (preserve cache, fail clean) from genuine
   cache corruption (wipe + retry). Pre-flight `git ls-remote --heads`
   probe with a 5-second timeout as a belt-and-suspenders check.
   Confined to `repoCache.ts` plus a couple of lines in `worker.ts`
   for the new error message. No schema changes.

3. **Window-based fingerprint matching** if line-drift duplication
   becomes painful. Today: per-location SAST fingerprint is
   `sha256(normalize(file_line_at_start_line))`. If the LLM emits
   `start_line ± 1` between runs (off-by-one on whitespace
   insertion), we get duplicate Issues. Mitigated for now by a
   prompt directive that pins line numbers to the vulnerable
   expression itself; if duplicates still accumulate, add a lookup
   that checks ±2 lines for an existing fingerprint before inserting.

4. **Streaming UI** for live findings as the LLM emits them (already
   listed under Open Questions; tracked here too as a real follow-up
   that has UX value once the engine is stable).

5. **Data export / backup.** SASTBot accumulates audit-grade evidence
   (issue history, triage decisions, reachability verdicts, vendored-
   library SBOM) that's painful to lose. Two complementary mechanisms:
   - **Per-repo / per-scope export** — admin route
     `GET /admin/repos/:id/export?format=json|markdown|cyclonedx&since=ISO`
     returning latest-scan summary, all open issues with reasoning +
     CVSS + reachability, vendored libs. Markdown variant suitable for
     handing to a CRA auditor. JSON is the canonical machine-readable
     form; CycloneDX 1.7 reuses the SBOM we already generate.
   - **Full-database backup** — admin "Backup database" button shells
     out to `pg_dump` and writes a tarball to `BACKUP_DIR` (configurable
     env var) or returns it as a download. Sibling restore CLI documented
     in OPERATIONS.md. Less polished than the export route but covers
     "I'm about to do something risky and want a snapshot."

6. **Delete scans / findings (maintenance).** Per-scan row action on
   the Scans (audit) page: admin-only delete with a "this will remove
   the SbomComponents + ScanFindings + SastFindings for this run; issue
   history is preserved" confirmation. Cascades work today via the
   existing FK chain (ScanRun → SbomComponent / ScanFinding /
   SastFinding); SastIssue / ScaIssue.lastSeenScanRunId is an
   unconstrained UUID, so dangling-pointer cleanup happens naturally
   on the next scan.
   - **Bulk maintenance** — `DELETE /admin/scans?older_than=ISO&keep_per_scope=N`
     for retention policies (e.g. "keep 10 most recent per scope, drop
     anything older than 90 days"). Useful once scan_runs accumulate.

7. **Delete repo + scope + everything (rare).** Repo deletion is the
   natural place to wipe scopes + issues + scan history because users
   never want to delete a scope without also stopping that repo from
   producing more issues. The FK chain already cascades correctly:
   Repo → ScanScope (cascade) → SastIssue / ScaIssue (cascade), and
   Repo → ScanRun (cascade) → SbomComponent / ScanFinding / SastFinding
   (cascade). The work is UI:
   - Repo admin page row action: "Delete repo" with a confirmation
     listing the impact ("This will permanently remove N scans, M open
     issues, K vendored-lib records. Cannot be undone.").
   - Required: explicit textual confirmation (type the repo name) per
     industry standard for destructive admin actions.
   - Ideally combined with the export feature — surface a "Export
     before deleting?" link in the confirmation dialog.

## Final deliverables

- [ ] `backend/prompts/{sast_system,sast_detection,sast_recheck}.md`
      (already written — ready for human review).
- [ ] `backend/src/services/promptLoader.ts` + tests for
      placeholder substitution edge cases.
- [ ] `backend/src/services/llmSastService.ts`:
      `runDetection`, `runRecheck`, JSONL parsing, fingerprinting,
      persistence wiring.
- [ ] Migration `m6_llm_sast_engine`: `repos.sast_engine`,
      `repos.llm_sast_token_budget`, `repos.llm_recheck_token_budget`,
      `sbom_components.discovery_method`,
      `sbom_components.evidence_line`.
- [ ] `docker/backend.Dockerfile`: install claude-code CLI.
- [ ] Compose: `ANTHROPIC_API_KEY`, optional `ANTHROPIC_BASE_URL`.
      `.env.example` updated.
- [ ] Worker branches on `repo.sastEngine`. Existing opengrep path
      untouched until phase 6g.
- [ ] Frontend Repo form: SAST-engine dropdown.
- [ ] Frontend SAST tables: Confidence column + sort.
- [ ] `POST /admin/repos/:id/run-comparison` admin endpoint + a
      simple comparison report (counts, per-rule diff, overlap %).
- [ ] `docs/PROGRESS.md` M6 entry.
- [ ] `docs/OPERATIONS.md` additions: claude-p auth, troubleshooting
      stream-json parse errors, token-budget tuning.
- [ ] All phase gates passed; committed at each gate.
