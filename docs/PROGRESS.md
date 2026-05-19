# SASTBot — Development Progress Log

Chronological record of milestones. Each entry is dated and covers two things: **what shipped** and **what we learned**. Raw material for the eventual project presentation.

---

## SAST dedup — same-scope merger + cross-file recheck verdict (2026-05-15)

### What shipped

- **Same-scope programmatic merger.** New `backend/src/services/sastDedup.ts`
  with `mergeDuplicateSastIssues(client, scopeId, scanRunId, options?)`. Reads
  `pending`-status SAST issues for a scope; groups by `latestFilePath`; builds
  line-proximity clusters (overlap or ≤5 lines apart); union-finds each cluster
  on CWE-family overlap. Five CWE families seeded: integrity, injection, path
  traversal, crypto, authentication. Survivor pick: highest severity → widest
  range → lowest id. Re-points `ScaIssue.reachableViaSastFingerprint` from
  merged → survivor fingerprint, unions CWE ids onto survivor, appends a
  `See also: …` footer to the survivor's summary, lifts `jiraTicketId` only
  if survivor has none, then deletes merged rows. Operator-curated rows
  (`confirmed`/`planned`/terminal) are never touched.

- **Worker wire-up.** Called after `applyRecheckVerdicts` and before the
  `sastFindingCount` denorm + SARIF regen, gated on `!hasErrorWarnings`
  (same rule as the SCA auto-fix sweep). Emits an info-severity
  `sast_duplicates_merged` warning when anything was merged.

- **Cross-file recheck verdict.** `RecheckVerdictRecord` gained
  `verdict: "duplicate_of"` with a `duplicate_of: <target-id>` field.
  `applyRecheckVerdicts` performs the same merge actions (re-point, union,
  lift, delete). Refuses to merge operator-curated rows away (falls back to
  `still_present`). Worker now builds and passes a `duplicateTargets` list
  (all `pending`/`error` SAST issues in scope) into the recheck pass.

- **Prompt updates.**
  - `sast_detection.md` gained a Consolidation section: when multiple CWEs
    describe the same weakness in the same region, emit ONE record using
    the broadest CWE (the family table is duplicated in the prompt) and
    list related CWEs in `summary`. Includes a worked example using the
    CWE-345/347/494 firmware-upgrade cluster, plus a rule against emitting
    a `sast_absence` when a per-line `sast` already covers the gap.
  - `sast_recheck.md` documents the new `duplicate_of` verdict, points at
    a new `{{DUPLICATE_TARGETS_PATH}}` JSONL input, and adds a Duplicates
    section telling the LLM when to merge (same-bug, different file/line)
    vs. when not (unrelated CWEs that happen to share a file).

- **One-off broad cleanup CLI.** `backend/src/cli/dedup-sast-issues.ts`
  (`pnpm run dedup-sast-issues [--apply] [--scope-id <uuid>]`) reuses the
  same merger code via a new `dryRun` option. Default is preview-only;
  `--apply` writes. Idempotent — re-running on already-deduped state
  reports zero clusters.

- **Applied on homelab.** 18 rows merged into 14 survivors across all 3
  scopes. The originally-reported FocalSpec case in
  `GoSensor/.../GsCoreUpgrade.cpp` collapsed from 5 rows → 2 (line 210
  standalone stays separate; lines 246-269 become the critical-severity
  survivor carrying CWEs `{345, 494, 347}` and a `See also` footer).

### What we learned

- **The duplication wasn't limited to the one cluster the user spotted.**
  The survey before applying found 79 file collisions across 3 scopes —
  `GsHttpServer.cpp` alone had 15 pending rows that the merger collapsed
  to 11. Visual spot-checks are useful for triggering investigation but
  miss the long tail; treat the reported case as one symptom and survey
  the table.

- **CWE-family curation is the right abstraction, not graph traversal.**
  The five hand-picked families catch the LLM's actual labeling drift
  (CWE-345 ↔ CWE-347 ↔ CWE-494 on the same integrity check; CWE-77 ↔ -78
  ↔ -94 on the same exec) without overcollapsing distinct weaknesses. A
  derived-from-CWE-graph approach would have folded unrelated weaknesses
  (CWE-22 has parents that lead to CWE-707 → CWE-707 children include
  injection and crypto sub-trees) into one mega-family.

- **Operator-curated rows must be invariant under remediation.** The same
  rule applies in three places now: the same-scope merger only touches
  `pending`; the recheck `duplicate_of` path refuses to delete
  `confirmed`/`planned`; the existing auto-fix sweep already left them
  alone. Keep this consistent — the alternative is operators losing their
  triage work to a worker pass and never trusting the tool again.

- **Same merger code, two callers (worker + CLI).** Adding `dryRun` to the
  merger let the one-off broad-cleanup script reuse the exact same logic
  the worker will run on every future scan. No second implementation to
  drift from the first.

- **Per-line `sast_absence` was a redundant emission pattern.** The
  detection prompt previously let the LLM emit both a `sast` finding at
  the line that should have had a signature check AND a `sast_absence`
  finding pointing at the same line. They're the same finding in two
  shapes. New consolidation rule in `sast_detection.md` says: emit only
  `sast` when there's a per-line locus; reserve `sast_absence` for
  genuinely cross-cutting absences (no CSRF middleware anywhere, no TLS
  implementation present).

---

## M6n — SBOM/SCA dev-tool filtering (2026-05-09)

### What shipped

- **Schema default flipped.** `repos.reachability_include_dev_deps` now defaults
  to `false` for new repos. Migration `20260509171959_m6n_default_exclude_dev_deps`
  only touches the column default — existing rows keep their prior value.

- **OSV query gate.** `queryAndPersistFindings` accepts `includeDevDeps: boolean`;
  when false, dev-only components are filtered before the OSV batch call (saves
  API calls outright, not just suppression at persist time).

- **UI: Components tab.** Defaults to `exclude_dev_only=true`. Shows
  "276 runtime / 2,174 dev" count badge. "Show dev-tool packages" toggle
  reveals the full set. Backend route adds `exclude_dev_only` querystring and
  `total_dev` / `total_runtime` to the response.

- **UI: SCA Issues tab.** Same treatment — defaults to hiding dev-only CVEs,
  "38 runtime / 283 dev" badge, "Show dev-tool CVEs" toggle.

- **Worker backfill.** `backfillDevOnlyScaIssues` runs on every worker boot.
  For repos with `reachabilityIncludeDevDeps=false`, finds active SCA issues
  with `latestIsDevOnly=true` and sets `dismissedStatus='suppressed',
  dismissedReason='dev_tree_policy'`. Confirmed idempotent: first boot updated
  283 rows on Gocator Classic /GoWeb; second boot updated 0.

### What we learned

- **89% of cdxgen's npm output is dev tooling.** GoWeb had 2,436 components;
  2,174 were dev-only (webpack/babel/jest trees and their transitive fanout).
  The 262 remaining (antd, mobx, react, three, kendo-react, vendored
  jQuery/RequireJS) are the CRA-relevant set — same order of magnitude as the
  hand-curated reference SBOM (41 components across three repos).

- **One flag, four consumers.** The same `reachabilityIncludeDevDeps` column
  (originally LLM-hint-set only) now gates OSV queries, the Components tab,
  the SCA tab, and the hint set. Column name kept to avoid a pointless
  migration — its broader role is documented in CLAUDE.md.

- **`dismissedStatus='suppressed'` with `dismissedReason='dev_tree_policy'`
  is the right vehicle for policy-driven hiding**, not `status='fixed'`.
  Using `fixed` would conflate "scan verified this is gone" with "operator
  chose not to care" — polluting the auto-fix sweep's semantics and the
  audit trail. A dedicated reason keeps the fixed lane honest.

---

## M0 — Requirements & Plan (2026-04-22)

**What shipped**
- Initial requirements captured in `SASTBot Initial Prompt.txt`
- Research pass on Aikido (UX north star), Opengrep (SAST engine), Aikido safe-chain (threat intel API — proprietary, not a foundation), CycloneDX v1.7 (SBOM spec), and EU CRA Articles 13/14 (vulnerability disclosure timelines)
- Architectural decisions locked: Python 3.12 / FastAPI + React + Vite + TypeScript + Postgres 16 + Redis + Celery; flat repo layout; AES-GCM credential encryption; local accounts with pluggable auth backend; Postgres-canonical defect DB with Jira link-out; CycloneDX **v1.7** (upgraded from the original v1.5 request for CRA alignment); `org_id` baked in now for cheap multi-tenant later; OSV.dev as primary public vulnerability source
- Approved 7-milestone plan (M1 skeleton → M7 ops polish) saved to `/Users/jpaul/.claude/plans/`

**What we learned**
- CycloneDX is at v1.7 as of Oct 2025 (user's original prompt said v1.5 — out of date); cdxgen targets 1.6/1.7 natively
- Aikido's safe-chain threat API is an internal/proprietary endpoint — not a public data source. OSV.dev + GHSA is the right public foundation, with paid feeds as future plug-ins
- Opengrep is an active, OCaml-based Semgrep fork (LGPL 2.1) with a consortium maintaining it — drop-in compatibility with Semgrep rules, SARIF + JSON output

---

## M1 — Skeleton (2026-04-22)

**What shipped**
- Monorepo scaffold: `backend/`, `frontend/`, `docker/`, `docs/`, plus `README.md`, `CLAUDE.md`, `.env.example`, `.gitignore`
- **Backend** (53 Python files): FastAPI app with async SQLAlchemy 2.x + asyncpg, Alembic migration for the full M1 schema (`orgs`, `users`, `sessions`, `credentials`, `repos`, `app_settings`, `scan_runs`, `encryption_canary`), pluggable auth backend, DB-backed session cookies, AES-GCM credential encryption with startup canary check, admin CRUD routes for repos/settings/credentials, `bootstrap-admin` CLI, 13 pytest tests
- **Frontend** (35 TS/TSX files): Vite + React 18 + TypeScript + Tailwind + shadcn/ui, TanStack Query server-state hooks, Zustand client-state slices, React Router v6, login + admin-gated routes for repos/settings/credentials, vitest smoke test
- **Docker**: `docker/backend.Dockerfile` (dev/prod targets), `docker/frontend.Dockerfile` (dev/build/prod targets), `docker/compose/docker-compose.yml` wiring postgres + redis + backend + celery worker + frontend with healthchecks, named volumes, hot-reload mounts
- **Verification** (all 8 checklist items green): clean compose up, bootstrap admin printed to logs, login round-trip, repo create with inline credential, encryption confirmed in DB (binary ciphertext opaque), full restart preserves data, credential decrypts to original plaintext, settings (Jira + LLM) persist, `/docs` renders full OpenAPI (11 routes), `pytest` 13/13 pass, `vitest` 2/2 pass, wrong `MASTER_KEY` triggers canary fail-fast with clear error

**What we learned**
- **`passlib[bcrypt]` breaks on `bcrypt>=4.1`** — passlib's startup probe `detect_wrap_bug` passes a >72-byte test password that newer `bcrypt` refuses. Pinned `bcrypt<4.1`. Long-standing passlib bug. Worth revisiting when passlib 2.x ships or we migrate off passlib.
- **Pydantic's `EmailStr` rejects reserved TLDs** (`.local`, `.test`, `.corp`). These are common in internal/private deployments. Swapped to plain `str` with service-layer validation — email format isn't the security boundary here.
- **Alembic + asyncpg + FastAPI lifespan is a trap**. Running `alembic command.upgrade` from an async lifespan while the env.py uses `asyncio.run()` internally causes a nested-loop deadlock (migration DDL commits but thread never returns). Switched Alembic env.py to a **sync psycopg engine** for migrations — the app still uses asyncpg at runtime. Cleaner and dodges the whole class of problem.
- **Docker Desktop bind mounts don't emit fsevents** — uvicorn `--reload` silently stops picking up host edits. Fixed with `WATCHFILES_FORCE_POLLING=true` in the backend compose env.
- **`readme = "README.md"` in `pyproject.toml`** means the Dockerfile MUST `COPY backend/README.md` before `uv pip install -e .` — otherwise `hatchling.metadata` raises `OSError: Readme file does not exist`. Easy to miss.

**Addendum — manual QA in the browser surfaced real contract bugs**
The sub-agent scaffolds built FE and BE in parallel without a shared schema; three distinct contract mismatches slipped through unit tests and were caught only when driving the UI in Chrome:
- `analysis_types` dict on the backend vs array on the frontend → React crashed with `repo.analysis_types.map is not a function`.
- Inline credential field named `new_credential` on the frontend but `credential` on the backend → credentials silently not created.
- Settings shape nested on the frontend but flat on the backend → the settings page never hydrated from the API, write path silently wrong.
- Bonus: Vite dev-proxy forwarded HTML page reloads for `/admin/*` to the backend, rendering raw JSON.

All four fixed during QA, but the root-cause lesson is on the process: parallel agents with no shared API spec produce subtly wrong code that only integration testing catches.

---

## M1.5 — Stack pivot to Node / TypeScript (2026-04-22)

**What changed**
- Backend moved from **Python 3.12 / FastAPI / SQLAlchemy / Celery** to **Node.js 20 / TypeScript (strict) / Fastify / Prisma / BullMQ**. Zod is the single source of truth for request + response shapes, exposed to the frontend via `@fastify/swagger` → `/openapi.json`.
- Frontend (React + Vite + TS) kept as-is — no changes needed.
- Old Python `backend/` directory deleted; Postgres volume wiped; `docker/backend.Dockerfile` rewritten on `node:20-bookworm-slim`.
- CLAUDE.md, README.md, and the compose file updated.

**Why**
- The user's team is Node-native; long-term maintainability was the dominant factor.
- cdxgen (M3's SBOM generator) is itself a Node tool — the backend can now invoke it in-process rather than subprocessing across runtimes.
- M1 was a walking skeleton with near-zero business logic yet; translation cost was ~2–3 days now, vs 2+ weeks if we'd pivoted after M3.
- Node's built-in `crypto` handles AES-256-GCM with a cleaner API than Python's `cryptography` — the one non-trivial Python-specific piece.

**How the QA lessons shaped the rebuild**
- **One spec, two sides.** Zod schemas live in `backend/src/routes/*` and emit the OpenAPI JSON schema; the frontend regenerates `src/api/schema.d.ts` from `/openapi.json`. A future CI check should diff the committed file against a freshly generated one to catch drift.
- **`analysis_types` canonicalised** as `string[]` from day 0 in the Prisma schema.
- **`credential`** (not `new_credential`) is the inline-credential field name on repos and settings, matching what the frontend already sends.
- **Flat settings shape** (`jira_base_url`, `jira_credential`, `llm_*`) — no nesting.
- Vite proxy keeps the `bypass` for HTML requests so deep-links and reloads hit the SPA.

**Next — M2**
GitHub repo creation (`smudgeface/SASTBot`) and first deploy to Dokploy. Build-script pipeline (LMI convention — Python scripts in `scripts/`, not GitHub Actions). Real BullMQ job: admin "Scan now" drives a `scan_runs` row through pending → running → done (still a no-op handler — M3 fills in the scan logic). Publish `docs/OPERATIONS.md` with key-rotation and webhook-deploy procedures.

---

## M2 — CI scripts, scan pipeline, first push (2026-04-22)

**What shipped**
- `smudgeface/SASTBot` created on GitHub; initial commit + M2 commit pushed.
- **Build scripts** under `scripts/` (modern Python 3, stdlib only, package-relative imports): `ci`, `typecheck`, `lint`, `test`, `check_openapi` (detects OpenAPI drift between running backend and committed `schema.d.ts`), `build_images`, `deploy`. Runnable as `python -m scripts.<name>`. Designed to be wired into whatever build runner LMI eventually points at them — no Bitbucket-Pipelines dependency.
- **Scan pipeline end-to-end:**
  - Backend: `POST /admin/repos/:id/scan` route + `scanService.triggerScan()` that creates a pending `scan_runs` row and enqueues a BullMQ job.
  - Worker: transitions the row through `pending → running → success/failed` with timestamps and error capture. 2-second stub handler — M3 will swap in cdxgen + OSV.dev.
  - Frontend: "Scan now" action in the repo row dropdown; Scans page is now a live table with status badges that auto-refetches every 2s while anything is non-terminal; Dashboard "Scans this week" card populated from real data.
- **Initial Prisma migration** captured and committed under `backend/prisma/migrations/20260422171946_init/`. Compose `backend` service now runs `prisma migrate deploy` at startup (replaced the M1 `prisma db push`).
- **Ops docs:** `docs/OPERATIONS.md` (generic: bootstrap admin, logs, scripts, deploy, key rotation procedure, migrations, disaster recovery) and `docs/DEPLOY_HOMELAB.md` (gitignored — holds the homelab Dokploy webhook URL + LiteLLM endpoint reference). IPs and webhook secrets never touch the committed tree.
- OpenAPI types regenerated (`frontend/src/api/schema.d.ts`) now reflect 17 routes including the new scan endpoint. `scripts/check_openapi.py` will fail the build on future drift.

**What we learned**
- Modernized Python imports (package-relative, `python -m scripts.<name>`) work cleanly and the dual-purpose `run()` + `__main__` pattern makes each script usable both from the CLI and from the `ci.py` umbrella without duplication.
- Prisma's `migrate dev` needs a pristine schema or it'll generate a spurious "delete everything that isn't in schema" migration the first time; wiped `public` via `DROP SCHEMA public CASCADE` before capturing the initial migration. Non-obvious but one-time.
- BullMQ's `removeOnComplete` / `removeOnFail` should be set on job options, not the queue, or Redis fills up over time.
- The M1 QA bugfix (renaming `new_credential` → `credential`) held — no contract drift reintroduced. Zod-as-single-source-of-truth paid off.

**Outstanding for M2 close**
Configuring the Dokploy application itself (Compose app pointing at `smudgeface/SASTBot`, env var wiring for `MASTER_KEY`, webhook ID copied into `~/.../DEPLOY_HOMELAB.md`) is a user-side step. Once the webhook is set, `DOKPLOY_WEBHOOK_URL=... python -m scripts.deploy` is the full deploy workflow.

**Next — M2.5 (below), then M3**

---

## M2.5 — Git auth for real + cache controls + credential UX (2026-04-22)

**Context**
Review of M2 flagged two gaps before M3 could build on top: (a) credentials were storage-shaped as `{kind, label, value}` regardless of kind — good enough for HTTPS tokens, broken for HTTPS basic (needs username+password) and SSH (needs private key + optional passphrase + known_hosts); (b) the Credentials admin page was list-and-delete only — no standalone create, rename, rotate, or "Used by" visibility. On top of that, the user asked for an opt-in "retain clone between scans" feature to trade disk for scan speed on big repos, with a manual purge escape hatch.

**What shipped**
- **Kind-aware credentials (backend).** Zod discriminated union on `kind` with five shapes; `credentials.metadata` JSONB column for non-secret kind-specific fields (username for https_basic, known_hosts for ssh_key). Secrets go through AES-GCM as before; ssh_key secrets (private key + optional passphrase) are JSON-wrapped before encryption so the plaintext column always holds just bytes.
- **Credential routes.** `POST /admin/credentials` (standalone create), `PATCH /admin/credentials/:id` (rename label), `POST /admin/credentials/:id/rotate` (replace secret value, preserving id so all references stay linked), and `GET /admin/credentials` now returns per-row `references` (repos + settings) + `reference_count` so the UI can show "Used by" and disable Delete when in use.
- **Credentials UI.** Rebuilt the page: standalone "+ Add credential" button (kind-aware form), per-row menu with Rename / Rotate / Delete, "Used by" column with repo-name badges, metadata surfaced (`user: alice` shown under label for https_basic; "host-key pinned" for ssh_key). A shared `CredentialFormFields` component is reused by the Repos dialog so adding a new credential inline when registering a repo works for all three git-auth kinds.
- **Git clone service.** `backend/src/services/gitClone.ts` shells out to `git` with standard env vars — `GIT_ASKPASS` for HTTPS kinds (helper script prints username/password on prompt), `GIT_SSH_COMMAND` with a tmp-file key + optional `UserKnownHostsFile` for ssh_key. Secrets never hit the URL or command line. The Dockerfile picked up `git` and `openssh-client`.
- **Retain-clone cache.** New `repos.retain_clone` (bool, default false) + `repos.last_cloned_at` (timestamp). New persistent volume `sastbot_repo_cache` mounted into both backend and worker at `/app/clones`. `services/repoCache.ts` runs `cloneOrRefresh`: with retain off, a fresh tmpdir clone per scan; with retain on, `git fetch --prune` + `git reset --hard origin/<branch>` against the cached working tree, falling back to a fresh clone on corruption. Worker now actually invokes this instead of the sleep stub — scan pipeline is end-to-end against real git remotes. "Retain the clone between scans" checkbox on the repo form; "Purge cache" row action that's disabled until a cached copy exists. `POST /admin/repos/:id/purge-cache` nukes the directory + clears `last_cloned_at`.
- **Integration test.** `scripts/integration_gitea.py` brings up a Gitea container (via `docker/compose/docker-compose.gitea.yml` overlay), provisions an admin user + token + SSH key + three sample repos, then drives the SASTBot API to create one credential of each kind, register one repo per credential, trigger a scan, and assert all three finish as `success`. Proves all three auth methods actually clone against a real git server — not just against `file://`. Runs on demand: `python -m scripts.integration_gitea` (not in the default CI lane).

**What we learned**
- The Gitea image ships with its own OpenSSH daemon bound to port 22 for git-over-SSH; enabling Gitea's *embedded* Go SSH server on the same port crashes the container with `bind: address already in use`. Leaving the embedded one off and relying on the built-in SSH daemon is the right default.
- Prisma's discriminated-union validator works as expected; the trickier part was matching TypeScript narrowing — the spread-to-narrow trick doesn't preserve the discriminant, so the service's `encodeSecret` takes the plain union instead of a manually-widened one.
- SSH passphrase-protected keys would need ssh-agent or `SSH_ASKPASS` to auto-unlock. M2.5 explicitly rejects them with a clear error message rather than failing mysteriously; real support lands with M3 or later.
- SASTBot's unique `(org_id, url)` constraint on repos means integration tests have to provision one upstream repo per credential kind, rather than pointing three SASTBot repos at the same URL.

**Next — M3: SCA vertical slice**
Real git clone using the stored credentials (now live — M3 will consume the cached working dir from `cloneOrRefresh`). cdxgen (Node, in-process) produces a CycloneDX 1.7 SBOM. Persist components + versions + PURLs + licenses. Call OSV.dev for CVE matches. Findings UI (list + detail). SBOM download as JSON. Verify against a repo with known-vulnerable deps.

---

## M3 — SCA vertical slice (2026-04-22)

**What shipped**
- **Credential expiry date (pre-M3 queue item).** Optional `expires_at` timestamp on `credentials` — set at create/rename, surfaced in the UI as a formatted date with orange/red colouring when within 30 days of expiry or already expired.
- **Prisma schema additions.** `SbomComponent` (name, version, purl, ecosystem, licenses, componentType) and `ScanFinding` (osvId, cveId, severity, cvssScore, cvssVector, summary, aliases, activelyExploited, detailJson) models; `sbomJson` JSONB + severity summary counters (componentCount, criticalCount, highCount, mediumCount, lowCount) added to `ScanRun`. Migration `20260422201148_m3_sca` applied.
- **sbomService.ts.** Shells out to `@cyclonedx/cdxgen` (installed as a production dep, binary at `node_modules/.bin/cdxgen`) via `execFile`. Parses CycloneDX 1.7 JSON, persists `SbomComponent` rows, stores raw SBOM in `scan_runs.sbom_json`.
- **osvService.ts.** Queries `https://api.osv.dev/v1/query` (one request per PURL, throttled to 10 concurrent). Maps `database_specific.severity` (CRITICAL / HIGH / MODERATE / LOW) plus CVSS v3 score fallback to the internal severity enum. Persists `ScanFinding` rows, deduplicates by (componentId, osvId).
- **Worker real pipeline.** Replaced the M2.5 stub with: clone → cdxgen → persist components → OSV.dev → persist findings → update severity summary counters.
- **New backend routes.** `GET /scans/:id/findings` (paginated, filterable by severity and package name); `GET /scans/:id/sbom` (raw CycloneDX JSON download with `Content-Disposition`); `GET /scans/:id/components`. ScanRunOut schema extended with the five counter fields.
- **Frontend ScanDetailPage.** Summary cards (Components, Critical, High, Medium, Low), findings table sorted by severity then CVSS, expandable rows showing aliases + CVSS vector, SBOM download button. `ScansPage` rows now clickable; Findings column shows coloured C/H/M/L chips. Credential expiry column added.
- **Vite polling fix.** `server.watch.usePolling: true, interval: 300` in `vite.config.ts` so Docker Desktop macOS bind-mount changes are picked up by the dev server.
- **End-to-end verification.** Local test repo (`backend/test-vuln-repo`) with lodash 4.17.15, axios 0.21.1, minimist 1.2.5. Scan produces 4 components, 13 findings (1 critical, 6 high, 6 medium). SBOM download returns valid CycloneDX 1.6 JSON.

**What we learned**
- **OSV.dev `/v1/querybatch` now returns stubs** — only `id` and `modified` per vulnerability, not the full record. Full severity / CVSS data requires per-PURL calls to `/v1/query`. The change appears to be a 2025 API update; the old batch approach silently produced 13 findings all labelled "unknown".
- **OSV.dev severity is `"MODERATE"` not `"MEDIUM"`** — the string comes from GitHub's advisory database, which uses `MODERATE` instead of the CVSS standard `MEDIUM`. Both must be mapped to the internal `"medium"` severity.
- **Docker Desktop bind mounts don't trigger `tsx watch` or Vite HMR on macOS** — the same Docker-Desktop-over-VirtioFS limitation that affected uvicorn in M1 applies to Node.js watchers. Restarts are required for the worker (which runs `tsx src/worker.ts` without watch mode). Added Vite polling config; noted the need to restart the worker container after any service code change.
- **Prisma `createMany` returns a count, not rows** — `persistComponents` uses `createMany` then a follow-up `findMany` to return the inserted rows (needed to build the OSV query list). Not a problem but a non-obvious Prisma quirk worth knowing.

**Next — M4**
Opengrep SARIF runner: shell out to `opengrep` binary, normalise SARIF findings into a `SastFinding` DB table, fingerprint by (file_path, rule_id, snippet_hash) so suppressions survive re-scans. LLM triage via LiteLLM: classify each finding as likely-FP vs. real, attach reasoning. Per-scan token budget. CWE + CVSS fields on SAST findings.

---

## M4 — SAST + LLM triage + reachability (2026-04-23)

**What shipped**
- **Schema additions.** `SastFinding` + `CveKnowledge` models; `ScanRun` extended with `warnings` JSON array, LLM token counters (`llmInputTokens`, `llmOutputTokens`, `llmRequestCount`), SAST + reachability summary counts; `ScanFinding` extended with five reachability fields; `AppSettings` extended with `llmAssistanceEnabled`, `llmTriageTokenBudget`, `reachabilityCvssThreshold`. Migration `m4_sast_scaffold` applied.
- **Opengrep + ripgrep in backend image.** Arch-aware binary download (`manylinux_aarch64` on Apple Silicon, `manylinux_x86` on CI/prod). Opengrep v1.20.0. Worker detects missing binary at runtime and writes a `opengrep_missing` warning — scan continues SCA-only.
- **`sastService.ts`.** Runs Opengrep (`--config auto --sarif`, 64 MB stdout buffer), parses SARIF 2.1.0, maps severity (`error→high`, `warning→medium`, `note→low`), strips the clone working-dir prefix from file paths, computes fingerprint `sha256(ruleId + ":" + normalizedSnippet)[0:16]` (file path excluded), inherits prior triage status from same-scope findings.
- **`llmClient.ts`.** Supports `anthropic-messages` (tool_use for structured output) and `openai-chat` (JSON mode). Org-aware settings lookup, retry once on 5xx/timeout, atomic token counter increments, `skipEnabledCheck` flag for the connection test. `checkLlmConnection()` for the Settings UI.
- **`llmTriageService.ts`.** Triage loop: severity-ordered, budget-enforced, one Zod-parse + one retry on malformed JSON, falls through to `triageStatus='error'` on second failure. Opportunistic reachability hints: LLM returns `confirmed_reachable_sca_ids` in the triage response, which mark SCA findings reachable immediately without a separate grep pass.
- **`cveKnowledgeService.ts`.** LLM-only extraction of vulnerable function names from OSV advisory text. Global cache in `CveKnowledge` table (one extraction per CVE for the tool lifetime). Re-extracts only when `osvModifiedAt` advances. Cache timestamp comparison uses second-precision epoch to handle OSV's nanosecond-precision `modified` strings vs Postgres's microsecond round-trip.
- **`reachabilityService.ts`.** For each high/critical SCA finding (by severity string when `cvssScore` is null — common in OSV/GHSA data): get function names from `CveKnowledgeService`, ripgrep scope directory, zero hits → `reachable=false` (no LLM), hits → LLM confirmation with ±10 lines of context.
- **Routes.** `GET /scans/:id/sast-findings` (filterable), `POST .../triage` (admin-only, server-side enforced), `POST /admin/settings/llm/check`.
- **Frontend.** SAST tab with severity badge, `file:line`, triage badge (colour-coded by status), expandable row showing snippet + reasoning + admin-only FP/Suppress/Confirm buttons. Warnings banner above tabs. LLM usage card (tokens in/out, request count, budget %). `REACHABLE N` summary card. ⚡ REACHABLE badge on SCA findings with reachability section in expanded row. Settings: LLM-assisted analysis card (toggle, token budget, CVSS threshold), connection check moved into LLM gateway card.

**Fingerprint robustness results**
| Test | Change | Fingerprint |
|------|--------|-------------|
| Baseline | `res.redirect(req.query.url)` | `f23296a4c3cfb955` |
| Blank line above | blank line inserted before the finding's line | same ✓ (triage inherited) |
| EOL comment on adjacent line | `app.get(...) { // comment` | same ✓ (triage inherited) |
| Whitespace inside tokens | `res.redirect(  req.query.url  )` | **different** — collapse to single spaces still produces `res.redirect( req.query.url )` vs `res.redirect(req.query.url)` |
| Variable rename | `req.query.target` | different ✓ (correct, content changed) |
| File moved | `src/routes/app.js` | same ✓ (path excluded from hash, triage inherited) |

Note on test 4: `normalizeSnippet` collapses whitespace runs but does not remove all inter-token spaces. Indentation and leading/trailing whitespace are fully normalized; extra spaces added *inside* code tokens produce a different hash. This is arguably correct — `redirect(  url  )` and `redirect(url)` are textually different, and a suppression of one should not silently apply to the other.

**What we learned**
- **Opengrep stdout buffer.** `execFileAsync` default `maxBuffer` is 1 MB; large repos produce SARIF that overflows it. Fixed at 64 MB. Symptom was "Unterminated string in JSON at position 1048562".
- **OSV `cvssScore` is frequently null.** OSV/GHSA advisories often include severity as a string (`"HIGH"`, `"CRITICAL"`) but omit a numeric CVSS score. Reachability threshold filter must use `OR` over both `cvssScore >= threshold` and `severity IN ('critical', 'high')`. The original query returned zero findings.
- **OSV `modified` timestamps have nanosecond precision** (`"2026-04-02T17:29:57.498155673Z"`). JavaScript `Date` truncates to milliseconds; Postgres round-trips to microseconds. String comparison of `.toISOString()` against the raw OSV string always fails. Fixed by comparing seconds-precision epoch values.
- **`llmClient` needs org-aware settings lookup.** Initial implementation used `getOrCreateSettings(null)` hardcoded. Connection check and triage were looking at the wrong settings row (null-org default, not the authenticated user's org). Fixed by threading `orgId` through all LLM call paths.
- **`tsx watch` and Vite HMR do not reliably detect host-side edits through Docker Desktop bind mounts on macOS.** Worker and backend require explicit container restarts; Vite requires both `.vite` cache deletion and frontend restart. Documented pattern: `docker compose exec frontend rm -rf /app/node_modules/.vite && docker compose restart frontend`.
- **Regex function extraction was dropped.** The plan included regex as the primary extraction path with LLM as fallback. On review, confidence derived from "number of patterns that fired" is not meaningful — a single clear `via \`template\`` match is more reliable than four noisy regex hits. LLM-only extraction (always, cache globally) is both simpler and more accurate.
- **Known issue — LLM extraction accuracy not validated at scale.** The extraction is demonstrably good on the test set (lodash template 0.99, prototype-pollution functions 1.0, axios HTTP methods 0.85). Accuracy on a broader corpus of OSV advisories is unknown. **TODO:** audit 50+ real OSV records from production repos; tune prompts; assess whether any class of advisories systematically produces wrong function names.
- **Lockfiles pollute ripgrep reachability search.** Adding `jest` / `mocha` devDependencies introduced `@babel/template` hundreds of times in `package-lock.json`, causing the LLM to dismiss a genuine `lodash.template` call as "only lockfile metadata." Fixed by excluding `*.lock`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `Gemfile.lock`, and `composer.lock` from all ripgrep invocations.
- **CycloneDX `scope` field semantics.** cdxgen marks direct runtime deps as `"required"` and both devDependencies and transitive deps as `"optional"`. The UI shows a "DEV" badge for all `optional`-scope findings and allows hiding them with a toggle. This is a useful noise-reduction proxy even though it's broader than "devDependencies only."

**M4 post-phase UI polish (added after 4e)**
- Scan detail tabs renamed: "Findings" → "SCA Findings", "SAST" → "SAST Findings"
- Unified SCA filter bar: severity chips, type chips (CVE/EOL/Deprecated), "Hide dev-only deps" (scope=optional), "Has fix available" (OSV events check), "Reachable only" (confirmed_reachable=true only — includes all types)
- SCA findings table: CVSS column removed (always null from OSV), "CVE / ID" → "Finding" column, EOL chip moved from severity cell to finding cell, DEV + ⚡ Reachable badges shown below summary text, Zap icon moved to expand cell to prevent severity column layout shift
- SAST findings table: Rule column → Summary (rule_message), filter for hiding FP/suppressed, Reset to Pending action
- Components tab: "Only show components with findings" filter
- `SbomComponent.scope` persisted from CycloneDX; `has_fix` computed from OSV `affected[].ranges[].events` (no DB column needed); both surfaced in `ScanFindingOut`

**Next — M5**

---

## M5 — Issue identity, scope-centric UX, Jira read-only sync (2026-04-24)

### What shipped

**Schema refactor — Issue identity (Phase 5a)**
- New `SastIssue` and `ScaIssue` tables as stable identity units (one row per `(scope, fingerprint)` or `(scope, packageName, osvId)`). `SastFinding` / `ScanFinding` become detection event rows pointing to their Issue via `issueId` FK.
- Triage fields (`triageStatus`, `triageConfidence`, `triageReasoning`, suppression) moved from detection rows to `SastIssue`. Reachability fields moved from `ScanFinding` to `ScaIssue`.
- `JiraTicket` table added — cached Jira ticket metadata synced from Jira Cloud.
- `ScanScope` gains `lastScanRunId` / `lastScanCompletedAt` denorm; `Repo` gains `lastScheduledScanAt`.
- Migration `m5_issue_identity_and_jira` + `m5c_jira_resolution` applied cleanly. New `resolution` field on `JiraTicket` stores raw Jira resolution name.
- All detection services (`sastService`, `osvService`, `eolService`) updated to upsert Issue rows before writing finding rows.
- `llmTriageService` and `reachabilityService` refactored to write decisions to Issue rows. `inheritTriage` deleted — triage persistence is inherent to the Issue model.

**Scope-centric UX (Phase 5b)**
- `/scopes` is now the landing page. Table shows each scope with severity breakdown (Critical/High/Medium/Low), SCA/SAST issue counts, pending triage count, last scan age.
- `/scopes/:id` scope detail page: 3-tab layout (SCA Issues, SAST Issues, Components), summary chips, Scan Now button, Recent Scans collapsible drawer, "← All scopes" back link.
- SCA Issues tab: filter bar with stackable groups (`critical|high|medium|low`, `cve|eol|deprecated`, `reachable has fix hide dev`, `include resolved`) separated by `|` pipes. Expandable rows with dismiss actions.
- SAST Issues tab: same filter pattern plus status filter. Expandable rows show ±3 lines of code context with highlighted match line, rule ID, CWE, triage buttons.
- Both tabs use `forceMount` so all three tab panels pre-fetch on page load — no loading flash when switching tabs.
- Shareable issue URLs: each row has a copy-link button (appears on hover) that copies `/scopes/:id?issue=:issueId`. Loading that URL auto-expands and scrolls to the issue.
- All tables wrapped in `<Card>` to match scan audit page. Severity sort: post-fetch SEVERITY_ORDER map fixes alphabetical ordering (`low < medium` bug). Stable sort tiebreaker (`id.localeCompare`) prevents row jumping.

**Jira read-only integration (Phase 5c)**
- `jiraClient.ts`: Jira Cloud REST API v3 client. `checkJiraConnection()`, `fetchTicket()`, `fetchTicketsBatch()` (JQL IN, max 50/batch), `fetchResolutions()`, `isValidIssueKey()`. Auth: `Basic base64(email:apiToken)`.
- `jiraTicketService.ts`: `linkSastIssueToTicket()` / `linkScaIssueToTicket()` — validates key, fetches from Jira immediately (fail loudly on missing/inaccessible ticket). `unlinkSastIssue()` reverts to `confirmed`. `refreshTicket()` for on-demand sync. `reconcileJiraSync()` for 15m/60m cadence batch sync (wired for Phase 5d scheduler).
- Routes: `POST/DELETE /api/sast-issues/:id/jira-ticket`, same for SCA, `POST /admin/jira-tickets/:key/refresh`, `GET /api/scopes/:id/jira-tickets`, `POST /admin/settings/jira/check`, `GET /admin/jira/resolutions`.
- Settings page: Account email field + "Check connection" button → "✓ Connected as Jordan Paul".
- JiraCard in expanded rows: key as external link, statusCategory + resolution, assignee, fix version, sync time. Visible **Refresh** + **Unlink** buttons.
- Jira status pill in STATUS column: `GOS-14158 · Done`, `GOS-15261 · To do`, colored by statusCategory.

**SAST issue lifecycle & status model**
- Status model: `pending → confirmed → planned → fixed` (main flow) + `wont_fix` / `invalid` (terminal).
- Linking a Jira ticket sets `triageStatus = "planned"`. Unlinking reverts to `confirmed`.
- Worker auto-marks undetected non-terminal SAST issues as `fixed` after each scan.
- SCA adds `confirmed` state for consistency with SAST.
- "Confirmed" renamed to **"To do"** everywhere (purple). Planned = blue. Fixed/Jira Done = green. Invalid/Won't fix = grey. Jira "To do" statusCategory = purple (matches issue To do).
- Attention indicator: "⚠ N need attention" appears when `planned` issues have Jira `statusCategory=done` — jira closed but scan not yet confirmed the fix.
- SAST code context: `persistSastFindings()` reads ±3 lines from source file during scan. `ContextSnippet` component renders with highlighted match line (yellow row + `→` arrow).

**Operational improvements**
- `checkGitConnection()`: `git ls-remote --heads` to verify URL + credentials without cloning. "Check access" item in repo actions dropdown.
- `sbomService`: removed `--no-recurse` (blocked manifests in subdirs); gracefully handles cdxgen producing no output (returns empty SBOM, scan succeeds with 0 components instead of ENOENT).
- Vite proxy routing fixed: all new API routes prefixed `/api/` to avoid SPA path collision.
- `ScopeDetail.tsx` `forceMount` + `data-[state=inactive]:hidden` eliminates tab layout shift.

### What we learned

- **Issue identity vs. detection events** is the right model for any scan-based security tool. The pain of the M5 backfill (even though our DB was tiny) validated that the exercise would be necessary at scale too. Worth doing early.
- **Vite bind-mount cache is sticky.** The browser's HTTP disk cache retained a stale 404 response for `/scopes` from before the proxy was configured. `ignoreCache: true` reloads didn't help — needed a truly fresh browser context. The fix (prefix `/api/`) is cleaner anyway.
- **Prisma string-sorts enums alphabetically.** `low < medium` alphabetically. Post-fetch sort with an explicit SEVERITY_ORDER map is the right approach at M5 scale; add a DB enum or expression index if the list grows to thousands.
- **Jira Basic auth requires `base64(email:apiToken)`, not `base64(apiToken)`.** Silent 401 with no body if wrong. Pitfall documented.
- **`git ls-remote --timeout=10` is not a valid flag** — caused immediate failure silently. Use Node spawn `timeout` option instead.
- **cdxgen exits non-zero for some project types** even when it writes the SBOM successfully. `sbomService` now checks for file existence before treating non-zero as failure.
- **`contextRegion`** in SARIF (standard surrounding-context field) is not emitted by Opengrep. We fall back to reading the source file directly during `persistSastFindings()` while the clone is on disk — correct approach, just not in SARIF.
- **LMI Bitbucket Server needs `https_basic`** (username + token as password), not `https_token`. GoPxL BE scan: 583 components, 5 critical, 24 high CVEs on first successful run.
- **Stable sort tiebreaker**: UUID `localeCompare` as final tiebreaker prevents rows from jumping positions when identical-score items are updated (Acknowledge → Reopen). Small but impactful UX fix.

### GoPxL BE verified results (2026-04-24)
- 583 npm + NuGet components, 5 critical CVEs, 24 high CVEs, 57 medium, 2 low.
- 46 SAST issues (Opengrep Python rules), severity properly mapped via `rule.defaultConfiguration.level` fallback (Opengrep omits `result.level`).
- Jira integration live: linked `GOS-14158` (Complete · Fixed · 1.4, 1.5), `GOS-15261` (In Progress · To do).

---

## M5 polish — UX, reachability v2, CVSS calculators, manifest origin, source links (2026-04-24)

### What shipped

**Severity bar header + LLM summaries everywhere**
- Replaced the row of summary chips on `/scopes/:id` with a single **stacked severity bar** card: full-width proportional bar, large total ("111 Open Issues"), per-severity legend, and a secondary line for SCA / SAST / Pending triage counts. Empty state shows "No open issues in this scope." with a check icon.
- LLM summaries are now the authoritative one-liner everywhere (50/50 SAST and 108/108 SCA backfilled in dev). Action-oriented, e.g. *"Replace xml.etree.ElementTree.parse with defusedxml to prevent XXE attacks"* / *"Allows attackers to pollute JavaScript object prototypes via crafted query strings"*.
- Fixed `backfillLlmSummaries` pagination bug: the offset-based loop silently skipped any row whose LLM call returned null (50/108 SCA rows missed in our DB). Replaced with a `notIn(attemptedIds)` filter so successes drop out via the null filter and failures aren't retried infinitely.
- `ContextSnippet` gained absolute line numbers in the gutter, so blank lines render with their number — clear that "3 lines before" still counts an empty line.
- `shortRuleSummary()` extracts the first sentence (≤100 chars) of a SAST rule message as a fallback when no LLM summary exists.

**Honest status badges + correct triage workflow**
- `StatusBadge` no longer overrides to "Planned" whenever a Jira ticket is linked — it always shows the actual status. The override hid the reason `false_positive` issues weren't counted as Critical.
- Conditional Jira link/unlink transitions:
  - Link: only `pending`/`confirmed` auto-transition to `planned`. Other statuses keep their value (a ticket link doesn't reopen a closed issue).
  - Unlink: only `planned` reverts to `confirmed`. Other statuses stay as-is.
- Inline ⚠ next to the badge when an issue is `planned` AND its Jira ticket has `statusCategory=done`. SCA tab gained the same "N need attention" banner that SAST already had.
- Complete next-status button matrix:
  | Status      | Buttons                                          |
  |-------------|--------------------------------------------------|
  | pending     | Confirm · Won't fix · Invalid                    |
  | confirmed   | **Planned** · Won't fix · Invalid · Reopen       |
  | planned     | Mark fixed · Won't fix · Invalid · Reopen        |
  | fixed/won't fix/invalid | Reopen                               |
  Forced workflow: confirmed → planned → fixed (no jumping straight to fixed from To do).

**Reachability v2 — confidence, call-sites, one-click dismiss**
- Severity-based threshold replaces the old `reachability_cvss_threshold` (Float) with `reachability_min_severity` (enum: critical/high/medium/low, default high). Settings UI is now a dropdown. Backend query becomes a single severity-IN comparison.
- Worker-startup `backfillReachability`: any SCA CVE that hasn't been assessed and meets the severity gate gets ripgrep + LLM confirmation on boot. Only works for retain-clone repos. Idempotent.
- LLM tool schema extended to return `{reachable, confidence, reasoning, call_sites: [{file, line, snippet}]}`. New columns `sca_issues.reachable_confidence` (Float) and `reachable_call_sites` (JSONB). Re-runs for rows assessed before the schema change.
- New `ReachabilityVerdict` block in the SCA expanded view: "Reachable / Not reachable" headline, confidence %, reasoning, code-block per call site. When `reachable=false && confidence ≥ 0.85`, shows one-click "Mark Invalid" / "Mark Won't fix" CTAs (suggestion, not auto-action).

**CVSS calculators (3.1 + 4.0)**
- `parseCvssScore` now handles full vectors as well as plain numbers. CVSS v3.1 calculator implements FIRST.org's deterministic formula (AV/AC/PR/UI/S/C/I/A weights → impact + exploitability → roundUp1).
- New `cvss4.ts` ports the v4.0 macro-vector lookup (270 entries from the spec's Appendix A). Uses macro-vector score directly; the within-bucket fractional refinement is not yet ported (within ±0.5 of FIRST.org calculator; severity bucket always exact).
- `pickCvss` prefers V4 → V3 → V2 from OSV's severity[] array. Many GitHub-reviewed advisories now ship only `CVSS_V4` — we were silently dropping them before.
- Backfill ran on 65/65 v3 vectors and 9/9 v4 vectors. form-data@2.3.3 (`CVSS:4.0/AV:N/AC:H/...`) now scores 9.5 (Critical), matching its GitHub advisory severity.
- Alias-overlap detector at OSV ingest: when a new record's aliases overlap an existing issue in the same scope+package but the `osv_id`s differ, we log a structured warning rather than silently inserting a duplicate. Doesn't fire on current data.

**SCA manifest origin (parity with SAST file paths)**
- `sbom_components.manifest_file` captures cdxgen's `evidence.identity.methods[].value` (technique=manifest-analysis) plus `properties[name=SrcFile]`, stripped to repo-relative.
- `sca_issues.latest_manifest_file/line/snippet` mirror the SAST `latest_file_path/start_line/snippet` trio.
- `osvService.readManifestSnippet` greps the manifest for the package name and captures ±3 lines (handles `"name"`, `'name'`, `name==`, `name~=`, plain).
- Worker-startup `backfillManifestOrigin`: reads each scope's stored sbom_json, indexes by package name, fills the new fields for retained-clone repos. Idempotent.
- SCA row Location column now shows `package-lock.json:4014` (basename + line, like SAST), with package@version as secondary text. Expanded view shows the full repo-relative path and 7-line ContextSnippet centred on the declaration. CVE link moved from row chips into the expanded metadata block.

**Clickable file paths via per-repo URL template**
- Repos can configure a `source_url_template` (e.g. `https://git.example.com/projects/X/repos/Y/browse/$FILE#$LINE`). Two placeholders: `$FILE` (URI-encoded) and `$LINE`.
- Frontend `<FileLink>` wraps any path span; renders an external `<a target="_blank">` with stopPropagation (clicks don't toggle the row). Used for SAST file paths, SCA manifest paths, and reachability call-sites. When no template is set, paths render as plain text.

**Sibling-scope exclusions + ignore_paths**
- Repos with overlapping scopes (e.g. `["/", "/GoWeb"]`) no longer double-scan. `computeScopeExclusions` returns the subdirs (relative to the current scope's working dir) that should be excluded — works for arbitrary nesting.
- New per-repo `ignore_paths` (JSONB array, default `[]`): paths to skip from every scan. Useful for vendored code, generated output, internal-only scripts. Concatenated with sibling scopes before the exclusion calc — no separate code path.
- Excludes flow into both `runCdxgen --exclude <dir>/**` and `runOpengrep --exclude <dir>` so SBOM and SAST agree on what's in/out of scope.

**Operational polish**
- "Save & test connection" replaces "Check connection" on the Settings page. Persists the form state before testing so first-time users don't get a confusing "not configured" error after typing valid credentials.
- Fixed credential silent-unset: when a user created a new Jira/LLM credential and clicked Save again, the second click sent `{credential_id: null, credential: null}` which the backend interpreted as "disconnect". Now we omit credential keys when the user hasn't supplied usable data, and reset choice → "existing" pointing at the new id after save.
- "Scan now" → "Scanning…" spinner: `useScopeScans` polls every 3s while the latest run is pending/running, drives the button label, and invalidates scope detail + issue queries on completion so counts refresh without a page reload. `useTriggerScan` synchronously prepends the new pending run to the per-scope cache so the spinner is up the instant the HTTP trigger returns (no flicker). Backend `triggerScan` now skips scopes that already have a pending/running run, so accidental double-clicks don't queue duplicate scans.
- Repo edit form copy polish: "Default branch" → "Branch", "URL" → "Clone URL", added help text under every field, Scan paths help explains "each path becomes its own scope" and the deeper-path-wins rule for overlaps.

### What we learned

- **`hasOwnProperty` partial-update semantics are subtle.** Two flavors of the same bug bit us this session: the credential silent-unset (sending `null` for both `credential_id` and `credential` to a backend that uses `hasOwnProperty` to detect intent), and the `backfillLlmSummaries` `skip:offset` issue. In both cases, "did the user supply a value?" needs to be distinct from "is the value null?". Omit the key when there's no intent.
- **CVSS 4.0 is now the default for npm advisories.** OSV records for newly-reviewed GHSAs increasingly ship only `CVSS_V4`. A V3-only ingest path silently drops them. The alias-overlap warning would tell us if OSV ever emits both for the same vuln, but for now V4 fallback is essential.
- **CVSS 4.0 macro-vector lookup is a clean approximation of the spec.** The 270-entry table matches the FIRST.org calculator's output to ±0.5. The within-bucket fractional refinement is non-trivial and we deferred it; the severity bucket (Critical/High/Medium/Low) is always exact, which is what triage actually keys off.
- **Status semantics matter more than UI niceness.** Auto-overriding `false_positive` to "Planned" because there was a Jira ticket made the count of Critical look wrong, even though the count was right. Honest labels exposed the actual data state and made the existing logic legible. Pattern: badge always shows the truth; transitions are explicit (link/unlink) or via buttons; never "implicit" override.
- **Reachability scoring should be deterministic from the metadata we already have.** The CVSS-score threshold made sense in theory, but only 0/108 issues had numeric scores until we computed them from vectors. Severity is what users think in and what NVD/GHSA classify into anyway. Switching the threshold to severity simplified both UI and query.
- **LLM verdicts need confidence + provenance to be actionable.** We had `reachable: bool + reasoning: string` for weeks; nobody dismissed anything because it didn't feel safe to act on. Surfacing confidence ("85% confident") and call-site code blocks made the same verdicts feel concrete enough for one-click suggested dismissals. Same data, very different UX.
- **`offset += BATCH` is unsafe with a delete-on-success filter.** When you query "rows where X is null" and update some to non-null, you can't paginate with skip — you'll skip past rows that stayed null. Track attempted IDs with `notIn` instead.
- **Async UI feedback needs synchronous cache writes when the polling interval > the user's reaction time.** The spinner regression was instructive: a 3 s poll plus a TanStack invalidate-only `onSuccess` left a 100–300 ms window where the cache held the *previous* run's terminal status, so the button flickered back to "Scan now" and users double-clicked. Fix: `setQueryData` synchronously on trigger success so isScanning is true the moment the HTTP call returns, then let the poll catch up. Always pair the optimistic update with a backend defense-in-depth check (skip scopes that already have pending/running runs).

### Migrations applied this batch
1. `20260424120000_add_llm_summary_remove_llm_enabled` — `latest_llm_summary` columns; drop `llm_assistance_enabled`
2. `20260424130000_unify_sca_states` — converts `active`→`pending`, `wont_fix`→`suppressed`, `acknowledged`→`suppressed`
3. `20260424140000_reachability_min_severity` — replaces `reachability_cvss_threshold` (Float) with `reachability_min_severity` (Text, default `'high'`)
4. `20260424150000_reachability_call_sites` — `reachable_confidence` (Float?), `reachable_call_sites` (JSONB?)
5. `20260424160000_sca_manifest_origin` — `latest_manifest_file/line/snippet` on sca_issues, `manifest_file` on sbom_components
6. `20260424170000_repo_source_url_template` — `repos.source_url_template`
7. `20260424180000_repo_ignore_paths` — `repos.ignore_paths` JSONB default `'[]'`

### Late additions (same day, post-doc-commit)

**Scan cancellation + Scan-now hardening**
- New `cancelled` value on `ScanStatus` (no migration — `scan_runs.status` is plain TEXT). `scanService.cancelScanRun` walks the BullMQ queue (waiting / delayed / paused), removes the matching job by `scanRunId`, and marks the row cancelled with a clear error message. Idempotent on terminal runs.
- Worker checks `scan_run.status` on pickup; if it's already `cancelled` (set while the job was waiting), it logs and exits cleanly without writing partial results.
- New `POST /scans/:id/cancel` admin route. `useCancelScan` hook + Cancel link in the Recent scans drawer (scope page) and a new last column on the Scans audit page (admin-only, on pending/running rows).
- Backend `triggerScan` now skips scopes that already have a pending/running run before creating a new ScanRun, so accidental double-clicks produce zero new rows.
- Frontend `useTriggerScan` synchronously prepends the new pending run to each affected scope's scans cache via `setQueryData`, so the "Scanning…" spinner is up the instant the trigger HTTP call returns. No flicker, no double-click window.
- **Mapper fallback bit us again.** `scanRunToOut.toStatus()` had a four-status allowlist (`pending/running/success/failed`) and silently fell back to `"pending"` for anything else — so cancelled DB rows came out of the API as "pending". Added `cancelled` to the list. Same pattern as the SCA `ALLOWED_DISMISSED` bug ("active" → "pending") earlier this milestone. Lesson reinforced: every hand-written allowlist that mirrors a Zod enum needs an automated way to stay in sync, or it will drift silently.

**Known limitation (not fixed this batch):** when a scan is cancelled while the worker is mid-tool (cdxgen / opengrep already executing), the row is marked cancelled but the external process keeps running. When it finishes, the worker writes `status="success"` and overwrites the cancelled flag. Future fix: status-check between phase boundaries and bail; or check status before the final update and refuse to overwrite cancelled.

**Next — M5d Scheduler + M5e Hardening, or M6**

---

## M6 — LLM-mode SAST replaces Opengrep (2026-04-25)

### Why we did this

A side-by-side experiment on the Gocator Classic repo showed that Opengrep with `--config auto` fired only 16 distinct rules across 16K files and missed several findings the user's reference Claude-driven CRA audit caught — most notably the CWE-798 super-user password macros at `GsHostProtocol.h:68-69`. Adding a custom rule pack closed that specific gap, but the broader gap (whatever the codebase contains that we haven't yet encoded a rule for) remains. Hand-curated rules are inherently retrospective.

The Claude-driven audit produced a strict superset of Opengrep's findings on the same codebase, plus identified vendored libraries cdxgen literally cannot see (no manifest = invisible to manifest-based SBOM tools). It did so in ~200K total tokens by orchestrating `grep`/`find`/`cat` rather than reading every file end-to-end.

### What shipped

**LLM-mode SAST is now the only SAST path.** A single `claude -p` agentic pass produces JSON-Lines findings parsed and persisted into the existing `SastIssue` table. cdxgen + OSV.dev stays for SCA — manifest-based dep extraction with canonical CVE lookup is a solved problem worth keeping. Reachability and vendored-library identification fold into the same LLM pass; the standalone `reachabilityService` is now only invoked by the worker-startup backfill (still useful for retroactively scoring older issues).

**A targeted re-check pass** verifies any non-terminal `SastIssue` the new detection didn't re-emit before marking it fixed. The model handles the case where a vulnerability moved files (file disappeared at original path → grep across scope → if found, return `still_present` with `current_snippet` from new location). Validated against four synthetic cases (real-still-present, fixed-on-real-line, file-deleted, refactor-relocation) — all four verdicts correct.

**Three prompts under `backend/prompts/`** as Markdown text files, not embedded TS strings, so humans can review and red-pen them: `sast_system.md` (role, honesty rules, snippet rule, severity calibration via CVSS), `sast_detection.md` (scan a scope, emit JSONL records), `sast_recheck.md` (verify N specific issues from a JSONL input file). Variable substitution is `{{KEY}}` → throws on unresolved at load time.

**Auth from `AppSettings`, not env vars.** `claude -p` is invoked with a per-scan subprocess env that injects `ANTHROPIC_API_KEY` + `ANTHROPIC_BASE_URL` from the AppSettings credential the user already configured for LLM triage. No container-wide secrets, no `~/.claude/settings.json` sync. Worker drops to a non-root `claudeuser` (uid 1001) for the subprocess because `claude -p` refuses `--dangerously-skip-permissions` when run as root.

**`repos.reachability_enabled`** flag (default true) — when false, the LLM SAST pass receives an empty SCA-hint file and skips the reachability portion. Useful where reachability output cost ($1.99 of detection on /GoWeb) outweighs signal value (4/120 reachable, mostly on transitive deps that aren't directly imported).

**`cloneOrRefresh` no longer wipes the cache on transient network failure.** New `RemoteUnreachableError` class + `isNetworkError` heuristic; pre-flight `git ls-remote --heads` probe with a 10-second timeout before any destructive operation. Refresh-time `git fetch` failures are classified — only true cache corruption (bad refs, missing objects) triggers the wipe-and-reclone recovery. Triggered by the VPN-drop incident during 6f testing where Gocator Classic's cache got wiped twice. New vitest tests for both branches.

**Schema additions and removals**
- `repos.llm_sast_token_budget INT DEFAULT 300000` — detection-pass budget
- `repos.llm_recheck_token_budget INT DEFAULT 50000` — recheck-pass budget
- `repos.reachability_enabled BOOL DEFAULT true`
- `sbom_components.discovery_method TEXT DEFAULT 'manifest'` (alt: `'vendored_inspection'`)
- `sbom_components.evidence_line INT?` — line in the manifest/header file where the LLM identified the version
- `repos.sast_engine` was added during 6e and removed in 6g — never persisted in production

**Migrations**
- `20260425100711_m6_llm_sast_engine` — added `sast_engine` and the budgets
- `20260425191231_m6_reachability_toggle` — added `reachability_enabled`
- `20260425200000_m6g_drop_sast_engine` — dropped the engine column when LLM-mode became the only path

**UI surfaces**
- Repo edit form: `Reachability analysis` checkbox (the SAST engine dropdown was removed in 6g)
- Scope detail SAST tab: new `Conf.` column showing the LLM's detection-time confidence (or "—" for legacy opengrep findings)

### Validation results

**Gocator Classic / scope** — $2.10 ($1.52 detection + $0.58 recheck), ~12 min:
- Found `GsHostProtocol.h:68-69` super-user password (the original motivating gap), conf 0.99
- 5 vendored libs surfaced (`nlohmann/json 3.8.0`, `CLI11 1.8.0`, `libzip 1.5.2`, `googletest 1.7.0`, `xxHash`)
- Bonus finding not in the reference report: hardcoded PIN at `GsHttpServer.cpp:797`
- 36/36 baseline opengrep findings recheck-confirmed `still_present`. Zero silent loss.

**Gocator Classic /GoWeb scope** — $5.14 ($1.99 detection + $3.15 recheck), ~31 min:
- 7 vendored libs surfaced (jQuery 1.11.0, jQuery UI 1.8, Raphaël 2.1.4, g.Raphael 0.51, Google Closure Library, CodeMirror, AjaxUpload) — all matching the reference CRA report's CRITICAL/HIGH list
- Caught all 7 SAST findings the reference report flagged for /GoWeb (lodash _.template injection, eval in rescue upload, innerHTML XSS sites, postMessage origin issues, no-TLS WebSockets, empty default admin password)
- 276/280 baseline opengrep findings recheck-confirmed `still_present`. 4 missing-verdict + 1 parse error left untouched (no false closure).

**Cost shape**: claude-p reports `total_cost_usd` and the math reconciles to standard-tier pricing ($3/M input, $15/M output, $0.30/M cache_read, $3.75/M cache_create). Across both Gocator scopes — 8.6M total tokens, 252 requests — no API call exceeded the 200K-context tier. Total spend $7.24 for the full Gocator Classic LLM scan, vs. previously $0 for opengrep but missing every C/C++ macro password and every vendored lib.

### What we learned

- **Hindsight pattern matching is the wrong tool for the unknown.** Custom Opengrep rules can recover the specific findings we already know about; they can't help with the next class of problem. The Claude reference report caught CWE-798 macros without anyone hand-encoding a rule for `#define`-macro password literals — that recall floor is what makes the LLM approach durable.

- **Fingerprinting on LLM-emitted snippets is too brittle.** Tiny whitespace drift between runs broke identity and produced duplicate `SastIssue` rows. Fixed by reading the actual source line at `(file_path, start_line)` from disk and hashing that — `sha256(normalize(file_line)).slice(0, 16)`. The orchestrator owns the fingerprint; the LLM only emits CWE + location + snippet for display.

- **CWE drift between siblings (CWE-352 vs CWE-862, CWE-798 vs CWE-259) is real but bounded.** Per-location findings hash on snippet alone — CWE drift doesn't split them. Absence findings hash `__absence__:CWE-XXX` and may occasionally duplicate; tolerated for v1, addressable later via a dedicated `AbsenceIssue` table if it bites.

- **Recheck pass must search-elsewhere for moved files.** The first recheck design returned `file_deleted` whenever the cited path was missing. After feedback, the prompt was updated to grep for the snippet's distinctive content across the codebase first. Validated against a synthetic relocation case where a vulnerability "moved" from `src/old-routes.js` to `src/routes/app.js` — recheck correctly returned `still_present` with `current_snippet` from the new location.

- **`cloneOrRefresh` was destructive on the wrong errors.** A 75-second fetch timeout doesn't mean "your cache is corrupt"; it means "the network is broken." The recovery-by-wipe path was making a transient outage permanent. Distinguishing `RemoteUnreachableError` from genuine cache corruption is two functions and a unit test; the value is letting a VPN reconnect resume the next scan in seconds rather than re-cloning the world.

- **Reachability ROI is debatable.** On /GoWeb at cap=200, 120 hints produced 4 reachable + 116 not-reachable verdicts and burned ~30% of the detection's output token budget. Most "not reachable" verdicts hit transitive deps that aren't directly imported by application code — work the user could shortcut with a `package.json` glance. The per-repo `reachability_enabled` toggle makes that tradeoff visible. We may revisit how/when to run reachability after more real-world data.

- **claude-p refuses `--dangerously-skip-permissions` as root.** Required adding a non-root `claudeuser` (uid 1001) to the worker image and passing `uid` / `gid` to `spawn()`. The per-scan `$HOME` lives at `/tmp/sastbot-<scanRunId>/home/` so concurrent scans (future) won't collide on session state.

- **One stable run isn't enough — but two stable runs back-to-back is signal.** The 6c verification did one persisted scan, looked great, then a second persisted scan produced 11 parse errors and dropped reachability records. Reproducibly intermittent. Two more clean runs after that suggested the API or cache state of claude-p occasionally hits a bad path; orchestrator-level telemetry (parse-error count surfaced as a scan warning) catches it without blocking.

### What's gone

- `backend/src/services/sastService.ts` (Opengrep wrapper)
- `backend/src/services/llmTriageService.ts` (per-finding triage that LLM-mode does inline)
- `OPENGREP_VERSION` ARG + binary install in `docker/backend.Dockerfile`
- `backfillSastContextSnippets` worker-startup hook (opengrep-era SARIF reparse)
- `repos.sast_engine` column
- The opengrep branch in `worker.ts`

If we ever want opengrep back — for hybrid dual-engine runs, deterministic CI gates, or as a fallback when the LLM endpoint is down — the implementation lives in commit `c2c03e8^`'s tree and can be cherry-picked back. Roughly 10 minutes of mechanical work plus a feature flag.

### Migrations applied this batch
1. `20260425100711_m6_llm_sast_engine` — `sast_engine`, `llm_sast_token_budget`, `llm_recheck_token_budget`, `discovery_method`, `evidence_line`
2. `20260425191231_m6_reachability_toggle` — `reachability_enabled`
3. `20260425200000_m6g_drop_sast_engine` — drop `sast_engine`
4. `20260425220000_repo_reachability_dev_filter` — original (mis-)named `reachability_include_dev_deps` column. Superseded by #5.
5. `20260425230000_rename_optional_deps_filter` — renames the column to `reachability_include_optional_deps` and flips the default to `true`. Updates existing rows to match the new default.

### Post-M6g corrections (same day)

**Snippet rule for multi-line findings (`6ae1325`).** The original system prompt said "include 7 lines centered on the finding." Multi-line findings (e.g., the two adjacent `#define` macros at `GsHostProtocol.h:68-69`) came back with no before/after context. Re-spelled the rule as: 3 lines above `start_line` + the `[start_line..end_line]` span + 3 lines below `end_line`. Single-line findings stay at 7 lines; multi-line findings expand to span+6.

**Reachability dev-deps filter saga (`3876021` → `9a55d95`).** First cut tried to skip cdxgen `scope: "optional"` components from the reachability hint set, on the assumption that `optional == dev`. Real data on /GoWeb showed cdxgen marks BOTH devDependencies AND transitive runtime deps as `optional` (CycloneDX scope is overloaded by cdxgen), so the filter dropped at least one verified-reachable runtime CVE (`requirejs@2.3.5` at `ModuleLoader.js:30`).

Correction:
- Renamed column `reachability_include_dev_deps` → `reachability_include_optional_deps`.
- Flipped default `false` → `true` (filter inert by default — include everything, no false negatives).
- Removed the misleading "DEV" badge from SCA issue rows, raw SCA detection rows, and the Components tab.
- Removed the "Hide DEV" filter toggle from the SCA filter bar.
- Deprecated the `hide_dev` API query parameter to a no-op (kept for back-compat).
- The whole `reachability_include_optional_deps` feature is flagged "Under review" in `docs/M6_LLM_SAST_PLAN.md` — it only delivers value with a real lockfile-based dev/runtime classifier (e.g. parsing `package-lock.json`'s `"dev": true`); without that, it's mostly cosmetic and may be ripped entirely.

### What we learned from the dev-deps misadventure

- **CycloneDX `scope` semantics are overloaded by cdxgen.** The CycloneDX spec means `optional` as "optional component"; cdxgen lumps in transitive runtime deps too. Treating `optional` as a clean dev-only signal is a category error.
- **Reachability ROI on a frontend repo is genuinely thin** — but most of the noise is dev tooling that *would* be filtered correctly with a proper lockfile-based classifier. The signal (`requirejs`, `underscore`'s `_.template`, `three`) is exactly what reachability is meant to surface.
- **Don't ship a UI label that lies, even if it's convenient.** A "DEV" badge on a transitive runtime dep is worse than no badge — it tricks the operator into deprioritizing a real risk.

### Investigated: can cdxgen tell us dev vs runtime?

Follow-up after the dev-deps correction. User research mentioned a possible `development` scope value and a `--required-only` flag in cdxgen docs. We checked our actual cdxgen v10.x output:

- **CycloneDX 1.6 spec defines only three `scope` values**: `required`, `optional`, `excluded`. There is no `development` value in the spec. Whatever doc the user saw is either older, aspirational, or referring to some non-spec extension that v10.x doesn't emit.
- **Our SBOM data confirms**: distinct `scope` values across 18,935 components on the /GoWeb scan are exactly `required` (629), `optional` (18,057), and null (249). No `development`.
- **`cdxgen --help` confirms**: `--required-only` is the only scope-aware filter flag. Nothing produces a per-component dev marker, no `dev: true` property, no separate `development` scope.
- **The CycloneDX `dependencies` graph isn't a runtime classifier either.** It's an adjacency list of "X depends on Y" relationships. We tested by walking from the root component's `bom-ref`: 99%+ of components are reachable, including obvious dev tools like `webpack-dev-server`, `terser`, `babel-traverse`, `react-dev-utils`. The graph mixes runtime + dev paths.
- **What `required` actually means in cdxgen**: first-level direct deps from `package.json:dependencies`. `optional` is everything else — devDependencies AND transitive runtime deps lumped together. So `--required-only` would drop transitive runtime CVEs (`qs` reachable through Express, `body-parser`, etc.) — *worse* than the current state, not better.

**Conclusion (initial)**: cdxgen's output as-shipped on v10.11.0 does not give us a usable dev-vs-runtime classifier. To get a real one we'd need to walk `package.json` ourselves: from `dependencies` (runtime direct), traverse the lockfile's runtime closure, mark anything reached as runtime; anything in `components` outside that closure is dev-only. ~1 day per ecosystem (npm, Python, Java each need their own lockfile-walking logic).

**Update — cdxgen 12.2 ships a real dev marker.** Found via cdxgen issue [#3927](https://github.com/cdxgen/cdxgen/issues/3927) (and the PR it follows from, #3925, merged 2026-04-24 → released as v12.2.1 the same day). cdxgen 12.2+ emits `cdx:npm:package:development=true` as a component property for npm packages whose lockfile entry has `dev: true`. We're pinned to `^10.10.7`, so we don't have it. The fix is small:

1. Bump `@cyclonedx/cdxgen` from `^10.10.7` → `^12.2`. Major-version jump; verify SBOM shape didn't change in incompatible ways for the rest of the pipeline.
2. In `sbomService.persistComponents`, read the `cdx:npm:package:development` property and persist a new `SbomComponent.isDevOnly` boolean.
3. In the worker LLM SAST pipeline, use `isDevOnly` instead of (or in addition to) the `latestComponentScope === "optional"` filter.
4. UI: optionally bring back a "DEV" badge — this time with truthful semantics, sourced from `isDevOnly`.

**Caveats:**
- Issue #3927 (still open) — `devOptional: true` lockfile entries don't get the marker yet. Most dev deps will be tagged correctly; a small fraction of devOptional ones won't. Acceptable for v1.
- npm-only. Python (poetry/pip), Java (maven/gradle), Go, etc. still need their own logic. Document the limitation; ship npm support first; expand as needed.

The plan doc's "Under review" item is updated with this path forward.

---

## M6h — cdxgen 12.2 dev marker (2026-04-25)

### Why we did this

The dev-deps misadventure (`3876021` → `9a55d95`) ended with us removing the "DEV" badge entirely because cdxgen v10.x's only ecosystem hint, CycloneDX `scope: "optional"`, conflated devDependencies with transitive runtime deps. Verification on the test-vuln-repo confirmed it concretely: 1 `required` component (lodash, the first direct dep), 412 `optional` — including form-data and other transitive runtime deps that the LLM reachability hint set legitimately needs.

cdxgen 12.2.1 ships a real npm dev classifier as the `cdx:npm:package:development=true` property, sourced from `package-lock.json`'s `dev: true` entries. With that we can distinguish dev from runtime honestly.

### What shipped

**`@cyclonedx/cdxgen` bumped from `^10.10.7` → `^12.2.1`.** No source changes needed in `sbomService.runCdxgen` — the SBOM shape stayed compatible (`specVersion: 1.7`, `bomFormat: CycloneDX`, `evidence.identity[]` always an array, `properties[name=SrcFile]` and `manifest-analysis` evidence still both present).

**One new wart from cdxgen 12**: a "SECURE MODE" diagnostic block now prints to stderr when run as root with credential-pattern env vars (`MASTER_KEY`, `BOOTSTRAP_ADMIN_EMAIL`, `NODE_PATH`). Noisy but non-fatal — the SBOM is still written. Future cleanup: drop the cdxgen subprocess to a non-root user (it already runs in the worker container, which has the `claudeuser` user from M6).

**`SbomComponent.isDevOnly` and `ScaIssue.latestIsDevOnly` columns** added (both `BOOLEAN NOT NULL DEFAULT false`). `sbomService.extractIsDevOnly` reads `properties[name=cdx:npm:package:development]==="true"` and `issueService.upsertScaIssueFromDetection` denormalizes it onto the issue. Existing rows default to `false` ("not declared dev"), which is the conservative choice — they stay in scans rather than being silently filtered.

**Repo flag renamed**: `reachability_include_optional_deps` → `reachability_include_dev_deps`. The previous name referred to cdxgen's `scope: "optional"` (which we now don't filter on at all); the new name reflects the truthful semantics. Default still `true` (include everything; flip off to skip reachability cost on npm dev tooling). Worker filter changed from `latestComponentScope: { not: "optional" }` to `latestIsDevOnly: false` — npm-only signal: non-npm components have `isDevOnly=false` and stay in the hint set as before.

**"Dev" badge restored** with truthful semantics:
- SCA issue rows: chip alongside "Has fix" / "Reachable" badges, keyed on `latest_is_dev_only`.
- Components tab: small badge next to the package name, keyed on `is_dev_only`.

The repo edit form copy was rewritten to explain the new filter (npm-only, driven by lockfile `dev: true` marker, with the cdxgen #3927 caveat called out).

### Schema changes

1. `20260426040224_m6h_cdxgen_dev_marker` — adds `sbom_components.is_dev_only` and `sca_issues.latest_is_dev_only` (both `BOOLEAN NOT NULL DEFAULT false`).
2. `20260426040800_m6h_rename_optional_to_dev` — renames `repos.reachability_include_optional_deps` → `repos.reachability_include_dev_deps`. Manual SQL (Prisma's auto-migration would have dropped+added and lost the existing values on three rows).

### Caveats (carried forward)

- **cdxgen issue #3927** (still open) — `devOptional: true` lockfile entries miss the dev marker. A small fraction of dev-only npm packages will read as `false`. Acceptable for v1; revisit if it bites.
- **npm-only.** Python (poetry/pip), Java (maven/gradle), Go, etc. still get `is_dev_only=false` for everything. Other ecosystems would need their own per-cdxgen-extractor markers.

### What we learned

- **Renames stick when the new name is truthful.** We churned the column name twice in two days (`reachability_include_dev_deps` → `_optional_deps` → `_dev_deps` again). The first rename was correct on the surface but wrong in semantics, because cdxgen v10's `optional` scope didn't actually mean dev. Once cdxgen could speak the real signal, the original name became correct again. Worth holding off on renames until the underlying source-of-truth is reliable — or, if you've shipped one based on a borrowed proxy, be willing to flip back when the real signal arrives.
- **Manual rename migration > drop+add for renamed columns.** Prisma's `migrate dev` saw the schema change as a column drop + column add and warned about losing data. Hand-writing `ALTER TABLE … RENAME COLUMN` preserves the three existing repo settings without any backfill step.
- **Verification before schema design saved a round-trip.** Running cdxgen 12.2 against the test-vuln-repo *before* writing the migration confirmed: marker is named `cdx:npm:package:development`, value is the string `"true"`, present on 362/413 components for a tiny project (jest+mocha closure), absent on transitive runtime (form-data via axios). One half-hour of verification meant zero schema iterations.

### Follow-ups (same day, after the feature commit)

**Canonical package names with group prefix (`b4043e7`).** UI verification of the dev badges turned up a row showing "Upgrade Node.js 25.6.0..." — but that's the runtime EOL, and the actual SBOM component was `@types/node` (TypeScript types, dev-only). Root cause: cdxgen splits scoped/namespaced packages into `group` + `name` (e.g. `group="@types"`, `name="node"`), but `sbomService.persistComponents` was storing only the bare `name`. That collided with `eolService.ts`'s slug map (`node: "nodejs"`), producing the bogus alert.

Fix: combine `group + name` into a canonical name in `persistComponents`, with per-ecosystem joiner — `/` for npm (matches OSV.dev's `@scope/name` format), `:` for maven (matches `groupId:artifactId`). Verified: 13 `@types/*`, all `@babel/*`, `@jest/*`, `@tootallnate/*` etc. now stored with full names. Issue count dropped 42→41, High dropped 12→11 (the one bogus EOL alert disappeared). Existing rows under bare names become orphans on next scan; for production repos the operator can rescan and let them age out, or `DELETE FROM sca_issues WHERE ...` manually.

**Drive-by typecheck fixes (folded into the feature commit `977be60`).** Three pre-existing errors that were failing `tsc --noEmit` on `main` before this work:
- `cveKnowledgeService.ts:97` — bogus 2nd argument to `callLlm` (no longer accepts options); dropped.
- `mappers.ts:50` — `"cancelled"` was added to `ScanStatus` in the DB during the M5 cancel feature but never to this local TS type union; added.
- `reachabilityService.ts:184` — Zod `.default([])` produces an output that's still optional in the type system; added `?? []` guard.

**Dead-code cleanup (same commit).** `ScopeDetailPage.tsx`'s `TriageBadge` was a stale duplicate of `StatusBadge` left over when SAST + SCA unified to a single status vocabulary in M5. Plus a handful of unused lucide imports and unused shadcn Card subcomponents.

---

## M6i — live scan progress + worker trust gates + UI polish (2026-04-26)

### Why we did this

Three things compounded in one session:
1. The "Scan in progress…" placeholder was the same regardless of phase or how long the scan had been running, leading to "is it stuck?" panic on a 6-hour /GoWeb run.
2. A degraded scan (cdxgen crashed silently over airplane wifi → 0 components) silently auto-marked all 41 real findings as "fixed" via the SCA auto-fix sweep.
3. A bunch of small SAST detail-panel issues had accumulated as the M5/M6 transition left Opengrep-era display logic visible on LLM-mode findings.

### What shipped

**Live scan progress (v1).** New `scan_runs.current_phase TEXT` + `phase_progress JSONB` columns. Worker emits phase markers at every boundary (cloning / cdxgen / osv / eol / llm_detection / llm_recheck / sca_summaries / finalizing) and within-phase counts where applicable (per N OSV components, per 5 SCA summaries). Surfaced in two UI places:
- Scope detail page: amber `ScanProgressBanner` between header and severity summary while a scan is running. Phase label + progress bar.
- Scopes list page: "Last Scan" column shows phase + n/total during an active scan (replaces the misleading "2m ago" timestamp from the previous good scan). One batched query across all scope IDs avoids N+1.
- Scan detail page: "Scan in progress…" placeholder upgraded to the same phase + progress card.
- `useScopes()` polls every 3s while any scope has an active scan; stops polling once everything is idle.

v2 (overall % + time-remaining estimate from per-scope baseline) deliberately deferred — needs historical phase-duration data v1 produces.

**Worker trust gates.** A degraded scan no longer destroys data:
- `ScanWarning` schema gains `severity: "info" | "error"`. Existing parse-error warnings classified as info; new ones for actual failure modes emit error.
- `runCdxgen` now returns `{ doc, ok, failureReason? }` so the caller can tell a hard failure (no output written) from a legitimate empty SBOM.
- Worker emits error-severity warnings at three sites: `cdxgen_failed` (runCdxgen reports !ok), `llm_sast_detection_failed` (claude-p `exitCode !== 0`), and an info-level `cdxgen_zero_components` notice (0 components when previous scan had >0; *doesn't* block auto-fix because legitimate manifest removal should still propagate).
- New `hasErrorWarnings(scanRunId)` helper. **SCA auto-fix sweep skips entirely** when any error-severity warning exists. The audit trail still records the failed scan; existing findings stay put.
- **Scope `lastScanRunId` advancement also gated** on trustworthiness. `lastScanCompletedAt` always advances (operational truth: "operator just tried"). `lastScanRunId` only advances on trustworthy scans (SCA/SAST default filters pivot off it). Without this gate, the "no issues match" filter result hides real findings on the next page load.
- Restored 41 wrongly-fixed test-vuln-repo SCA issues + reset its scope pointer back to the morning's good scan.

**SAST detail-panel cleanup.** Six fixes targeting Opengrep-era display logic:
1. Drop the `llm:CWE-XXX` sub-line under the filename in the location column for LLM-mode findings (CWE is shown elsewhere; the rule_id is just a placeholder).
2. Skip the duplicate "Rule description: ..." block when the message is the same as the LLM summary, OR when rule_id is an `llm:` placeholder.
3. Drop the redundant "Rule: llm:CWE-798" entry in the bottom metadata when rule_id is an LLM placeholder; only "CWE: ..." remains.
4. SCA chip strip uses styled lozenge badges: CVE (red), EOL (gray, replacing "DEPRECATED"), Has fix (green), Dev (blue), Reachable (amber). All consistent shape.
5. Token usage on scan detail header: `{N} LLM calls · {input}k in / {output}k out` alongside duration. Tooltip notes cache tokens aren't included.
6. Scan detail header restructured by visual hierarchy — status biggest and color-coded, LLM info, duration, then date+audit-view-disclaimer in muted italic.

**SAST snippet rendering — match-line locator.** The LLM is inconsistent about following the prompt's "3 lines above start_line + span + 3 lines below" rule. Sometimes the snippet has only 1 line of context above (GsAccount.cpp:27), sometimes 18+ (GsHostProtocol.h:68 with 25-line snippet). The renderer can't trust a fixed offset.

Fix: `findAllKeywordMatchIndices` searches the snippet for distinctive identifiers (UPPER_SNAKE_CASE) or keywords (≥5 chars after stopword filter, naive trailing-s stem) from the issue summary. Returns every line tied at the highest score. The renderer treats those as the match span, displays 3 lines above the first match + the contiguous span + 3 lines below. Falls back to offset-from-top only when no keywords match. Verified on:
- GsHostProtocol.h:68 — snippet has 25 lines, offset-from-top would highlight `GS_DEFAULT_IP`. Keyword search finds both `GS_SUPER_USER_PASSWORD` (line 68) and `GS_SUPER_USER_HDI_PASSWORD` (line 69), highlights both, shows lines 65–72.
- GsAccount.cpp:27 — short 6-line snippet, but offset-from-top would highlight `loginState = GS_USER_NONE` (line 29). Keyword search finds `obj->adminPassword[0] = 0` (line 27 = match line), highlights only line 27.

### Schema changes

1. `20260426151053_m6i_scan_progress` — `scan_runs.current_phase` + `phase_progress`.

(No migration for trust gates — purely a worker-logic change. ScanWarning's new `severity` field defaults to `"info"`, so existing rows render correctly.)

### What we learned

- **A scan that finds nothing is NOT the same as a scan that worked and confirmed nothing exists.** The auto-fix sweep was conflating these. Always think about whether a piece of remediation logic is gated on the *quality* of the input data, not just the *quantity*.
- **Scope-level pivot pointers are easy to forget about.** `lastScanRunId` is used by default filters across multiple list endpoints. Updating it on a degraded scan made all previously-found issues invisible by default — even though the data was intact. Pivot pointers should only advance on trustworthy data; "operational truth" timestamps can be separate.
- **Inconsistent LLM output requires inference, not assumption.** The "3 lines above start_line" rule from the snippet prompt holds maybe 30% of the time. Real solution: search the snippet content for the actual issue using the summary as a clue, instead of assuming a fixed offset.
- **Vite HMR is unreliable through the Docker bind mount on this setup.** Most file edits require a full `docker compose restart frontend` to pick up. Live with it; restart unconditionally after a meaningful change.
- **The 6-hour /GoWeb hang was a free production simulation** of what happens when claude-p stalls over a flaky network. Now the worker treats `exitCode !== 0` as untrust signal and the operator's data survives. Same gate would catch a real Dokploy outage.

**Next** — M5d (Scheduler) and M5e (Hardening + rate limiting) are still on deck from M5; both are independent of M6. After that, `docs/M6_LLM_SAST_PLAN.md` has a "Future improvements" section (deep-reasoning model option, streaming UI, lockfile-based dev classifier for non-npm ecosystems, etc.). The pending-features memory has the full queue including notifications, scan resilience (wall-clock cap + heartbeat + retry), dashboard merge, scan progress v2 (overall % + ETA), and remaining SAST UI polish (the user flagged "still issues in the SAST issues page" — needs a fresh look).

---

## M6j/M6k — SARIF export + worker-built snippets (2026-05-08)

### Why we did this

Three threads converged in one batch:
1. The LLM-mode SAST has been live since M6 but produced no portable
   export. Operators wanted a SARIF file they could hand to dashboards,
   CI gates, or compliance evidence — the same shape Opengrep used to
   produce, just generated from our deduplicated `sast_issues`.
2. M6i exposed a deeper problem with LLM-emitted snippets: the model is
   wildly inconsistent about how many context lines it includes (0 to 20+
   preamble lines), forcing the frontend to use a keyword-search heuristic
   to locate the actual match line. M6i made the heuristic *work*; this
   batch made it *unnecessary*.
3. While building SARIF, scrutinizing it against the spec revealed several
   places we were freestyling instead of using the standard idioms — most
   visibly emitting `partialFingerprints` and `properties.cwe` on every
   result.

### What shipped

**SARIF v2.1.0 export.** Every successful scan now stores a SARIF document
in `scan_runs.sast_sarif` (JSONB), regenerated post-detection on each scan
and backfilled on worker boot for runs that pre-date the column. New
`GET /scans/:id/sast-sarif` returns the JSON with an attachment
disposition; new `SastSarifViewerPage` route mirrors the SBOM viewer
(Monaco-based, syntax-highlighted, downloadable). Two new buttons on the
scan detail page header: *View SARIF* / *Download SARIF*.

**Producer-shape only — no RMS metadata in the scan-level SARIF.** SARIF
§3.27.23 + Appendix B explicitly assign `partialFingerprints` and
lifecycle fields (first/last seen, triage status) to the result management
system, not the direct producer. In SASTBot the *scan* is the producer
(a single LLM run on one revision) and the *scope* is the RMS (cross-scan
dedup, triage, lifecycle). So the scan-level SARIF emits only what the
producer can know: `ruleId`, `level`, `message`, `locations`, plus
`properties.severity` for the finer-grained 5-band scale that SARIF's
4-level enum can't carry losslessly. A future scope-level SARIF (with
fingerprints + lifecycle) is a natural follow-up.

**CWE references via taxonomies + relationships, not property bags.** First
pass put `properties.cwe` on each result. The user spotted that this was
both non-idiomatic (SARIF has a first-class CWE pattern via §3.19
taxonomies + §3.49 relationships) AND triple-encoded — the rule_id is
already `llm:CWE-798`, the rule's `helpUri` already points at MITRE, and
emitting per-result `taxa[]` repeats the same CWE on every finding under
that rule.

The cleanup: `runs[0].taxonomies[0]` declares a CWE taxonomy with the
deduped set of cited CWEs (each with a `helpUri` to MITRE). Each rule
descriptor carries
`relationships: [{target: {toolComponent: {name: "CWE"}, id: "798"}, kinds: ["relevant"]}]`.
Results dereference through `ruleId`. No per-result `taxa[]`, no
`properties.cwe`. Single canonical place for the rule→weakness mapping.

**`region` + `contextRegion` per SARIF §3.30.** Initially we put the whole
snippet in `region.snippet`. The spec model is cleaner: `region` carries
the problem location (just startLine + optional endLine, no snippet),
`contextRegion` carries the surrounding lines + the snippet text. A SARIF
reader recovers "which line is the problem within the snippet" via
`region.startLine - contextRegion.startLine`.

**Worker reads snippets from disk; LLM stops emitting them.** The
detection prompt no longer asks for a `snippet` field; the system prompt
makes the worker's responsibility explicit. New
`backend/src/services/sourceSnippet.ts` exposes `readSourceSnippet` with
a path-traversal guard. `persistDetection` replaces the LLM-supplied
snippet with a file-read snippet for both SAST findings and reachability
call sites. `applyRecheckVerdicts` does the same for `still_present`
verdicts (the line itself didn't move, so we re-read at the existing
`latestStartLine`). All three accept the LLM-supplied snippet as
fallback only — used solely when the file isn't readable.

`sast_issues.latest_end_line` (nullable INT) joined the schema so
multi-line problems get all problem rows + canonical 3 lines of context
on each side. SARIF emits `region.endLine` when set.

**Frontend `ContextSnippet` simplified.** With canonical snippets, the
keyword-search heuristic and parallel-prefix span extension are dead
code. Replaced with a straight offset-based renderer that takes
`matchLine` + optional `matchEndLine`. Removed `findAllKeywordMatchIndices`
and the parallel-prefix logic — net deletion. Defensive comment in
CLAUDE.md not to reintroduce them.

**`backfillSastSnippets` worker startup hook** regenerates legacy
`latestSnippet` values from disk for any retained-clone scope. Skips
absence rows. Just ran on the 12 issues for Gocator Classic `/`: every
snippet is now exactly 7 lines (3+1+3) regardless of what the LLM
originally emitted (which had ranged from 6 to 25 lines). Old data with
no retained clone is left as-is and will fix up on the next scan.

**Token economy bonus.** Snippet text was the single biggest contributor
to detection-pass output token count; cutting it saves real money on
every scan, especially on repos with hundreds of findings.

### Schema changes

1. `20260509002905_m6j_scan_run_sarif_export` — `scan_runs.sast_sarif` JSONB nullable.
2. `20260509010131_m6k_sast_end_line` — `sast_issues.latest_end_line` INT nullable.

### What we learned

- **Architectural distinctions in standards aren't ceremony — they map to
  real system boundaries.** SARIF's "producer vs RMS" distinction is
  essentially the difference between "what one tool said about one
  revision" and "what we currently believe about this codebase." Once
  named, that boundary clarified WHY first-seen / last-seen / triage
  state don't belong on the scan-level export and pointed at a future
  scope-level export naturally.
- **If the data model already encodes information once, don't duplicate
  it in the export.** Per-result `taxa[]` was redundant with
  `ruleId="llm:CWE-798"`. The fix wasn't to drop both — the rule
  descriptor IS the right place for the rule→weakness mapping (via
  `relationships`). Find the canonical place once; let everything else
  reference it.
- **Stop fixing inconsistency in the consumer; fix it at the producer.**
  M6i added a sophisticated keyword-search heuristic to the frontend to
  cope with LLM snippet drift. M6k makes the heuristic unnecessary by
  giving the data a stable shape at write-time. Net code: substantially
  smaller. The system prompt got *simpler* — saying "don't emit a
  snippet" beats explaining the 7-line rule across three places.
- **The LLM is best at reasoning, not transcription.** Reading bytes from
  a file is something machines do better and cheaper. Use the LLM for
  identification (where + what kind), and use code for everything that
  has a deterministic answer.

**Next** — Same as M6i, plus several SARIF follow-ups now in the
pending-features memory: scope-level SARIF export with RMS-augmented
fields (fingerprints, triage state, lifecycle dates), SCA reachability
rendered in SARIF too (currently only SAST findings appear), and
surfacing unparseable-record contents on the warning so operators can
see what the LLM emitted that didn't conform.

## M6l — SCA accuracy: filter OSV results by component version (2026-05-08)

### Why we did this

The handoff from the previous session flagged a Gocator Classic finding
that looked wrong: `System.Net.Http@4.3.4` was being reported as
vulnerable to CVE-2017-0247 and four other CVEs that — by reading the
OSV records directly — were already fixed in `4.3.4` or only ever
affected unrelated packages (`Microsoft.AspNetCore.Mvc`).

Investigation showed all 5 findings on that one component were false
positives, and that the same bug had been silently inflating SCA noise
on every NuGet-heavy scope.

### Root cause

`backend/src/services/osvService.ts` — `queryOsvForPurl` was POSTing
`{ package: { purl } }` to `https://api.osv.dev/v1/query`. cdxgen often
emits **bare purls** (no `@version`), especially for NuGet (60/99
components in the local DB) and `generic` (27/33). When OSV.dev
receives a bare purl with no `version` field, it returns *every*
advisory that has ever affected the package — across all versions —
and we were persisting all of them. There was no version-vs-affected-
range comparison anywhere in the pipeline; we relied entirely on OSV
to filter, then handed it the data needed to do so.

Verified empirically against `pkg:nuget/System.Net.Http`:

| Request body                                                              | OSV returns           |
|---------------------------------------------------------------------------|-----------------------|
| `{ package: { purl: "pkg:nuget/System.Net.Http" } }`                      | 5 vulns (all-time)    |
| `{ version: "4.3.4", package: { purl: "pkg:nuget/System.Net.Http" } }`    | 0 vulns (correct)     |
| `{ package: { purl: "pkg:nuget/System.Net.Http@4.3.4" } }`                | 0 vulns (correct)     |
| `{ version: "4.3.4", package: { purl: "pkg:nuget/System.Net.Http@4.3.4" } }` | error: "version specified in params and PURL query" |

So OSV will filter correctly via *either* a versioned purl *or* a
`version` field — but not both at once.

### What shipped

`queryOsvForPurl(purl, version)` now sends `{ version, package: { purl: bare } }`
when a version is known on the `SbomComponent`. To avoid the
"version specified in params and PURL query" rejection from OSV when
cdxgen *does* emit a versioned purl, a new `purlWithoutVersion(purl)`
helper strips the `@version` suffix while preserving qualifiers
(`?type=jar`) and subpath (`#…`). Scoped npm packages
(`pkg:npm/%40types/node@1.2.3`) are safe — the scope's `@` is
percent-encoded as `%40`, so `lastIndexOf('@')` only ever finds the
version separator.

The body construction is split into a pure `buildOsvQueryBody(purl, version)`
function so unit tests cover the wire format directly without mocking
fetch. Eight new tests in `backend/tests/osvService.test.ts` (purl
stripping for bare/versioned/qualified/subpath/scoped-npm shapes,
plus the three body-shape cases). 26/26 pass; typecheck clean.

### Cleanup of existing false-positive rows

Not done automatically. The existing SCA auto-fix sweep already marks
issues `fixed` when they're absent from a successful rescan
(M6i hardened it to gate on `hasErrorWarnings`). Re-scan an affected
scope and the false positives clear themselves through the standard
operator-visible path — no surprise mutations to the issue list. The
Gocator Classic root scope is the obvious first re-scan target;
`docs/HANDOFF_SCA_ACCURACY.md` was the disposable companion to this
work and was deleted.

### What we learned

- **"OSV returned it" is not the same as "the version is affected".**
  We treated `/v1/query` as if it always filtered by version — it does,
  but only when the request actually carries one. cdxgen's purl format
  is non-uniform across ecosystems, so relying on the purl alone to
  encode the version meant 88/3409 components (mostly NuGet) silently
  bypassed the version filter.
- **Trust the data, not the upstream API's defaults.** We had
  `SbomComponent.version` populated correctly the whole time. The fix
  was to *use* it explicitly rather than to assume the purl encoded it.
  Future external-API integrations should pass every dimension we
  ourselves know, not assume the request carries it implicitly.
- **A pure helper unlocks testability.** Pulling
  `buildOsvQueryBody` out as a pure function turned a fetch-mocking
  test into three trivial `expect(...).toEqual(...)` assertions. Worth
  doing whenever a network call has interesting body construction.

**Next** — Trigger a re-scan on the Gocator Classic root scope to
clear the five false-positive `System.Net.Http` issues via the
existing auto-fix sweep. Confirm the scope's SCA count drops by 5,
then audit other NuGet-heavy scopes the same way.

## Scan-page live UX + worker diagnostics (2026-05-09)

### Why we did this

The M6l verification scan exposed three rough edges on the scan detail
page that all came from the same root cause: the page was assuming
that "data is fresh because it was fetched recently" without a way to
prove it.

1. The elapsed timer didn't tick. Watching a 14-min Opus run on
   `/GoWeb`, the duration display stayed frozen between phase
   transitions and only jumped when `phase_progress` happened to
   change.
2. The "X of 300000 tokens" counter stayed at 0 for the entire LLM
   detection phase, then flipped to its final value at the end. Made
   long-running scans look hung.
3. The recheck phase stuck at "0 of N issues" for the full ~60s
   duration, then flashed briefly before the page moved on.
4. After scan completion, the SAST count on the scan page sometimes
   showed an incorrect transient value (11) before settling on the
   real count (24).

Separately, a /GoWeb scan crashed silently mid-detection with no stack
trace — pnpm just printed `ELIFECYCLE Command failed` and the worker
restarted via Docker. We had no signal about what broke.

### Root causes

**TanStack Query v5 structural sharing.** Identical content between
refetches → same `data` reference → component doesn't re-render.
`formatDuration(started_at, undefined)` reads `Date.now()` at render
time, so without a render the timer can't advance. Same root cause for
why `useSastFindings` cached stale data when it wasn't polling.

**Worker calls `setPhase` once per phase boundary.** During the long
LLM detection / recheck phases, no further updates happen — the
phase_progress JSONB stays at `{done: 0, total: budget, label: "..."}`
for the entire phase. Recheck verdicts arrive batched at the end of
the claude-p run (one big assistant message), so even count-based
progress can't show movement during the run.

**No `uncaughtException` / `unhandledRejection` handlers.** Any async
error in stream-event callbacks killed the worker silently. Node's
default exit-on-unhandled-rejection behavior leaves no diagnostic.

### What shipped

**Frontend ticker hook.** New `useNow(intervalMs, enabled)` in
`frontend/src/lib/useNow.ts` — `setInterval`-driven `useState` that
forces a re-render every second while the scan is live. Bound
explicitly into `formatDuration(startedAt, finishedAt, now)` as a
third argument so React's reconciler sees the JSX dependency on
`now`; the earlier "just call the hook and rely on the side-effect
re-render" form didn't work because nothing in the rendered output
referenced the returned value.

**Per-message LLM token usage.** `spawnClaudeAndStream` now extracts
`message.usage` from each `assistant` stream event and accumulates
cumulatively (`inputTokens / outputTokens / cache_*` per turn). The
terminal `result` event still overwrites with claude-p's authoritative
session totals, so accumulation drift doesn't affect the post-run
audit log. New optional `onProgress(usage)` callback on
`SpawnClaudeInput`. The worker passes a 2s-throttled callback that
calls `setPhase` with `done = inputTokens + outputTokens` against
`total = repo.llmSastTokenBudget`. Same pattern reused for recheck —
verdict-count was the wrong unit (verdicts arrive batched at the end
of the run; counter only moves once); switched recheck progress to
tokens-against-budget for visual continuity with detection.

**Cancelled-scan UI fix.** `isTerminal` now includes `"cancelled"`.
Without this, a cancelled scan showed both "Cancelled" in the header
status AND "Scan in progress…" in the lower card simultaneously.

**`showResults` / `showInProgress` gates.** Tables and summary cards
now require `isTerminal && success && !dataIsFetching` to render;
otherwise the in-progress UI stays up. The "scan transient" between
`status='success'` and the post-recheck-apply data refetch was a real
race — fixed two ways for belt-and-suspenders:

1. `useScanFindings` and `useSastFindings` now poll every 2s while the
   cached scan data shows `pending`/`running`. Reads scan status from
   the QueryClient cache via a `liveRefetchInterval` helper — caller
   API unchanged.
2. `useEffect` in `ScanDetailPage` invalidates the SAST / SCA /
   components caches the moment scan status transitions to terminal.
   Covers the race where the scan poll wins, `refetchInterval` returns
   false, and SAST polling stops before catching the
   post-recheck-apply state.

**Worker fatal handlers.** `worker.ts` now installs
`process.on('uncaughtException')` and `process.on('unhandledRejection')`
that log `level=fatal` with full stack before exiting non-zero. We
haven't reproduced the silent crash since landing them, but the next
recurrence will print actionable info.

### What we learned

- **"It re-renders on data change" is not a contract.** TanStack
  Query's structural sharing is an optimization that makes the
  consumer's view of "freshness" subtly wrong: the data you read is
  fresh, but the *moment* the component last re-rendered may be much
  older than you'd expect. The fix is always to bind your
  wall-clock-dependent computation to a tick source, not to data
  state.
- **Throttle output, not invocation.** The first attempt at recheck
  progress was verdict-count-based with a 2s throttle. Verdicts
  arrived all at once at the end of the claude-p run, the throttle
  blocked all but the first, and the user saw "0 → 1 → done" with no
  intermediate movement. Switching to tokens-per-assistant-event
  surfaces the actual work happening (one tool call = one event = one
  update). When picking a progress unit, pick the one that ticks at
  the cadence the LLM produces output, not the cadence the post-run
  semantics imply.
- **Belt + suspenders for race conditions in client caches.** Polling
  every 2s during running gives most refreshes; explicit
  `invalidateQueries` on the status transition catches the "last poll
  was too early" race. Either alone leaves a window; both together
  close it.
- **Diagnostic wiring is cheap; debug only when you have signal.**
  The fatal handlers are 8 lines of code. We spent more time
  speculating about what might be killing the worker than we'd have
  spent landing the handlers and waiting for the next crash to print
  a stack. Default to instrumentation-first when the bug is
  intermittent.

## M6m — explicit per-phase, per-repo LLM effort (2026-05-09)

### Why we did this

After the live-progress fixes, we re-ran scans to validate. Then
swapped the configured model from Sonnet 4.6 to Opus 4.7 to compare.
Numbers were striking — and confusing.

| Scope | Sonnet 4.6 | Opus 4.7 | Δ |
|-------|-----------|----------|---|
| Root: detection duration | 403s | 877s | 2.2× slower |
| Root: cache reads | 4.3M | 22.3M | 5.2× more |
| Root: detection cost | $2.23 | $13.84 | 6.2× more |
| Root: SAST findings | 24 | 39 | +15 |
| /GoWeb: detection cost | ~$1 | $3.81 | 4× more |
| /GoWeb: SAST findings | 8 | 18 | +10 |

Opus produced more thorough output for more cost. But how much of
that delta was "Opus is a better model" vs "Opus was running at a
different effort tier"? We had no idea — we never set `--effort`
explicitly.

### What's actually happening with effort

`claude --help` exposes `--effort <level>` with values
`low | medium | high | xhigh | max`. Two layers of defaults:

| Layer | Default for Opus 4.7 |
|-------|----------------------|
| Anthropic API (raw `messages.create`) | `high` |
| Claude Code product (incl. `claude -p`) | **`xhigh`** — raised "for all plans" in 4.7's release notes |

So the Sonnet runs were at Sonnet's `high` default; the Opus runs
were at Opus's `xhigh` default. We were comparing different efforts,
not just different models. The Anthropic effort docs explicitly
recommend xhigh as the starting point for Opus 4.7 on coding/agentic
work, so the Opus runs were doing the right thing — but the
comparison was conflated and the cost wasn't a deliberate choice.

### What shipped

**Schema migration `20260509093900_m6m_repo_effort_drop_triage_budget`:**

- `repos.llm_sast_effort    TEXT NOT NULL DEFAULT 'xhigh'`
- `repos.llm_recheck_effort TEXT NOT NULL DEFAULT 'medium'`
- `DROP app_settings.llm_triage_token_budget` — its `llmTriageService`
  was removed in M6g; the field had been orphaned since (read by no
  service code, still surfaced as "Token budget per scan" on the
  settings page).

**Backend.** `spawnClaudeAndStream` now requires `effortLevel` and
passes `--effort <level>` to claude-p. `RunDetectionInput` /
`RunRecheckInput` plumb it through; worker reads from
`repo.llmSastEffort` / `repo.llmRecheckEffort`. The dry-run CLI
matches.

**Frontend.** Repo edit dialog: side-by-side selectors for SAST
detection / recheck effort, between Reachability analysis and Source
URL template. Settings page: removed the orphan "Token budget per
scan" input — reachability minimum severity is now the only field in
that section, with copy noting that per-repo SAST settings live on
the repo edit page.

**Defaults follow the docs.** Detection at `xhigh` ("Start with xhigh
for coding and agentic use cases" — Opus 4.7 effort guide). Recheck
at `medium` — recheck is narrow verification (one location, one
snippet, three discrete answers), no need for deep agentic
exploration.

### What we learned

- **Always pass effort explicitly.** Claude Code's product default
  has already changed once (high → xhigh in the 4.7 release) and may
  change again. A scan that's "the same" between sessions but at a
  different effort tier is silently a different test. Effort is a
  first-class parameter, not a model attribute.
- **Per-phase before per-model.** Recheck and detection have
  different shapes — one is open-ended search, the other is narrow
  verification. Tying effort to the model alone (cheap-model =
  low-effort, expensive-model = high-effort) misses that detection
  on a cheap model still benefits from medium/high effort. Phase is
  the better dimension.
- **A "dead" field can survive on the UI for a long time.**
  `llm_triage_token_budget` was orphaned in M6g (April) and still
  shipped in the settings page until today (May). Reading the schema
  from the form is fine; the form is supposed to drift TOWARD what
  the schema says, not the other way around. When deleting service
  code, also delete the schema field, then the wire types, then the
  UI — top to bottom.
- **Open question for next time:** the SCA-hint set passed to LLM
  detection (currently 11-120 entries depending on scope) is
  meaningful work — anti-duplication against OSV findings + Goal 2
  reachability analysis. It's already gated by
  `repo.reachability_enabled`, but a finer-grained cap
  (`max_sca_hints = top-N by CVSS`) might let operators trade
  detection time against reachability coverage on hint-heavy scopes.
  Filed but not landed.

**Next** — Now that effort is explicit, run a real Sonnet@high vs
Opus@xhigh comparison knowing the variables, plus a Sonnet@high vs
Sonnet@max run to isolate the effort dimension from the model
dimension. The 0-fixed/all-still-present pattern across recheck runs
also wants more data points before we trust the recheck phase
unconditionally.

---

## M6p Stage 2 — LLM SBOM augmentation pass (2026-05-10)

**What shipped:**

- **Prisma migration `m6p_llm_sbom_augmentation`**: three new `Repo` fields
  (`firstPartyNamespaces`, `vendoredDirs`, `llmSbomEffort`) and a new
  `SbomComponent.llmEvidence` JSONB column.
- **`llmSbomService.ts`** — new service that mirrors `llmSastService`:
  `runSbomAugmentation` writes the Stage-1-cleaned SBOM to a tmp file, spawns
  `claude -p`, parses JSON-Lines keep/drop/add records. `applySbomAugmentation`
  applies the records to the in-memory CdxComponent list and returns a final list
  + evidence map.
- **`sbomService.ts` extensions**: `extractCleanedComponents` (Stage-1 without
  persisting) and `persistAugmentedComponents` (persist pre-augmented list with
  evidence). The old `persistComponents` is still available for code paths that
  don't need augmentation.
- **New prompts** `sbom_system.md` + `sbom_augmentation.md`: role + ground rules
  (conservative keep-bias, first-party + test-only exclusion criteria), task
  steps (review SBOM → inspect vendored dirs → check csproj toolset refs →
  verify singletons).
- **Worker phase `llm_sbom`** wired between cdxgen and OSV. On failure, emits
  `llm_sbom_augmentation_failed` error warning and falls back to Stage-1 output
  — scan still completes.
- **Admin form** (ReposPage): new `firstPartyNamespaces`, `vendoredDirs`, and
  `llmSbomEffort` fields. Arrays entered as comma-separated text.
- **Components tab tooltip**: info icon on rows with `llm_evidence`; hover shows
  LLM rationale + evidence path + excerpt. Uses existing `FileLink` component.
- **Frontend types updated**: `Repo`, `RepoUpsertInput`, `SbomComponent` + new
  `LlmEvidence` interface; `ScanPhase` union + `SCAN_PHASE_LABELS/UNITS/CAPS`
  updated with `llm_sbom`.
- All 50 backend tests still passing. TypeScript strict mode clean on both sides.
- Gocator Classic `firstPartyNamespaces` pre-set to `{GoSdkNet,kApiNet,GoAccelerator,LMI}` via psql for the first live verification scan.

**What we learned:**

- **cdxgen SBOM file as LLM input, not prompt text.** Writing the SBOM to a tmp
  file and telling the LLM to `Read` it keeps the prompt short and avoids
  token-per-component overhead. The prompt body stays fixed cost regardless of
  how many components there are.
- **Conservative keep-bias matters more than recall.** The prompt instructs the
  LLM to only drop when confident (first-party prefix match, confirmed test-only,
  or obvious BCL assembly). A missed drop is auditable; a spurious drop silently
  removes a real dep from CVE monitoring.
- **Evidence for adds is non-negotiable.** Every `add` record requires an
  `evidence_path` in the protocol. This gates the LLM's creative speculation —
  it can't add MSVC Runtime unless it found a concrete `<PlatformToolset>`
  reference in a file it read.
- **Failure graceful by design.** The augmentation wraps in try/catch and falls
  back to Stage-1 on any error. The scan completes; the operator sees the warning
  and can investigate. This was the right call — the SBOM augmentation pass is
  value-add, not load-bearing for the scan record.
- **Open question for next time:** The first live scan will tell us whether the
  prompt's Step 2 (vendored dirs) and Step 3 (csproj toolset detection) produce
  the expected MSVC Runtime / gettext / IpToCountry adds. The prompt may need
  iteration based on actual model output — watch the `llm_sbom_parse_errors`
  warning count and the keeps/drops/adds log line after the first scan.

---

## M6q — Components tab UX & data richness (2026-05-11)

### What shipped

- **Phase 1.1 — cdxgen invocation fix.** `runCdxgen` now passes `cwd: workingDir`
  so paths in `evidence.identity.methods[].value` and `properties.SrcFile` come
  out repo-relative instead of `../clones/<uuid>/...`. Also added `--evidence`
  flag explicitly so `evidence.occurrences[]` is a guaranteed contract rather
  than an accident of project-type defaults.

- **Phase 1.2 — Prisma migration.** `sbom_components.occurrences` JSONB column
  (default `[]`). Shape: `{path: string, line: number | null}[]`.

- **Phase 1.3 — Occurrence extraction.** `extractOccurrences()` in the new
  `sbomOccurrences.ts` service: gold source is `evidence.occurrences[].location`
  (repo-relative, has line numbers); fallback to `evidence.identity[].methods[].value`;
  `properties[].SrcFile` always skipped (redundant). LLM-augmented components
  also get `llm_evidence.path` as a guaranteed first occurrence. Wired into
  `persistComponents` and `persistAugmentedComponents`.

- **Phase 1.4 — Worker backfill.** `backfillSbomOccurrences` boot hook fills
  rows with `occurrences = []` from stored `sbom_json` (with one-time clone-prefix
  strip for pre-M6q rows). First run filled 25,705 historical component rows.

- **Phase 1.5 — Tests.** 10 unit tests in `sbomOccurrences.test.ts` covering
  path#line parsing, identity fallback, clone-prefix stripping, LLM-augmentation
  entry, SrcFile skip, deduplication.

- **Phase 2 — Endpoints.** `SbomComponentOutSchema` extended with `occurrences[]`,
  `manifest_file`, `discovery_method`. `GET /scans/:id/components` uses the shared
  schema (no `linked_issue_ids`). `GET /api/scopes/:id/components` adds `linked_issue_ids`
  `{sca, sast}` derived in a single batch query (no N+1). New `GET /api/scopes/:id/sbom-json`
  endpoint: downloads SBOM JSON for the scope's `lastScanRunId` with correct
  `Content-Disposition` header.

- **Phase 3 — `prettyEcosystem()` helper** in `frontend/src/lib/componentLabels.ts`.
  Keys on `discovery_method='llm_augmentation'` rather than `ecosystem='generic'`
  to be forward-compatible with any future non-LLM generic rows.

- **Phase 4 — Expandable component rows.** Both `ScopeDetailPage` and
  `ScanDetailPage` `ComponentsTab` now have expandable rows showing: License
  details (all entries), Found in (occurrences as FileLinks, truncated to 15 with
  "and N more" disclosure), LLM augmentation evidence panel. Scope-page rows
  additionally show linked SCA issues with severity and clickable cross-tab
  navigation. Vendored badge (violet) replaces "GENERIC" for LLM-augmented rows.
  New License column (first license + "+N more" suffix).

- **Phase 5 — URL-driven tab and row state.** `App.tsx` adds nested routes for
  `/scopes/:id/{sca,sast,components}/:rowId`. `ScopeDetailPage` reads active tab
  and expanded row from `useMatch()` instead of local state; `Tabs.onValueChange`
  navigates to the tab URL. Backward-compatible with legacy `?issue=` search param.

- **Phase 6 — Scope SBOM download button.** "SBOM" button in scope page header
  (next to Scan now); disabled when `lastScanRunId` is null; hits `GET /api/scopes/:id/sbom-json`.

### What we learned

- **Worker and backend must be restarted after bind-mount edits.** `tsx` is not
  in watch mode in compose — it reads source once at startup. Worker was up for
  16 hours when M6q landed; the new cdxgen CWD argument only took effect after
  `docker compose restart worker`. The CLAUDE.md claim that "edits are picked up
  live" is aspirational for tsx watch mode but not true for the standard `tsx src/worker.ts` command.

- **`evidence.occurrences[]` is already repo-relative even before the CWD fix.**
  cdxgen computes occurrences relative to the project root regardless of the
  process CWD. The CWD fix only affects `evidence.identity.methods[].value` and
  `properties.SrcFile`. This means the occurrence data was already clean in older
  scans; the backfill captured it correctly from stored `sbom_json`.

- **Phase 1.1 scan verification pending VPN reconnect.** The Gocator Classic
  clone requires VPN to `git.example.com`. Two scan attempts during implementation
  failed with `RemoteUnreachableError`. The identity-path format change (from
  `../clones/<uuid>/...` to repo-relative) can only be confirmed by a fresh scan
  that runs cdxgen. The occurrence data is already correct in all scans (see above).

- **`linked_issue_ids.sast` is always empty today.** SAST issues don't have a
  per-component foreign key in the data model. The field is wired in and returns
  `[]` for all components pending a future data-model change to track SAST-to-component
  links explicitly. This is correct per plan §2.

## M6q review round — UI & data fixes (2026-05-11/12)

A series of manual-review iterations on the M6q changes once they landed in
the browser. Each item shipped as its own commit; this is a roll-up.

### What shipped

- **`3a440a8` — drop `--evidence` flag.** Initial Phase 1.1 added an explicit
  `--evidence` flag to cdxgen for "guaranteed contract." Empirically it broke
  cdxgen 12.2.1 on this codebase (exit 0, no output file). Evidence section is
  emitted anyway for npm/nuget/.csproj/.vcxproj — the flag was unnecessary AND
  harmful. cwd+`.` part of Phase 1.1 still applies.
- **`d70cc18` — review bundle (items 1-9).** GoWeb scope occurrences missing
  the `GoWeb/` prefix (extractOccurrences now takes a scopePath and applies
  `toRepoRelative`); clicking a linked-CVE badge didn't expand the SCA row
  (useEffect now sets local expanded state, not just scrolls); scroll-to was
  smooth (now instant — tab change is already a hard transition);
  route-targeted row gets a `bg-primary/5 ring-1` highlight + subsequent
  interactions (any row click, filter toggle, severity/status change) clear
  the URL row segment via a `clearRowTarget` callback; ScopeComponentRow
  converted from URL-driven (single-expand) to local useState so multiple
  rows can stay open; `/scopes/:id/sbom` route + ScopeSbomViewerPage; new
  View SBOM button next to Download SBOM on scope header; Components
  `<Table className="table-fixed">` with `w-64` Issues column so expanded
  rows can't widen the table; linked-issues row uses w-16 severity +
  w-56 id + flex-1 summary so the long DEPRECATED-npm-X id doesn't wrap;
  `prettyEcosystem()` returns plain strings with proper casing (`Maven`,
  `NuGet`, `npm`, `PyPI`, `RubyGems`); "Vendored" renders as plain text
  to match other variants.
- **`442154d` — license casing.** `prettyLicense()` preserves SPDX IDs
  (`MIT`, `Apache-2.0`, `BSD-3-Clause`, `LGPL`, ≤4-char all-caps) and
  title-cases bare-word labels (`CUSTOM`, `UNKNOWN`, `PROPRIETARY`).
- **`d051583` — manifest paths missing subdirectory.** `normalizeManifestPath`
  was written for "always absolute or clone-prefixed" cdxgen output. The M6q
  cwd fix made cdxgen emit scope-relative paths; every relative path fell
  through to the basename fallback, then `toRepoRelative` tacked the scope
  prefix on, yielding bogus paths like `GoWeb/package-lock.json` pointing
  at a file that doesn't exist (real lockfile at
  `GoWeb/EmulatorUI/package-lock.json` etc.). Added a "trust relative paths
  verbatim" branch + a new `backfillSbomManifestFiles` worker-boot hook that
  walked every scan_run's stored sbom_json and rewrote `sbom_components.manifest_file`
  (repaired 27,615 component rows + 146 SCA issues).
- **`b0261bd` — chain-link copies path-based URL.** The chain icon at the end
  of SCA/SAST row summaries was still copying the legacy `?issue=<id>` form.
  Now copies the path-based form (`/scopes/:id/{sca,sast}/:issueId`). Full
  audit of every internal Link/navigate covered; everything else was already
  on the path-based form.
- **`35fad98` — manifest line numbers for transitive deps.** cdxgen attaches
  `evidence.occurrences[]` with line numbers only when a component is directly
  `require()`/`import`-ed; transitive lockfile-only deps fell back to identity
  (path only, no line). New `resolveManifestLines()` greps each manifest-shaped
  occurrence for the package name (same patterns as `readManifestSnippet`),
  cached per lockfile. /GoWeb now sits at 4,988/4,996 line-numbered occurrences
  (99.84%; the 8 outliers are LLM-augmented evidence paths or non-manifest
  files where grep won't help).
- **`68f2048` — cdxgen jar-deps phantom paths.** When cdxgen extracts a Maven
  coord from a packed jar, identity is just the bare jar basename
  ("compiler.jar") — no path. The chain produced "GoWeb/compiler.jar" pointing
  at a file that doesn't exist. New `ScopeFileIndex` lazily walks the scope
  dir (skipping `node_modules`/`.git`/`build`/`dist`/etc.) and resolves a
  basename to its repo-rooted path when exactly one match exists. Also fixed
  `backfillManifestOrigin` keying — it had been reading from sbom_json with
  `c.name` ("protobuf-java") but `sca_issues.package_name` uses canonical
  "com.google.protobuf:protobuf-java" so maven rows never matched the
  lookup. Rewrote to read from sbom_components (already canonical, already
  path-fixed by the previous backfill). Worker boot now chains
  `backfillSbomManifestFiles → backfillManifestOrigin` so SCA paths inherit
  the corrected component paths.
- **`d2ea049` / `c5f4085` — distinguish co-package CVEs.** A single npm
  package can carry multiple distinct CVEs against the same version (e.g.
  is-svg@2.1.0 → CVE-2021-28092 + CVE-2021-29059, both ReDoS). The collapsed
  SCA row only showed severity + summary + package@version + status, so two
  rows for the same package@version looked indistinguishable. Now the
  summary cell is two stacked rows: summary on top (truncated with a
  title= tooltip carrying the full text), CVE/OSV id on the second line
  mono+muted as an identifier badge. Detail panel surfaces the full OSV
  summary verbatim followed by the LLM summary when different. Applied
  consistently on the scan-page Findings tab.

### What we learned

- **The "no path normalisation" cleanup needs every consumer updated together.**
  The Phase 1.1 cdxgen-cwd fix produced cleaner cdxgen output, but each
  downstream consumer (`normalizeManifestPath`, the manifest-snippet read,
  `backfillManifestOrigin`'s sbom_json re-parse) had been written for the
  old shape. Each became its own bug to discover by inspection during the
  UI shake-out. A pre-fix audit of every consumer would have been faster.
- **cdxgen's `evidence` shape is heterogeneous.** Direct-import deps get
  `evidence.occurrences[]` with line numbers; lockfile-only transitive deps
  get only `evidence.identity[].methods[].value`; jar-extracted Maven coords
  get just a bare jar basename. Single-display-shape requires post-extraction
  enrichment (grep lockfile for line, scope-walk for basename) — there's no
  cdxgen flag that produces a uniform "where is this used" record.
- **Same canonical name on both sides of the join.** `backfillManifestOrigin`
  silently dropped maven SCA rows for months because it keyed by cdxgen's
  raw `c.name` ("protobuf-java") while `sca_issues.package_name` is canonical
  ("com.google.protobuf:protobuf-java"). Always join against the table that
  already has the canonical form, not the raw SBOM JSON, to inherit the
  canonicalisation work that's already been done.
- **A backfill that silently no-ops on unchanged rows is the right design.**
  Both `backfillSbomManifestFiles` and `backfillSbomOccurrences` re-process
  every eligible row on every worker boot but only write when the value
  actually differs. Each new fix in this round (jar-deps, manifest lines,
  scope prefixing) added more cases the existing backfills picked up
  without filter changes. Worker restart became the canonical "apply
  fixes to historical data" gesture.

### Addendum — onboarding-a-new-repo failures (2026-05-12)

While intaking the FSS repo (`https://git.example.com/scm/internal/repo.git`) we
hit three "no helpful message in the GUI" failure modes and a confusing
SBOM mismatch. All shipped as their own commits.

- **`14554ff` — pre-flight + typed warnings for scan-config errors.** Two
  real failure modes had been producing `status=failed` with `warnings=[]`,
  leaving the UI silent: (a) **scope path doesn't exist in the clone** —
  FSS had `scan_paths=["/FSS"]` but the cloned tree has the code at the
  root (no `FSS/` subdir). The worker passed the missing dir as `cwd` to
  cdxgen and Claude; Node's spawn returns `ENOENT` on a missing cwd and
  blames the executable, producing the misleading "spawn cdxgen ENOENT"
  / "spawn claude ENOENT" logs. Now a pre-flight stats the scope dir
  right after clone and emits a typed `scope_path_missing` error
  warning with concrete fix instructions. (b) **clone failures** (remote
  unreachable, branch not found, auth failed, generic clone error) were
  caught and written to `scan_runs.error` (free-text) but never converted
  into typed `warnings`. Now mapped to `remote_unreachable`,
  `branch_not_found`, `auth_failed`, `clone_failed` with operator-facing
  messages.
- **`6bf7142` → `f76bf9a` → `ff4a35d` — split scan-vs-scope SBOM
  surfaces.** Both viewers were serving `scan_runs.sbom_json` (raw cdxgen
  output). On FSS that meant 65 entries — mostly CMake `find_package()`
  probes from inside Eigen's CMakeLists.txt and `evidence.identity`
  values formatted as `"Filename /app/clones/<uuid>/.../CMakeLists.txt"`
  (cdxgen's CMake parser emits absolute paths regardless of process
  CWD). The Components tab correctly showed the post-Stage-2 21 entries,
  so the SBOM viewer felt broken. New split:
    - `GET /scans/:id/sbom` → raw cdxgen output (audit trail of what
      this run produced). Filename prefix `sbom-raw-…`. Viewer
      subtitle: "cdxgen output · pre-curation".
    - `GET /api/scopes/:id/sbom-json` → curated CycloneDX 1.7 doc
      built from `sbom_components` rows. Matches the Components tab.
      This is the file the operator ships for CRA compliance.
  `buildCuratedSbomJson(scanRunId)` in `services/sbomCurated.ts` is
  the builder. Includes purl, version, licenses, evidence.identity
  (manifest_file), evidence.occurrences (path#line), and
  `sastbot:discovery_method` / `sastbot:llm_rationale` properties.

### What we learned (round 2)

- **`spawn ENOENT` lies about which thing was missing.** When a
  child-process call fails with ENOENT, Node reports the executable
  path. The actual cause is often a missing `cwd`. Pre-flight stats
  on every external resource (scope dir, manifest paths, prompt
  files) catch this class of misattributed failure cheaply.
- **Audit trail ≠ ship artifact.** The scan-level SBOM is internal
  forensics; the scope-level SBOM is what an auditor or customer
  receives. Serving the same JSON from both surfaces conflated those
  purposes. The split now matches the rest of the model:
    - **Scan page** = "what this run did" (audit, raw, per-execution)
    - **Scope page** = "current state, ready to act on" (curated,
      cross-scan, the operator's truth)
- **Set `firstPartyNamespaces` per repo.** FSS's first run dropped
  61 of 62 cleaned cdxgen components via LLM inspection alone (the
  `k*` directories at the repo root are all LMI internal). Setting
  `firstPartyNamespaces = ["k"]` on the repo lets the SBOM
  augmentation short-circuit these without LLM inspection — cheaper,
  more deterministic. Worth doing for every LMI repo on onboarding.
- **OSV's generic-ecosystem coverage is essentially zero.** FSS's
  21 curated components are mostly vendored C/C++ (libgit2, zlib,
  freetype, eigen, …) emitted with `pkg:generic/...` purls. OSV
  returned zero findings even though several have known CVEs
  (libgit2 0.26 from 2018, zlib 1.2.6 from 2012). This is a
  cross-repo gap, not an FSS-specific bug — any C/C++ project will
  see the same hole. Workarounds (CPE/NVD direct query, GHSA via
  GitHub, curated short list of high-profile C/C++ packages) are
  candidate work for a future milestone.


## M7 — deterministic component dedup, scope_components as durable truth, evidence with line numbers (2026-05-15)

Component-identity refactor closing a long tail of dup bugs and giving
operators direct edit/delete control over the scope inventory. Single
all-day session; committed as `c5005f8`.

### What shipped

**Identity & dedup**

- **`componentMatch.ts` — 7-tier deterministic chain.** Each tier is a
  progressively-tolerant identity predicate: (1) component_root exact
  equality, (2) component_root prefix containment, (3) CPE exact, (4) CPE
  vendor+product (version-agnostic), (5) PURL exact, (6) normalized name
  + version (lowercase + strip `[-_\s]` + drop `lib` prefix — tolerates
  LLM naming drift across scans), (7) manifest_file + name. First match
  wins. Used in both `applySbomAugmentation` (intra-scan dedup against
  cdxgen survivors AND prior LLM adds) and
  `persistScanComponentsToScopeState` (vs DB).
- **`component_root` field** — the shallowest repo-relative directory
  exclusively owned by an upstream library (e.g. `extern/Xenomai`, or
  `extern/Nerian/libnvshared` when sibling libs share a parent). LLM
  emits it on every `add` record. Stable across scans even when the LLM
  picks different specific evidence files for the same library.
- **`evidence` jsonb of `{path, line?}`** replaces the flat `evidence_paths`
  text[]. Line numbers were always available on `sbom_components.occurrences`
  but discarded by the M7 string-array shape. Restoring them makes lockfile
  links (`package-lock.json:1234`) clickable through to the exact line via
  the existing `$LINE` URL template.

**Operator UX**

- **Trashcan delete** on each row in the Components tab.
  `DELETE /api/scopes/:id/components/:componentId` hard-deletes; the next
  scan re-emits real components and the match chain collapses them.
  Confirm dialog kept to one short line ("The next scan may re-add it if
  it's found in the repo.") — no jargon.
- **Inline edit** (pencil icon in the Evidence section header).
  `PATCH /api/scopes/:id/components/:componentId` accepts name,
  component_root, evidence (textarea where each line is a path with an
  optional `:N` suffix → parsed into `{path, line}`). Marks the row
  `source='manual_override'` so future scans don't overwrite curated values.
  Rename collisions surface as 400 with a useful message.
- **Component detail panel** reordered: Evidence section now sits at the
  top above LLM augmentation.

**Data flow correctness**

- **Scope page Components tab now reads `scope_components`, not
  `sbom_components`.** This was the missing piece of the M7 architecture
  — the table that the trashcan delete + LLM merge + inline edit all
  mutate is now the table the UI displays. Manual edits propagate
  immediately; deleted rows actually disappear from the list. The
  scan-detail page (`/scans/:id`) is unchanged — it still reads its own
  `sbom_components` for per-scan audit. **Invariant:** data flows scan →
  scope, never the reverse.
- **"Found in" section dropped** from the Components panel; the Evidence
  section is the single source of file-location display on the scope
  page. Existing `occurrences` data was lifted into
  `scope_components.evidence` by migration 20260515123000.
- **Removed `backfillScopeComponentsFromLatestScans` entirely** (was a
  worker boot hook). Its legacy ON CONFLICT clause silently duplicated
  version-NULL rows on every restart because of Postgres NULL-distinct
  semantics. The in-flight scan flow now bootstraps `scope_components`
  natively via componentMatch — the boot backfill was dead-on-arrival.

**Augmentation prompt / Zod schema hardening**

- **`version`-Zod-transform on `AddRecord`**: coerces sentinel strings
  (`"unknown"`, `"*"`, `""`) to null at parse time, so the synthesized
  purl is canonical (`pkg:generic/yaffs2`, not `pkg:generic/yaffs2@unknown`).
  Catches a class of LLM-output drift at the boundary instead of letting
  it create twin rows in the DB.
- **SAST detection prompt examples compacted** to single-line JSON.
  The prior version had pretty-printed examples that the LLM occasionally
  copied verbatim — those mid-stream newlines defeated the JSONL parser.
  Detection parse-error rate on FSS dropped from 5 → 2 in the next scan.
- **Parse-error samples logged at info level** from detection + recheck,
  giving us actual visibility next time something parses oddly.

**Migrations applied this session**

| Migration | Purpose |
|---|---|
| `20260515090000_dedup_sbom_components_by_purl` | re-pointed scan_findings, deleted dups, added unique index `(scan_run_id, purl)` |
| `20260515093000_normalize_unknown_versions` | merged `version="unknown"` siblings; normalized solos to NULL with stripped purl |
| `20260515103000_add_component_root_and_evidence_paths` | new columns + backfill from `evidence_path` parent dir |
| `20260515113000_cleanup_existing_scope_component_dups` | merged scope_components by (normalized_name, version) — collapsed Boost×2, OpenGL×2, Nerian variants |
| `20260515123000_backfill_evidence_paths_from_occurrences` | lifted per-scan `occurrences` paths into scope-level `evidence_paths` |
| `20260515133000_evidence_to_jsonb` | `evidence_paths text[]` → `evidence jsonb` (array of `{path, line?}`) on both tables |

### What we learned

- **The rebuild bug that started the day** was `rebuildComponentsFromScopeState`
  using `INSERT … ON CONFLICT DO NOTHING` with no unique index to drive the
  conflict resolution — every merge-followed-by-rebuild silently doubled
  the per-scan row count. Adding the partial unique index on
  `sbom_components(scan_run_id, purl)` made the existing clause finally do
  what it claimed to do. **Lesson:** never assume `ON CONFLICT DO NOTHING`
  is meaningful without a matching unique constraint.
- **Postgres NULL-distinct semantics keep biting**. The
  `(scope_id, name, version, purl)` unique constraint allows two
  `(…, NULL, …)` rows to coexist because NULL ≠ NULL — that's how the
  duplicate Boost / OpenGL rows survived every prior dedup pass and how
  the boot backfill silently re-injected them on each worker restart.
  **Lesson:** when version is nullable, the unique key must either
  treat NULL as distinct deliberately (and have a second index that
  handles NULL-version cases) or be paired with `NULLS NOT DISTINCT`
  (PG 15+).
- **Two-tables-for-one-thing is a footgun.** `sbom_components` (per-scan
  audit) and `scope_components` (durable state) are conceptually
  different and the user-facing UI was reading from the wrong one. The
  fix wasn't to collapse them (that would violate scan-page audit
  semantics) but to make each surface read from the table that matches
  its semantic role.
- **"Shallowest unique path" is the right identity primitive for vendored
  libs**, not "deepest" or "the specific file." The LLM picks different
  evidence files for the same lib across scans (`extern/Xenomai/include/xeno_config.h`
  one run, `extern/Xenomai/README` the next); the shared root
  `extern/Xenomai` is stable. The 8-step match chain falls back to
  CPE / normalized name when the root is missing or shared with sibling
  sub-libs.
- **Backfills accumulate sins**. Every time we add a column and write a
  "safe to re-run on boot" backfill, we accumulate a ticking-bug-future
  every time we change semantics. The boot backfill removed today was
  innocent at write-time and quietly destructive a few schema migrations
  later. Better to bootstrap from the live scan flow when possible.

### Known follow-ups (next session)

- **Bugs on the Gocator Classic `/GoWeb` scope's Components tab** —
  scope has 2436 active rows (npm-heavy), behaviour there hasn't been
  verified after today's switch from sbom_components → scope_components.
  Expect issues around pagination, occurrences→evidence lifting, and
  LLM-rename collisions on common npm packages.
- **`/scans/:id` Components tab isn't loading correctly anymore.** Not
  investigated this session — likely a downstream effect of the data-flow
  refactor.
- **Manual ADD component** (companion to manual delete) — operator-driven
  insertion of a scope_component the LLM missed, with on-save OSV+NVD
  lookup. Captured in `project_pending_features.md`.

## Production readiness — six-stream sprint (2026-05-16)

Plan: `docs/PROD_READINESS_PLAN.md`. Six work items sequenced as one
foundation stream + three waves. Multi-agent execution: main agent
supervised, Sonnet sub-agents implemented each stream. One focused
commit per stream.

### What shipped

- **Stream 0 — Layered runtime config (`e2dd0f8`).** `backend/src/config.ts`
  is now a three-source loader: env vars (lowest precedence) → YAML
  config file → CLI args (highest). YAML location resolves via
  `SASTBOT_CONFIG_FILE` → `/etc/sastbot/config.yaml` → repo-local
  `backend/config.local.yaml`. All three normalize to one canonical
  `SCREAMING_SNAKE_CASE` key before the existing Zod schema validates,
  so every downstream `config.MASTER_KEY` / `config.DATABASE_URL`
  import keeps working unchanged. CLI parsed via Node built-in
  `node:util`'s `parseArgs`. Added `yaml` dep. New `docs/user/`
  scaffold (`README.md` index + `configuration.md` reference) and
  README pointer.

- **Stream A — Auth hardening + dev-escape-hatch (`44a37d6`).**
  `@fastify/rate-limit` (Redis-backed, `skipOnError: true`) on
  `/auth/login` and `/auth/logout`: 10 attempts per 60 s per IP, both
  thresholds tunable via `AUTH_RATE_LIMIT_MAX` /
  `AUTH_RATE_LIMIT_WINDOW_MS`. `BOOTSTRAP_ADMIN_PASSWORD` is no longer
  silently honoured in prod — when `NODE_ENV=production` and the env
  is set, the config loader throws a `ConfigError` and the backend
  refuses to boot. Frontend login form parses `retryAfter` from the
  429 JSON body and runs a per-second countdown on the disabled
  Submit button.

- **Stream F — Admin DB backup (`4c4bc97`).** `GET /admin/db/backup`
  streams a `pg_dump --format=custom --compress=9` of the live
  database into the HTTP response via `reply.hijack()` (bypasses the
  Zod serializer; no in-memory buffering). DB password passed only
  via `PGPASSWORD` env, never argv — `pg_dump` is never logged with
  credentials. `postgresql-client-16` installed from the PostgreSQL
  APT repo in `docker/backend.Dockerfile` (matching the Postgres 16
  server pinned in compose). "Download backup" card on the admin
  Settings page.

- **Stream B — Pagination + worker concurrency (`40b657d`).**
  `/scans`, `/admin/repos`, `/admin/credentials` now return
  `{items, total, page, page_size}` (clean break — frontend hooks
  updated in the same commit). Defaults: 50/200 max for `/scans`,
  100/500 for the two admin routes. New `SCAN_WORKER_CONCURRENCY`
  env (default 2, max 4) drives BullMQ's `Worker({concurrency})`.
  Frontend list pages reuse the `Pager` pattern landed for SCA/SAST
  tables in `03ac821`.

- **Stream D — Per-repo LLM token budgets (`5901457`).** Four
  nullable Int columns on `Repo`: `llmSbomTokenBudget`,
  `llmSbomRecheckTokenBudget`, `llmSastTokenBudget`,
  `llmRecheckTokenBudget`. NULL → fall back to the worker's
  hardcoded defaults (200k / 50k / 300k / 50k respectively).
  Migration `20260516165953_add_per_repo_llm_token_budgets`. Repo
  edit dialog grows a pre-collapsed "Token budgets" section with
  four number inputs (empty → NULL → default). Worker live-progress
  label simplified — phase prefix flows from the existing
  `SCAN_PHASE_LABELS` table; redundant per-call label strings
  removed.

- **Stream E — `parseErrors` raw on scan warnings (`c03504d`).**
  `ScanWarningSchema` gains optional `details: z.unknown()`. Worker
  passes `detection.parseErrors.slice(0, 5)` (and recheck +
  augmentation equivalents) into `details`, with each `raw` capped
  at 2 KB by `truncateParseErrors` — UTF-8-safe (uses `TextDecoder`
  to avoid splitting multi-byte chars). Frontend `ScanDetailPage`
  renders a native `<details>` per warning when `details` is a
  well-typed `{raw, reason}[]`; warnings without `details` are
  unchanged. 7 new unit tests cover the truncation helper.

- **Stream C — Scan resilience (`c39fb47`).** Three layers:
  - **Wall-clock cap** on `claude -p`. Defaults 60 min detection /
    30 min recheck (`CLAUDE_DETECTION_TIMEOUT_MS`,
    `CLAUDE_RECHECK_TIMEOUT_MS`). On timeout: SIGTERM → 5 s grace →
    SIGKILL. Sets `killedReason="timeout"`.
  - **Stdout staleness heartbeat**. Default 5 min
    (`CLAUDE_STDOUT_STALENESS_MS`); resets on every stdout chunk.
    Same kill ladder. Sets `killedReason="staleness"`.
  - **Retry once** on `exitCode != 0 && records.length === 0`,
    fresh tmpdir, **full token budget**. No retry if the subprocess
    was killed by a watchdog (timeout / staleness) — those exits
    aren't candidates. Retry emits an `info`-severity warning
    documenting doubled spend. 0-record clean exit emits an
    `error`-severity `sast_detection_failed` warning so the
    existing `hasErrorWarnings` gate marks the scan degraded
    instead of "success".
  
  11 new tests on mocked spawn + fake timers cover all four paths.
  BullMQ lock-extension errors on laptop sleep: investigated, no
  fix needed — BullMQ's built-in lock renewal + stalled-job recovery
  handle this and the worker's job-entry idempotency clears any
  stale state on re-queue.

### What we learned

- **Foundation streams pay for themselves.** Wiring the three-source
  config loader before Wave 1 meant Streams A/B/C each added their
  knobs (rate-limit thresholds, `SCAN_WORKER_CONCURRENCY`, claude
  watchdog timeouts) as one-line Zod additions — no per-stream
  re-litigation of "where does the env var live, what's the YAML
  shape, how do we test it?" The cost was a single extra commit
  before Wave 1; the saving was three streams that didn't have to
  decide.

- **Parallel sub-agents on disjoint files lands cleanly when the
  seams are named upfront.** Each Wave-2 prompt explicitly listed
  off-limits files for the other parallel streams. Zero conflicts
  in three parallel commits touching `worker.ts`, `schemas.ts`,
  `config.ts`, and `docs/user/configuration.md`. The one near-miss
  — Stream B observing tsc errors in Stream D's in-flight Repo Zod
  changes — resolved itself once Stream D's commit landed.

- **`reply.hijack()` is the right escape hatch for streaming large
  binary bodies from Fastify.** Fastify's typed routes assume
  serialized JSON. For `pg_dump` (binary, potentially gigabytes,
  streamed), hijack-and-pipe to the raw HTTP response is
  cleaner than trying to satisfy `octet-stream` content-types
  through the type-provider plumbing.

- **The 6 h 37 m hung `/GoWeb` detection has a name now.** The
  staleness heartbeat would have caught it inside 5 minutes
  instead of waiting for a token budget that wasn't going to fire.
  Wall-clock cap is the second backstop, retry is the third. The
  natural stop signal is still the token budget — these are nets,
  not steering wheels.

- **`pg_dump` major-version pinning is non-optional.** Debian's
  default `postgresql-client` package typically lags the server by
  a major. Installing `postgresql-client-16` from the PostgreSQL
  APT repo means the dump format matches the running Postgres 16
  server. Add to the Dockerfile boilerplate when bumping the DB
  major.

- **Always pass watchdog kill state into the retry decision.**
  Without `killedReason`, a timeout-induced exit-1 looks identical
  to a legitimate LLM crash and would trigger another full-budget
  attempt — exactly the wrong response to a stuck subprocess.
  The retry path checks `killedReason == null` before re-spawning.

### Known follow-ups (next session)

- **Browser smoke-test on the rebuilt image.** Streams A, F, B, D
  all touched UI surfaces; the running containers cache prior
  builds. A fresh `docker compose up --build` is needed to verify
  the rate-limit countdown, download-backup button, three new
  pagers, and the token-budgets dialog end-to-end.

- **`pg_dump` route timing on a non-trivial DB.** Verified clean
  on an empty DB (the route returns 500 cleanly when the binary is
  missing pre-rebuild). The Fastify request timeout and any proxy
  layer should be re-checked once the homelab Postgres has more
  data — pg_dump on multi-GB DBs can take minutes.

- **`/admin/repos` paginates in memory.** Stream B sliced after
  `listRepos()` loads all rows — fine at current admin scale,
  needs a DB-level skip/take if repo counts grow.

## First trial deploy to homelab Dokploy (2026-05-19)

End-to-end deployment of SASTBot onto the homelab Dokploy node as a
dress rehearsal for the eventual company LMI Dokploy deploy. The plan
was four pre-flight commits, push, hand off to Dokploy. Reality: four
in-flight debug cycles surfaced bugs that only the Dokploy build farm
exposed. Each cycle: read the build/runtime log, hypothesise, patch,
push, redeploy. The final stack came up green and the pre-deploy DB
backup restored cleanly via the in-app `/admin/db/restore` endpoint.

### What shipped — pre-flight (before first deploy attempt)

- **trustProxy scoped to two hops (`6af2657`).** Fastify's
  `trustProxy: true` trusted any `X-Forwarded-For`, allowing a client
  to spoof its source IP through the chain. Scoped to `2` (Traefik on
  the edge + the per-stack nginx-frontend that fronts the SPA) so the
  backend sees the real client IP without being spoofable. Bumped to
  `0.1.1`.

- **All domain routes mount under `/api/*` (`0e51e4c`).** Previously
  routes lived at bare paths (`/auth/login`, `/admin/repos`, …). The
  prod nginx config needs a clean `location /api/` block to forward
  everything to backend without enumerating each prefix. Server-side
  refactor: parent register adds the `/api` prefix to the whole
  bundle; route files keep their bare-path declarations. Frontend's
  `apiFetch` was updated to normalise either form so call sites
  didn't all need touching at once. Bumped to `0.2.0`.

- **Production compose stack + nginx config (`06a23ce`).**
  `docker/compose/docker-compose.prod.yml` (no bind mounts, env from
  Dokploy editor, `target: prod` build stage, healthchecks chained
  via `depends_on.condition: service_healthy`) plus
  `docker/nginx.prod.conf` (the frontend container's nginx, fronting
  the SPA + reverse-proxying `/api/*` and the four root-level
  operator endpoints to `backend:8000`).

- **Dropped frontend host port publish (`e952560`).** Original draft
  published `80:80` on the frontend container. Dokploy fronts every
  stack with Traefik, so publishing the host port both collides with
  the Dokploy proxy and bypasses its routing. Removed the `ports:`
  block; Traefik reaches the container by service name + port on the
  shared compose network.

### What shipped — in-flight (after each Dokploy deploy attempt)

- **Bookworm-slim + lockfile-less frontend build (`866bea3`).**
  Build attempt 1 died with `Cannot find module
  @rollup/rollup-linux-x64-musl` during `vite build`. Root cause:
  `npm ci` against a macOS-generated `package-lock.json` doesn't
  install Rollup's per-platform native binding for Linux (npm bug
  4828). Fix: switch the build stage base from `node:20-alpine` to
  `node:20-bookworm-slim` (glibc, prebuilt Rollup native) AND copy
  only `package.json` so `npm install` resolves optional deps fresh
  for the build platform. Image is ~100 MB larger but only at the
  build stage; the final layer is still `nginx:alpine`.

- **Pinned pnpm to 10.33.4 (`9031c0c`).** Build attempt 2 died with
  `Error: No such built-in module: node:sqlite` during
  `corepack prepare pnpm@latest --activate`. Root cause: pnpm 11.1.3
  shipped on the registry on 2026-05-18 and dropped Node 20 support
  (requires v22.13+). The backend image runs Node 20. Fix: pin to
  the latest pnpm 10.x (10.33.4) in both build stages of the backend
  Dockerfile. Lockfile is v9, read natively by pnpm 10.

- **Moved `prisma` CLI to dependencies (`2f24252`).** Build attempt 3
  succeeded; the backend container then crash-looped with
  `ERR_PNPM_RECURSIVE_EXEC_FIRST_FAIL  Command "prisma" not found`.
  Root cause: the prod stage runs `pnpm prune --prod` to slim the
  layer, which removed the `prisma` CLI (a devDependency); the
  compose `command:` then tries `pnpm prisma migrate deploy`. Per
  Prisma's prod-deploy guidance, when `migrate deploy` runs at boot
  the CLI must be a regular dependency. Moved it across, regenerated
  the lockfile.

- **Frontend `/api/` prefix on backup + restore call sites
  (`2f123f1`).** After the deploy was green and the smoke tests
  passed, the Settings → Download backup button on local dev had
  always been "downloading" a 714-byte HTML file. Two call sites in
  `SettingsPage.tsx` were missed by the `0e51e4c` refactor because
  they bypass `apiFetch`: the backup anchor (`a.href = "/admin/db/backup"`)
  and the restore POST (`fetch("/admin/db/restore", ...)`).
  `apiFetch`'s path-normalisation didn't help; neither call site uses
  it. In dev, Vite's hand-rolled proxy list only forwards
  `/api`+`/healthz`+`/version`+`/openapi.json`+`/docs`, so
  `/admin/*` falls through to the SPA fallback and the "download" is
  `index.html`. In prod nginx the same path returns 405 / aborts the
  multipart POST → browser fetch rejects with `Failed to fetch`.
  Patched both to use explicit `/api/admin/...`.

### Operator quirks discovered live

- **POSTGRES_PASSWORD with `/` broke Prisma's URL parser.** The
  compose template `postgresql://${USER}:${PASSWORD}@postgres:5432/${DB}`
  percent-encodes nothing. A `/` (or any of `@ : ? # & %`) in the
  password breaks `prisma migrate deploy` with `P1013: invalid port
  number`. Worked around by regenerating the password without `/`.
  Resolution path required wiping the postgres data volume (the
  password is baked into pgdata on first init) — and Dokploy's "Stop"
  doesn't `docker rm`, so the stopped container still holds the
  volume reference and `docker volume rm` refuses. Forced via
  `docker rm -f sastbot-fullstack-elogex-postgres-1`.

- **macOS DNS cache cratered after Dokploy redeploy.** After the
  split-horizon record on UDM started resolving, a redeploy briefly
  tore the stack down and `mDNSResponder` cached a negative answer.
  `dig` still returned the right IP (it queries libresolv directly);
  `curl` and the browser couldn't reach the host until
  `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`
  plus a full browser restart.

### What we learned

- **Local pre-flight only catches what's reproducible locally.** The
  pre-flight on this branch was thorough (rebuilt the dev image,
  smoke-tested the compose stack, took a backup). Every issue that
  surfaced in flight required a build host with different state than
  our laptop: a clean npm cache (Rollup musl), a registry that just
  rev'd pnpm (Node 20 mismatch), a build stage that runs
  `pnpm prune --prod` (CLI strip), and a Dokploy-managed nginx that
  doesn't have the Vite dev fallback (the bare-path frontend bug).
  Three of those four were invisible to any local rebuild. The
  takeaway is structural: a Dokploy-environment build dry-run (or a
  no-cache CI build against a fresh image) is needed in the
  pre-flight loop, not just a "rebuild the dev image" pass.

- **`pnpm prune --prod` is a runtime contract, not a build
  optimisation.** Anything the prod `command:` reaches for must live
  in `dependencies`, not `devDependencies`. The two contracts that
  matter at the boundary are (a) the binaries in `node_modules/.bin/`
  the entrypoint shell scripts call (`prisma`), and (b) the runtime
  modules the compiled `dist/*.js` requires. Audit the compose
  `command:` against the output of `pnpm prune --prod` before
  shipping a new prod image.

- **`pnpm@latest` is a lie at build time.** Corepack resolves
  `latest` against the registry at the moment of `corepack prepare`,
  which by definition drifts. We pinned to a specific 10.x. The
  same trap applies to anything else fetched by tag in a Dockerfile
  — `npm install -g <tool>@latest`, `apt-get install <pkg>` against
  rolling distros. Pin or budget for breakage.

- **Vite dev proxy is opt-in, not catch-all.** Any backend path not
  in `proxied = ["/api", "/healthz", "/version", "/openapi.json",
  "/docs"]` falls through to the SPA's `try_files` and the user gets
  `index.html` back. The CLAUDE.md note about `apiFetch`
  path-normalisation applied only to `apiFetch`; raw `fetch` or
  `<a href>` for binary downloads bypassed it. When refactoring
  route prefixes, grep the frontend for **call sites that bypass
  apiFetch** (`fetch("/`, `a.href = "/`, `window.location =
  "/`), not just `apiFetch` arguments.

- **Cross-version backup/restore round-tripped clean.** Pre-deploy
  dev → post-deploy trial, same app version + schema version,
  metadata.json shape compatible, restore succeeded. The endpoint's
  auto-migration logic was unused (versions matched), but the
  round-trip validated the format. Worth re-validating once we
  hit a real version mismatch (e.g. a schema bump between dev and
  trial).

- **The `unless-stopped` restart policy + Dokploy supervision
  fights you during volume rotation.** Even after Dokploy's "Stop",
  the container record persists and locks the volume. The reliable
  sequence is: Stop in Dokploy UI → `docker rm -f <name>` → `docker
  volume rm <name>` → update env in Dokploy → Deploy. Documenting
  this in the operator runbook before company deploy.

### Known follow-ups (next session)

- **Generic `docs/HOW_TO_DEPLOY_WEB_APP_ON_DOKPLOY.md`.** The
  public-shareable deliverable distilled from this experience. Cover
  the four classes of issue (npm/Rollup, package-manager pinning,
  prune-vs-runtime contract, frontend-call-site sweep on a route
  refactor) plus the operator quirks (URL-safe password chars,
  container-rm-before-volume-rm). Targeted at engineers deploying
  a Node + Postgres + Redis stack to Dokploy for the first time.

- **HTTPS on the trial.** Currently plain HTTP through Traefik.
  Dokploy's Let's Encrypt wizard wants externally-resolvable DNS
  (HTTP-01 challenge), which this homelab record doesn't satisfy
  — split-horizon DNS only. Options: bring an internal CA cert, or
  do DNS-01 with a public-side CNAME, or run HTTPS-terminated
  inside the LAN with a self-signed cert + browser trust. Decide
  before exercising real workflows that use `SESSION_COOKIE_SECURE`.

- **Harden the compose to accept `DATABASE_URL` directly.** The
  template-substitution form is a foot-gun for any password with a
  URL-reserved char. Switching the prod compose to pass
  `DATABASE_URL` through as a single Dokploy env var (with the
  operator responsible for percent-encoding) removes one class of
  bug at the cost of one more env var to manage.

- **Browser exercise the trial UI end-to-end.** Click through
  Repos / Scopes / Settings / scan a small repo. The curl smoke
  tests only covered what curl can do; cookies, large payloads, and
  any SSE / long-poll streams need a real browser.

- **Capture the bootstrap admin password.** The first-boot
  `BOOTSTRAP_ADMIN_PASSWORD` log line is the only printed copy. If
  not already saved, regenerate via the `bootstrap-admin` CLI
  before the log rolls.

