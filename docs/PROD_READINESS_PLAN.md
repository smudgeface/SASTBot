# SASTBot — Production-readiness plan (2026-05-16)

Locked scope: ship the six items below before declaring SASTBot
deployable to a shared environment. M5d (scheduled scans) is deferred
to post-launch. Task 7 is **scoped to DB backup export only** — the
rest of the data-export/delete suite stays in `project_pending_features.md`.

Items, in priority order:

1. Remove the `BOOTSTRAP_ADMIN_PASSWORD=admin` dev escape hatch.
2. **M5e hardening** — rate-limit `/auth/login` (+ `/auth/logout`),
   paginate `/scans` / `/admin/repos` / `/admin/credentials`, expose
   `SCAN_WORKER_CONCURRENCY` env var.
3. **Scan resilience** — wall-clock cap on `claude -p`, stdout
   staleness heartbeat, one retry on `exitCode != 0 && records == 0`,
   refuse to mark a scan `success` when detection emitted zero records.
4. **Per-repo LLM token-budget overrides** — four nullable Int columns
   on `Repo`; UI tweak; live-progress label clarification.
5. **Surface `parseErrors` raw payloads on scan warnings** — extend
   `ScanWarning` with optional `details`; cap each raw to ~2KB.
6. **DB backup export** — admin-only "Download backup" button that
   streams a `pg_dump` of the production schema + data.

(Numbering matches the survey response that opened this plan: 1 = item 1,
2 = item 2, 3 = item 3, 5 = item 4, 6 = item 5, 7-scoped = item 6.)

## Conventions every subagent must follow

- Read `CLAUDE.md` before touching anything. The non-obvious rules
  there override anything implied below.
- One stream = one focused commit (or a tight series). Don't bundle
  unrelated work. Match the existing commit-message style — see
  `git log --oneline -10`.
- TypeScript: strict, ESM, Zod-first. `tsc --noEmit` must pass.
- Backend tests: `docker compose -f docker/compose/docker-compose.yml
  --env-file ../.env exec backend pnpm test`. All existing tests must
  pass; add new ones for any new behaviour.
- Never push to remote. Never commit `.env`. Don't touch the
  homelab IP or any LMI hostnames in generic docs.
- Use `docker compose -f docker/compose/docker-compose.yml …` — there's
  no root compose file.
- For UI changes, end-to-end-test in a browser after `tsc` passes.

### How subagents surface questions

Every subagent prompt must include: **"If you hit any
decision-shaped ambiguity — anything that could change behaviour the
operator sees — STOP, return a short note to the main agent describing
the choice and the options. Do not pick one and proceed. The main
agent will forward to the user and resume you."**

This applies even to small-looking choices (HTTP status codes, default
threshold values, migration column nullability, response field names).

Subagents should NOT surface for: typo fixes, obvious formatting,
straightforward Zod schema mirroring of existing fields, choosing
test-file names that match existing patterns.

## Open decisions to confirm before kickoff

These are flagged so the main agent forwards them to the user on
session start. Defaults the main agent should propose are listed;
subagents proceed with the default only after user confirmation.

- **Task 1 — env-var posture.** Two options:
  - (a) Delete `BOOTSTRAP_ADMIN_PASSWORD` env support outright.
  - (b) Keep the env, but treat its presence as a hard config error when
    `NODE_ENV=production`.
  Default proposal: **(b)** — preserves the dev convenience the operator
  added 2026-05-08, while making accidental shipping impossible.

- **Task 3 — wall-clock caps.** Defaults: detection 60 min, recheck
  30 min, stdout-staleness threshold 5 min. The /GoWeb scan that
  surfaced this issue ran 6h 37m before failing. Cap should be a config
  knob (env var, with sensible defaults).

- **Task 3 — retry behaviour.** Default: at most ONE retry on
  `exitCode != 0 && recordCount == 0`. Fresh `$HOME` tmpdir, same
  prompts. The retry uses the same token budget — operator pays for
  both attempts if both burn tokens. Acceptable? (Alternative: halve the
  budget on retry, but that risks the retry running out of room.)

- **Task 6 — backup format.** Default: `pg_dump --format=custom
  --compress=9` (`.dump` file, restorable with `pg_restore`). Includes
  schema + data. Alternative: plain SQL gzipped (`.sql.gz`). Custom
  format is smaller and parallelizable on restore; plain SQL is
  human-inspectable.

- **Task 6 — where does pg_dump run?** Default: install
  `postgresql-client` (matching the Postgres 16 server version) in the
  backend image; the route shells out to `pg_dump` against
  `DATABASE_URL`. Streams stdout into the HTTP response. Alternative:
  separate sidecar — overkill for this scope.

---

## Streams

Six streams, sequenced into three waves to avoid `worker.ts` and
`schema.prisma` collisions. Within a wave, streams run in parallel.

### Wave 1 (parallel)

#### Stream A — Auth hardening + dev escape hatch (covers task 1 + part of 2)

**Scope**

- Remove or gate `BOOTSTRAP_ADMIN_PASSWORD` per the open decision.
- Add `@fastify/rate-limit` (Redis-backed, since Redis is already in
  compose) on `/auth/login` and `/auth/logout`. Limit: 10/min per IP,
  `skipOnError: true` (don't fail-closed if Redis is down).
- Frontend: on 429, surface "Too many attempts. Please wait N seconds."
  using the `Retry-After` header. Block submit while the countdown
  runs. Existing login form is `frontend/src/routes/LoginPage.tsx`.

**Files to touch**

- `backend/package.json` — add `@fastify/rate-limit`.
- `backend/src/server.ts` — register the plugin.
- `backend/src/routes/auth.ts` — opt in per-route or via `config`.
- `backend/src/config.ts` — remove or gate `BOOTSTRAP_ADMIN_PASSWORD`.
- `backend/src/services/bootstrap.ts` — same.
- `.env.example` and local `.env` (local file is gitignored — don't
  commit it).
- Frontend login form for the 429 UX.

**Acceptance**

- `curl -X POST /auth/login` 11 times within a minute → 11th returns
  429 with `Retry-After`.
- With `NODE_ENV=production` and `BOOTSTRAP_ADMIN_PASSWORD` set,
  backend refuses to boot (path (b)) — OR the env var is gone entirely
  (path (a)).
- Existing `tests/passwords.test.ts` still passes.
- Login UI shows countdown on 429.

**Risks**

- Redis being down shouldn't lock everyone out. `skipOnError: true`
  must be set.
- `@fastify/rate-limit` keys on `req.ip` by default; verify it works
  behind nginx in the homelab compose (X-Forwarded-For chain).

#### Stream F — DB backup export (task 7 scoped)

**Scope**

- New admin-only route: `GET /admin/db/backup`. Streams a `pg_dump` of
  the configured `DATABASE_URL` as the HTTP response.
- New UI in the admin area: a "Download backup" button on the existing
  admin settings page (`frontend/src/routes/admin/SettingsPage.tsx` or
  wherever feels right — pick the page that already has admin-only
  actions).
- Backend image: install `postgresql-client` (Postgres 16, matching the
  server version pinned in compose) so `pg_dump` is on PATH.

**Files to touch**

- `docker/backend.Dockerfile` — add `postgresql-client` install.
- `backend/src/routes/` — new file or fold into existing admin routes.
- Frontend admin page — button + click handler that triggers a download.

**Acceptance**

- `curl -b <admin-session-cookie> /admin/db/backup -o backup.dump`
  produces a non-empty file.
- `pg_restore --list backup.dump` enumerates expected tables.
- Non-admin user gets 403.
- A truly minimal backup (empty DB) still produces a valid dump.

**Risks**

- pg_dump can take minutes on large DBs. Don't time out the request at
  the proxy layer. Set sensible HTTP response timeouts.
- `DATABASE_URL` includes the password — don't log the spawned command.
  Pass DB connection via env, not argv.
- Postgres version mismatch between client and server will refuse to
  dump. Pin matching majors.

**Wave-2 prerequisite**: none.

### Wave 2 (parallel)

#### Stream B — Pagination + worker concurrency (rest of task 2)

**Scope**

- Paginate three endpoints. Defaults / max:
  - `/scans` → page 50, max 200.
  - `/admin/repos` → page 100, max 500.
  - `/admin/credentials` → page 100, max 500.
- Frontend pagination controls on those three list pages. The
  `Pager` component (used on `/scopes` SCA/SAST tabs) is the pattern.
- New env var `SCAN_WORKER_CONCURRENCY` (Zod-validated in
  `backend/src/config.ts`, default 2, max 4). Passed to `new Worker(…,
  { concurrency: N })` in `backend/src/worker.ts`.

**Files to touch**

- Routes: `backend/src/routes/scans.ts`, `adminRepos.ts`,
  `adminCredentials.ts`.
- Schemas: `backend/src/schemas.ts` (add Paginated wrappers if not
  already there for these endpoints — server-side sort+paginate on
  SCA/SAST tables shipped recently, follow that pattern).
- Frontend list pages (Scans page, ReposPage, CredentialsPage).
- `backend/src/config.ts` + `worker.ts` for the concurrency env.

**Acceptance**

- `GET /scans?page=2&page_size=20` returns 20 rows of page 2; total
  count present in response.
- `SCAN_WORKER_CONCURRENCY=4` makes the worker process up to 4 scans in
  parallel; default 2 otherwise. Verify with two concurrent test scans.
- All three list UIs have a working Pager.

**Risks**

- The Pager pattern was added recently for SCA/SAST tabs (commit
  `03ac821`). Reuse, don't reinvent.

#### Stream D — Per-repo LLM token-budget overrides (task 5)

**Scope**

- Four nullable `Int?` columns on `Repo`: `llmSbomTokenBudget`,
  `llmSbomRecheckTokenBudget`, `llmSastTokenBudget`,
  `llmRecheckTokenBudget`. NULL → fall back to the worker's hardcoded
  default (today: 200k / 50k / 300k / 50k respectively — verify
  current values in `worker.ts` before touching).
- Prisma migration generated via `prisma migrate dev --name
  add_per_repo_llm_token_budgets`.
- Frontend repo edit dialog gets a pre-collapsed "Token budgets"
  section just below the existing "LLM effort" section. Four number
  inputs; empty input means "use default" (null in DB).
- Worker live-progress label: prefix the count with the phase name
  (e.g. "LLM SAST detection · 130k / 300k tokens"). The label field
  on `phase_progress` already exists — just enrich the string.

**Files to touch**

- `backend/prisma/schema.prisma` + new migration folder.
- `backend/src/worker.ts` — replace hardcoded budget constants with
  `repo.llm*TokenBudget ?? DEFAULT_*` reads.
- `backend/src/services/mappers.ts` and admin repo schema in
  `backend/src/schemas.ts`.
- `frontend/src/routes/admin/ReposPage.tsx` (edit dialog).
- Frontend types: regenerate via `npm run gen:types`.

**Acceptance**

- A new repo saved with all four budgets blank still scans with the
  default values.
- Setting `llmSastTokenBudget = 100000` reduces the LLM-detection
  phase total in the live-progress bar.
- `tsc --noEmit` clean on both backend and frontend.

**Risks**

- Make sure the migration is reversible. NULL default + the worker's
  `?? DEFAULT_*` fallback means rolling back is just dropping the
  columns.

#### Stream E — parseErrors raw on scan warnings (task 6)

**Scope**

- Extend `ScanWarningSchema` in `backend/src/schemas.ts` with optional
  `details: z.unknown().optional()`.
- Worker (`backend/src/worker.ts`) passes
  `detection.parseErrors.slice(0, 5)` (and the recheck equivalent)
  into the warning's `details`. Cap each `raw` field to 2KB before
  persisting.
- Frontend `ScanWarnings` rendering: collapsible `<details>` per
  warning when `details` is non-empty; show `{raw, reason}` pairs.

**Files to touch**

- `backend/src/schemas.ts`.
- `backend/src/worker.ts` (the two existing parse-error append-warning
  sites; grep for `parse_errors`).
- Wherever the frontend renders warnings (grep `scan_warnings` /
  `warnings:`).

**Acceptance**

- Force a malformed LLM line locally; verify the warning's `details`
  array contains the truncated raw text + reason.
- Existing warnings without `details` still render correctly (no UI
  regression).
- 2KB cap enforced (write a unit test).

**Risks**

- `unknown` in the Zod schema is lazy but correct here — we don't
  control the LLM's output shape. Don't try to make it strict.

### Wave 3 (alone)

#### Stream C — Scan resilience (task 3)

**Scope**

- **Wall-clock cap** on the `claude -p` subprocess. Defaults: detection
  60 min, recheck 30 min. Env-var overrides:
  `CLAUDE_DETECTION_TIMEOUT_MS`, `CLAUDE_RECHECK_TIMEOUT_MS` (Zod-validated
  in `config.ts`). On timeout: SIGTERM, 5 s grace, then SIGKILL.
- **Staleness heartbeat** on the streaming JSONL parser. Track
  time-since-last-stdout chunk. If no output for 5 min (env-configurable,
  `CLAUDE_STDOUT_STALENESS_MS`), kill the subprocess and treat as failed.
- **Retry once** on `exitCode != 0 && recordCount == 0`. Fresh tmpdir,
  same prompts, full token budget (per the open decision). At most one
  retry per phase per scan.
- **Don't mark `success` on 0-record detection** scans. The simplest
  path: emit an `error`-severity warning (`sast_detection_failed`) when
  detection should have run but produced zero records — the existing
  `hasErrorWarnings` gate already changes UI semantics for these. Verify
  the scope page's status badge reflects this.
- Investigate the BullMQ lock-extension errors that show in
  laptop-sleep logs. Likely already handled by BullMQ's stalled-job
  recovery; document if so, fix if not.

**Files to touch**

- `backend/src/services/llmSastService.ts` — `spawnClaudeAndStream`
  for the timeout + heartbeat; `runDetection` / `runRecheck` for the
  retry-on-zero-records loop.
- `backend/src/worker.ts` — the 0-record warning emission.
- `backend/src/config.ts` — new env vars.

**Acceptance**

- A manually-induced hang (e.g. block the LLM endpoint) triggers the
  staleness kill within `CLAUDE_STDOUT_STALENESS_MS`.
- A manually-induced subprocess exit-1 retries exactly once.
- A 0-record detection produces a scan visible as degraded in the UI
  (matches the existing `cdxgen_failed` / `llm_sast_detection_failed`
  treatment).
- Existing scans still complete normally.

**Risks**

- Don't break the natural token-budget-driven termination. The
  wall-clock cap is a safety net, not the primary stop signal.
- Retry doubles spend in the worst case. Document this in the warning
  payload so operators can audit cost.
- SIGTERM may leave tmpdir state behind. `cleanupTmp` already handles
  this — verify it runs in the timeout path.

---

## Wave gating

The main agent should:

1. Confirm the open-decisions list (above) with the user before
   spawning any subagent.
2. Spawn Wave 1 subagents (A + F) in parallel. Wait for both to land
   commits.
3. Spawn Wave 2 (B + D + E) in parallel. Wait for all three commits.
4. Spawn Wave 3 (C). Wait for it to land.
5. Update `docs/PROGRESS.md` with a single "Production readiness"
   entry summarizing all six streams.
6. Hand back to the user with a final summary.

If any subagent surfaces a question, the main agent pauses ALL active
subagents (or finishes the in-flight one safely), forwards the
question to the user, and resumes once the user answers.

## Subagent prompt template

Use this skeleton when spawning each subagent. Fill in `{{STREAM}}`
with the section above.

```
You are working on the SASTBot production-readiness plan. Your stream is:

{{STREAM full text from docs/PROD_READINESS_PLAN.md}}

Read CLAUDE.md and docs/PROD_READINESS_PLAN.md before touching anything.

Constraints:
- Pass `model: "sonnet"`. Do not escalate to Opus without main-agent
  approval.
- Make your edits, run `tsc --noEmit`, run `pnpm test`. If something
  fails, fix it before stopping.
- For UI changes, smoke-test in a browser before reporting done.
- One focused commit at the end. Match the project commit-message
  style — see `git log --oneline -10`. Co-Authored-By line as in
  existing commits.
- DO NOT push to remote.

If you hit any decision-shaped ambiguity — anything that could change
behaviour the operator sees — STOP, return a short note to the main
agent describing the choice and the options, do not pick one and
proceed. The main agent will forward to the user.

Report back: commit hash, files changed, tests added/passing, anything
that surprised you that the next stream should know.
```

## Out of scope for this plan

These are intentionally NOT in the six streams above. They live in
`project_pending_features.md` and stay there:

- M5d scheduled scans
- Per-repo / per-scan data export beyond DB backup
- Repo deletion UI with cascade preview
- Bulk-by-age retention purge
- Notifications system (depends on scheduler)
- Dashboard merge + finish open-findings rollup
- Within-phase progress streaming, scan progress v2
- Manual "Add component" button
- Live-scan banner link to scan detail
- SAST UI polish re-audit
- LLM extraction accuracy audit

If during implementation a subagent thinks one of these has become a
genuine prerequisite, surface it — don't expand scope unilaterally.
