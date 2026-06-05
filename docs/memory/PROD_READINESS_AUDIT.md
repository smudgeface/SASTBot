# SASTBot — Production-Readiness Audit (Stage 1)

**Date:** 2026-05-29 · **Version audited:** v0.15.0 (`main`, commit `cce2d1c`)
**Purpose:** Survey the codebase before the production push (Stage 2 = Bitbucket
migration, Stage 3 = Pipelines/Packages build, Stage 4 = Proxmox runbook). This
document is the Stage-1 deliverable: a grouped findings list to align on scope
**before** making sweeping changes.

Method: six parallel read-only audit passes (security, backend
error-handling/ops, dead-code/consistency, docs/manual drift, test coverage,
frontend prod-readiness). The highest-stakes findings were re-verified by hand;
severities below are the **post-verification** judgments, which in several cases
*lower* what the raw passes proposed (noted inline). Nothing has been changed.

---

## 0. TL;DR — what matters most

1. **🚨 BLOCKER for Stage 2:** two untracked directories contain sensitive
   material and are **not** in `.gitignore` — `docs/Claude CRA Analysis Reference/`
   (real LMI firmware audit findings incl. plaintext passwords) and `.claude/`
   (local session state/screenshots). They must be ignored **before** the repo
   moves to Bitbucket. (PR-01)
2. **Security defaults:** `SESSION_COOKIE_SECURE` defaults to `false` with no
   production guard (PR-02); no HTTP security headers (PR-12); SSH host-key
   policy is trust-on-first-use (PR-20, LMI IT will ask).
3. **Worker resilience:** OSV/NVD HTTP calls have **no timeout** (PR-03) — a hung
   upstream socket can stall a scan phase until the OS TCP timeout; `server.ts`
   has no `unhandledRejection`/`uncaughtException` handler (PR-04, the worker
   already does).
4. **Operability for a manual Proxmox deploy:** `/healthz` doesn't probe DB/Redis
   (PR-13), no container `HEALTHCHECK` / compose healthcheck (PR-14), containers
   run as root (PR-21).
5. **Doc/version drift:** README + `versioning.md` still say `0.1.0`; several docs
   reference the removed Opengrep and a never-shipped 15-min Jira auto-sync. All
   quick wins, but LMI IT will read these. (PR-30…PR-37)
6. **Test coverage:** the security and correctness-critical core (sessions, auth
   plugin, credential crypto round-trip, CVSS scorers, `componentMatch`,
   `hasErrorWarnings`) has **zero** direct tests. Most are small, pure-logic
   quick wins. (§5)

**Recommended Stage-1 scope:** do all of **Group A (safe quick wins)** in one or
two batched commits; pick from **Group B (needs-a-decision)** together before I
touch them; and decide how much of the **test backfill** belongs in Stage 1 vs a
follow-up. See §6 for the proposed plan and the open questions for you.

---

## 1. 🚨 Pre-Bitbucket blocker (do first, regardless of scope)

### PR-01 — Sensitive untracked dirs not gitignored — **CRITICAL**
*Confirmed by hand: neither path is tracked, neither is matched by `.gitignore`.*

- `docs/Claude CRA Analysis Reference/` — contains `CRA_Compliance_Report.md`
  (31 KB) with **real LMI product firmware findings**: hardcoded firmware
  passwords, MongoDB credentials, RSA key paths, an internal IP
  address, plus a product SBOM and the generating prompt. This is not
  SASTBot code and must never land in a shared repo.
- `.claude/` — local Claude Code session state: `settings.local.json`,
  screenshots, `worktrees/`, task locks. Machine-local, not for sharing.

**Fix:** add both to `.gitignore` now. (Also fold in: confirm `Screencaps/` and
`SASTBot Initial Prompt.txt` rules still hold — they do.) One-line-each change,
zero risk. **This is the one item I'd like to land immediately on your go-ahead**,
because it's the gate for Stage 2.

> Note: `.DS_Store`, `.env`, `docs/DEPLOY_HOMELAB.md`, `docs/DEPLOY_DOKPLOY_*.md`
> are already correctly ignored. The leak surface is just the two dirs above.

---

## 2. Group A — Safe quick wins (low-risk, batchable, no behavior/arch decision)

These are mechanical or additive, with no architectural impact. I'd batch them
into a small number of commits (security/ops fixes, doc fixes, frontend polish).

### Security / config
- **PR-02 — `SESSION_COOKIE_SECURE` prod guard.** Default is `false` and there's
  no boot check. Add a guard mirroring the existing `BOOTSTRAP_ADMIN_PASSWORD`
  one: if `NODE_ENV=production` and it's `false`, refuse to boot with a clear
  message. (HIGH) `backend/src/config.ts:170,309`
- **PR-05 — Validate `effort`/`model` before passing to `claude` argv.** Not an
  injection (separate argv elements, no shell), but add a Zod enum on `effort`
  and a `/^[A-Za-z0-9._:-]+$/` check on `model` so a bad DB value can't smuggle a
  CLI flag. (LOW) `backend/src/services/llmSastService.ts:608`
- **PR-06 — `licenses` Postgres array literal escaping.** *Re-verified: this is
  NOT SQL injection (bound as `$7::text[]`).* It's a robustness bug — only `"` is
  escaped, not `\`, so an exotic license string produces a malformed array literal
  and fails the scan. Build the array via `Prisma.join`/parameters instead of a
  hand-rolled `{...}` string. (MEDIUM, downgraded from HIGH)
  `backend/src/services/scopeComponentService.ts:162,230,304`

### Backend resilience / ops
- **PR-03 — Add timeouts to OSV + NVD fetches.** Both lack an `AbortSignal`; a
  hung upstream stalls the phase until the OS TCP timeout. Add
  `signal: AbortSignal.timeout(...)` (Jira/EOL/LLM already do this). (HIGH)
  `osvService.ts:224`, `nvdService.ts:330`
- **PR-04 — `server.ts` process-level handlers.** Add `unhandledRejection` /
  `uncaughtException` handlers like `worker.ts` already has. (MEDIUM-HIGH)
- **PR-07 — Redis `connectTimeout`.** Add `connectTimeout: 10_000` so a startup
  Redis outage surfaces fast instead of hanging. (LOW-MEDIUM)
  `backend/src/queue/connection.ts`
- **PR-08 — Explicit BullMQ `attempts`/`lockDuration`.** *Re-verified: the agent's
  "scans >30s always stall" was wrong — BullMQ auto-renews the lock on the event
  loop while `claude -p` is awaited.* Still worth setting `attempts: 1` and a
  generous `lockDuration` defensively (the narrow real risk is an event-loop block
  on a large payload causing a false stall + duplicate scan). (MEDIUM, downgraded)
  `worker.ts:2015`, `scanService.ts:67`
- **PR-09 — Document/clean diagnostic env vars.** `SASTBOT_RAW_STREAM_DUMP`,
  `SASTBOT_EVENT_TEXT_DUMP` read directly from `process.env`; add to `.env.example`
  as commented DEBUG vars. (LOW)

### Container / compose (additive)
- **PR-14 — Add `HEALTHCHECK` to backend Dockerfile + a compose healthcheck** for
  backend/worker (postgres/redis already have them). Use `wget --spider` against
  `/healthz` (or the new readiness probe from PR-13). (MEDIUM)
- **PR-15 — Pin base images** to a dated tag or digest (`node:20-bookworm-slim`
  floats today). (LOW)

### Frontend
- **PR-10 — Top-level React error boundary.** A render crash currently
  white-screens the SPA with no recovery. Wrap `<App/>` in a small boundary with a
  reload affordance. (HIGH — quick win) `main.tsx`
- **PR-11 — Surface mutation errors.** Bare `triggerScan/cancelScan/triage/dismiss
  .mutate()` calls swallow failures silently in the primary scope-detail UX; add
  `onError` toasts mirroring `ReposPage`. (MEDIUM) `ScopeDetailPage.tsx`,
  `ScansPage.tsx`
- **PR-16 — Neutralize the hardcoded LLM default URL.** `SettingsPage.tsx` defaults
  the LLM base URL to an internal TKH/LMI LLM-gateway URL and even
  falls back to it when the stored value is empty. Default to `""`. (MEDIUM)
  `frontend/src/routes/admin/SettingsPage.tsx:32,83`
- **PR-17 — Generalize the LAN IP comment.** `clipboard.ts:7` hardcodes
  a LAN IP in a doc comment; replace with `http://<LAN-IP>:5173/`. (LOW)
- **PR-18 — Dashboard "Available in M3" placeholder.** Stale milestone label shown
  to operators; wire to real counts or change the hint. (MEDIUM) `DashboardPage.tsx`
- **PR-19 — Error states.** `ScansPage` renders blank (no `isError` branch) on
  query failure; `ScopeSbomViewerPage` shows a generic error instead of the
  404/"re-run to produce artifact" guidance its sibling viewers use. (MEDIUM)
- **PR-19b — `favicon.svg` 404 + per-route `document.title`.** `index.html`
  references a favicon that doesn't exist; add one. Optionally set page titles.
  (LOW)

### Docs / manual / OpenAPI (all quick wins; LMI IT will read these)
- **PR-30 — Version drift.** README says "Currently `0.1.0`" (×1) and
  `docs/user/versioning.md` shows `0.1.0` throughout incl. the `GET /version`
  example. Update to `0.15.0` (or make examples illustrative). (MEDIUM)
- **PR-31 — README milestone table stale.** Lists M4 as "Opengrep + LLM triage"
  (Opengrep removed M6g), shows M5d/M5e as pending though much shipped, omits
  M6–M14. (MEDIUM)
- **PR-32 — `.env.example` `DATABASE_URL`** uses a Python `postgresql+asyncpg://`
  DSN — wrong for Prisma. Fix to `postgresql://` and the comment. Also add the
  undocumented-but-real vars (`PORT`, `CLONE_CACHE_DIR`, the three
  `CLAUDE_*_TIMEOUT_MS`, `DB_RESTORE_MAX_BYTES`, `SASTBOT_CONFIG_FILE`). (MEDIUM)
- **PR-33 — OPERATIONS.md false/stale claims:** "ignore paths applied to cdxgen
  and **Opengrep**" (gone); "Jira re-synced every 15 minutes (Phase 5d)" —
  **never wired** (`reconcileJiraSync` exists but is uncalled; only the UI Refresh
  button syncs); cancellation note mentions opengrep; backfill table lists 5 of
  ~10 actual backfills (and a wrong name `backfillSastContextSnippets` vs
  `backfillSastSnippets`). (MEDIUM for the Jira claim, else LOW)
- **PR-34 — Manual: `removed` → `not_found`.** `sca-issues.md` / `scopes.md` still
  use the pre-M14 `removed` status name. (MEDIUM)
- **PR-35 — Manual: LMI-specific phrasing** in `index.md` ("At LMI Technologies…")
  and `repositories.md` ("every LMI repo"); generalize. (LOW)
- **PR-36 — SBOM/SARIF artifact routes lack OpenAPI metadata.**
  `GET /scans/:id/sbom` and `/sast-sarif` use bare `app.get` with no
  `tags`/`summary`, so they're invisible in the API-reference page the manual
  links to. Add metadata. (MEDIUM) `routes/scans.ts:298,346`
- **PR-37 — Stale comments/notes:** `worker.ts:1346` "strip excluded subtrees from
  opengrep" (now the LLM `IGNORE_PATHS` block); `sbomCurated.ts` header describes
  only the per-scan builder; three stale M14 `TODO`s in `frontend/.../scopes.ts`;
  CLAUDE.md phase enum missing 5 phases and the stale "read M5_PLAN.md" pointer.
  (LOW/INFO)

---

## 3. Group B — Larger / needs-a-decision (behavior, architecture, or scope)

I will **not** touch these without aligning with you first.

- **PR-20 — SSH host-key policy is TOFU.** When an SSH credential has no
  `known_hosts`, clone uses `StrictHostKeyChecking=accept-new`. There's an
  explicit `TODO(security)` in `gitClone.ts:160`. **Decision:** require
  `known_hosts` for SSH creds (migration + UI), or document the residual risk in
  OPERATIONS.md and accept it. LMI IT will likely ask. (MEDIUM)
- **PR-21 — Containers run as root.** Main server/worker run as UID 0; only the
  `claude -p` subprocess drops to `claudeuser`. Standard scanners (Trivy/Snyk/
  Docker Scout) flag this. Fixing it touches volume ownership for `/app/clones` +
  artifacts and the chown-to-claudeuser mechanism — non-trivial. **Decision:**
  in-scope for Stage 1, or a Stage-3/4 hardening item? (MEDIUM)
- **PR-13 — Readiness probe.** Add `/readyz` (or upgrade `/healthz`) to do
  `SELECT 1` + Redis `PING`. **Decision:** new endpoint vs change `/healthz`
  semantics (affects whatever already calls it). (MEDIUM)
- **PR-22 — Unbounded list queries.** `GET /scans/:id/sbom-components`,
  `/scopes/:id/sast-issues`, `/scopes/:id/sca-issues` do `findMany` with no `take`
  and sort in memory. Fine at today's volumes; grows with scan history.
  **Decision:** add a safety cap now (quick) vs proper pagination (API + frontend
  change). (MEDIUM)
- **PR-23 — Stuck-`running`-scan cleanup.** If Postgres is down at finalize, a
  scan can stay `running` forever (no sweeper). **Decision:** add a startup/cron
  sweep that fails `running` scans older than N hours. (LOW-MEDIUM)
- **PR-24 — `backfillLlmSummaries` failure behavior.** If the LLM endpoint is down
  it iterates the whole un-summarized corpus returning `null`, with a growing
  `notIn` set. **Decision:** add consecutive-failure early-exit + cursor paging.
  (MEDIUM)
- **PR-25 — `ARTIFACT_DIR` bypasses `config.ts`.** Read directly from
  `process.env` (intentional for tests). **Decision:** fold into the Zod config
  with a test reset helper, or leave with a comment. (MEDIUM)
- **PR-26 — `schema.d.ts` unused.** Generated OpenAPI types are committed but never
  imported; hooks use hand-written `types.ts`. **Decision:** wire the generated
  types (realize the safety guarantee) or drop `schema.d.ts` + the `gen:types`
  script and bless `types.ts`. (MEDIUM)
- **PR-27 — Compose targets `dev`.** The committed compose builds the `dev` stage
  and publishes Postgres/Redis ports to the host — correct for local dev, unsafe
  if reused for prod. The Stage-4 Proxmox compose will be separate, but
  **decision:** add a warning comment / `docker-compose.prod.yml`, or leave it to
  Stage 4. (MEDIUM in a prod context)
- **PR-28 — Manual scan-trigger endpoint doc.** `scans.md` documents
  `POST /api/scans {scope_id}`, which doesn't exist (only `POST /api/admin/repos/
  :id/scan`). **Decision:** fix the doc to the real endpoint, or add a per-scope
  trigger route. (MEDIUM)
- **PR-29 — Mid-session 401 handling (frontend).** A 401 from non-`/me` queries
  shows per-card errors with no redirect/"session expired" message. **Decision:**
  global `QueryCache`/`MutationCache` `onError` that invalidates `me` (soft) vs a
  hard `window.location` redirect. (HIGH UX, small but a behavior choice) `main.tsx`
- **Lower-priority "needs decision" notes:** SSRF validation on admin
  `llmBaseUrl`/`jiraBaseUrl` (LOW), `sameSite:"lax"` + `GET /admin/db/backup`
  CSRF surface (LOW), prompt-injection hardening for repo name/branch in the LLM
  prompt (LOW), bootstrap admin password appearing in container logs (operational
  — document + rotate), `staleTime: Infinity` on the scope SBOM query vs the known
  scope-SBOM drift TODO (LOW).

---

## 4. Things checked and found GOOD (for the LMI IT conversation)

Worth keeping handy — the audit found a lot that's already right:

- **No shell injection anywhere.** Every subprocess (`git`, `cdxgen`, `claude`,
  `pg_dump`/`pg_restore`/`tar`, `prisma migrate`) uses argv arrays, `shell:false`.
  Git credentials go via `GIT_ASKPASS`/`GIT_SSH_COMMAND`, never in argv/URLs;
  `GIT_TERMINAL_PROMPT=0`.
- **AES-256-GCM done correctly** — random 12-byte IV per encryption, auth tag
  verified, boot-time canary. Session tokens are 256-bit random, stored as SHA-256
  hashes. Cookies `httpOnly`; `secure` is env-driven (see PR-02 for the default).
- **AuthZ is consistent** — every `/admin/*` route has `requireAdmin`; every
  domain query is `org_id`-scoped (no IDOR); all routes Zod-validated; no
  `$queryRawUnsafe` with user data in structural position.
- **CORS locked to a single configured origin**; auth rate-limiting enabled
  (Redis-backed).
- **Path traversal guarded** in `readSourceSnippet` and in restore tarball
  extraction (entry allowlist).
- **Credentials never returned in API responses**; `MASTER_KEY` never logged.
- **Worker error→failed lifecycle is solid**: typed clone/cdxgen/OSV warnings,
  `hasErrorWarnings` gating, scan marked `failed`, scope pointer held. Worker has
  graceful shutdown + process-level handlers. Atomic artifact writes.
- **Frontend hygiene:** no `console.log`/`debugger`, no `any`/`@ts-ignore`, no
  prod source maps, no absolute API hosts (all via `apiFetch`), nginx prod proxy
  correct, manual route correctly public, login 429 countdown UX.
- **No `any` in backend src; no dead service files** from the M6g/M7/M9 deletions
  (verified zero references). Version surfaces (the 3 sanctioned files) agree at
  `0.15.0`.

---

## 5. Test coverage (its own workstream)

CI does not exist yet (expected — Pipelines is Stage 3). `vitest` + `typecheck`
scripts exist both sides. Backend has 35 test files with strong coverage of the
SBOM/SARIF pipeline, LLM stream/resilience, config, crypto primitives, scan-delete,
restore bucketing, and the SCA trust-gates. **The gaps are concentrated in the
security and correctness core** — mostly small, pure-logic unit tests:

**HIGH-value quick wins (no new infra):**
- `sessions.ts` (create/resolve/expire/revoke) — **zero** coverage, runs on every
  request.
- `credentialService` encode/decode round-trip — **zero** (only mocked elsewhere).
- `ensureCanary()` in `crypto.ts` — boot-time key guard, untested.
- `cvss4.ts` + `computeCvss31BaseScore` — severity scores drive triage/CRA
  artifacts; **zero** coverage. Table-driven vectors vs first.org ground truth.
- `componentMatch.ts` 7-tier dedup — the M7 corruption hot-spot; only exercised
  transitively with root-scope fixtures.
- `scanWarnings.hasErrorWarnings` — the single gate for sweep/recheck/finalize;
  **zero** coverage.
- `scaAutoFix` `TERMINAL_STATUSES` exactness; `scopePath` non-root translation;
  `sourceSnippet` real file read; `sastDedup`; `issueSort`; `nvdService.sanitizeVersion`.

**Needs a small harness (decision):**
- HTTP-level tests for `plugins/auth.ts` and `routes/auth.ts` via `fastify.inject`
  (no external HTTP) — verifies 401-without-session and the login/logout flow.
- `osvService.queryAndPersistFindings` network/trust-gate path (mock fetch+Prisma).
- Frontend: data-bearing components (`StatusBadge`, `ContextSnippet`, `FileLink`)
  are untested.

**Decision for you:** how much of this lands in Stage 1? My suggestion is the
HIGH-value pure-logic unit tests (sessions, credential round-trip, canary, CVSS,
componentMatch, hasErrorWarnings) — they're cheap, they protect exactly the code
LMI IT will care about, and they give us a real suite to wire into Pipelines in
Stage 3. The Fastify-inject harness is a slightly larger lift but high value.

---

## 6. Proposed Stage-1 execution plan (for your approval)

1. **Now, on your go-ahead:** PR-01 (gitignore the two sensitive dirs). Smallest,
   highest-urgency, gates Stage 2.
2. **Batch 1 — safe quick wins (Group A), grouped commits:**
   - (a) security/config + resilience: PR-02, 03, 04, 05, 06, 07, 08, 09
   - (b) docs/manual/OpenAPI: PR-30…PR-37
   - (c) frontend polish: PR-10, 11, 16, 17, 18, 19, 19b
   - (d) container additive: PR-14, 15
   Each batch is a reviewable commit; I'll run `tsc --noEmit` + the test suite
   before proposing anything for commit, and I won't commit without your say-so.
3. **Decisions to make together (Group B):** I'll bring PR-13/20/21/22/26/27/29
   to you as a short decision list — these change behavior or architecture.
4. **Tests:** confirm the Stage-1 slice (my suggestion above).
5. **Version bump:** this is operator-visible (config guard, new healthcheck,
   manual edits) → a MINOR bump (0.15.0 → 0.16.0) across the 3 surfaces, per
   policy. **A bump is not a deploy** — I'll ask before any deploy.

### Open questions for you
- **Q1.** OK to land **PR-01 (gitignore)** immediately?
- **Q2.** Run **all of Group A** in batched commits, or do you want to cherry-pick?
- **Q3.** For Group B, which are Stage-1 vs deferred? (My lean: do PR-13, 22-cap,
  29 now; defer PR-21 root-user and PR-26 schema-types to a dedicated hardening
  pass.)
- **Q4.** Test scope — the HIGH-value pure-logic unit tests in Stage 1? Add the
  Fastify-inject auth harness too?
- **Q5.** Single `0.16.0` bump at the end of Stage 1, or hold the bump until we
  know what's actually shipping?
