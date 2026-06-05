# M7 — Production-Readiness Plan

> **Status:** Survey + plan. No implementation yet.
> **Date:** 2026-05-13
> **Scope:** Everything that has to be true before SASTBot can be deployed
> to a non-dev environment (currently dev-only on local Colima; first prod
> target is homelab Dokploy per `docs/DEPLOY_HOMELAB.md`).
>
> Use this doc to pick what ships first. Items are tagged **P0 / P1 / P2**:
>
> - **P0** — must be true before *any* non-dev deploy. Hard blockers.
> - **P1** — must be true before the system is shared with anyone else
>   (other operators, internal team). Soft blockers; you can run a
>   single-operator deploy without them, but you shouldn't.
> - **P2** — should be true within the first month of running shared.
>   Quality, resilience, and operability work that compounds.
>
> Effort estimates are coarse: **S** (≤2 hr), **M** (half-day), **L**
> (1 day), **XL** (2–3 days). They're for sequencing, not commitments.

## Reading order

1. § Auth & sessions
2. § Rate limiting
3. § Secrets & key material
4. § Deployment topology & hardening
5. § Database
6. § Worker resilience
7. § Observability
8. § Tests & CI
9. § Approved-but-unshipped milestones (M5d / M5e)
10. § Documentation & runbook

---

## 1. Auth & sessions

### 1.1 Remove or hard-guard `BOOTSTRAP_ADMIN_PASSWORD` — **P0, S**

**Current state.** `backend/src/config.ts` declares `BOOTSTRAP_ADMIN_PASSWORD`
as optional; `backend/src/services/bootstrap.ts` uses it verbatim when set
and prints a `[BOOTSTRAP] WARNING` to stdout (only fires when there's no
admin yet — i.e. on first boot after a fresh DB, not on subsequent
restarts). `.env.example` ships the var commented out with a "DEV-ONLY,
leave UNSET in production" note. The local `.env` currently sets it
(intentional dev convenience — added 2026-05-08 so `docker compose
down -v` doesn't force a password fish from logs each time).

**Risk.** A `.env` carrying `BOOTSTRAP_ADMIN_PASSWORD=admin` copied verbatim
to Dokploy will silently seed `admin@sastbot.local` / `admin` on first
boot. Warning is advisory only — no code-level guard against production
use.

**Fix sketch.** Two viable paths, pick one:

- **(a) Delete the env var support.** Remove the field from
  `backend/src/config.ts`, drop the conditional in
  `backend/src/services/bootstrap.ts`, remove the commented stanza from
  `.env.example`. Operators always get a random password printed to
  backend logs on first boot. Simpler, less surface area.
- **(b) Treat it as a hard config error when `NODE_ENV === "production"`.**
  Keep the dev convenience; refuse to boot in prod if it's set. Add the
  guard in `loadConfig()` and a test.

Either way, scrub local `.env` before any prod copy. Whichever option
ships, update `docs/OPERATIONS.md` to reflect it.

### 1.2 Rate-limit `/auth/login` and `/auth/logout` — **P0, S** (also part of M5e)

**Current state.** `@fastify/rate-limit` is not installed (`backend/package.json`
has no entry). No custom throttle. `POST /auth/login` is unauthenticated and
unrate-limited; bcrypt cost-12 makes brute force expensive but does not
prevent credential-stuffing attempts at small scale.

**Risk.** With the API exposed via Dokploy Traefik on a public URL, anyone
can hammer login. Logs would record nothing useful (see 1.4).

**Fix sketch.** Add `@fastify/rate-limit` plugin, Redis-backed (we already
have Redis), `skipOnError: true`. Apply to `POST /auth/login` and
`POST /auth/logout`: 10 attempts / minute per IP. Frontend `LoginForm`
shows "Too many attempts, please wait Ns" on 429. This is the same spec
as M5e §1; ship it now rather than waiting for the full M5e bundle.

### 1.3 Session rotation on login — **P1, S**

**Current state.** `backend/src/security/sessions.ts` always *creates* a
new session row on login; pre-existing sessions for the same user are
**not invalidated**. `revokeSession` exists but is only called from logout.
TTL is 14 days; tokens are 256-bit CSPRNG and stored as SHA-256 hashes.

**Risk.** If an attacker captures a session cookie (e.g. via XSS, MITM
on a misconfigured proxy, or a developer leak via the un-redacted Pino
request logs — see 7.2), it remains valid for 14 days even if the user
later changes password. There is no "logout everywhere" path.

**Fix sketch.** On successful login, revoke all sessions for the user
(other than the new one). On password change (once that exists, see
1.6), revoke all existing sessions. Tighten TTL to 7 days. Add a
"Sign out everywhere" button on the admin profile page (post-1.6).

### 1.4 Log failed logins + fix the timing oracle — **P1, S**

**Current state.** `backend/src/routes/auth.ts` returns a flat 401 on
auth failure with no `req.log.warn`. `backend/src/security/authBackend.ts`
calls `findUnique` first; if the user doesn't exist, it returns `null`
*without* calling `bcrypt.compare`. This is a side-channel:
unknown-email responses are measurably faster than wrong-password
responses, leaking which addresses are registered.

**Risk.** Two things: (a) failed-attempt forensics are impossible —
nothing is recorded; (b) email enumeration via timing makes the rate
limit in 1.2 work harder. Both are low-severity but cheap to fix.

**Fix sketch.** In `authBackend.authenticate`, always run a bcrypt
comparison even when the user doesn't exist (against a fixed dummy
hash). In `auth.ts:POST /auth/login`, emit `req.log.warn({ email, ip })`
on every failure (after the rate-limit middleware so it's not noisy).
Don't include the password.

### 1.5 Cookie flags — `SESSION_COOKIE_SECURE=true` mandatory in prod — **P0, S**

**Current state.** `auth.ts` sets `httpOnly: true`, `sameSite: "lax"`,
`secure: config.sessionCookieSecure`. `SESSION_COOKIE_SECURE` defaults
to `false` (`config.ts`) and `.env.example` ships it as `false`. The
admin who copies `.env.example` to `.env` in Dokploy and forgets to
flip this gets cookies sent over HTTP if anyone accesses without TLS.

**Risk.** Cookie capture over plaintext on misconfigured deploys.
Behind Dokploy's Traefik with auto-LE certs this is unlikely in
practice, but defense in depth is cheap.

**Fix sketch.** Add a config-time guard: if `NODE_ENV=production` and
`SESSION_COOKIE_SECURE !== "true"`, refuse to boot with a clear error.
Update `.env.example` to leave the var unset with a comment "Required
to be true in production". `sameSite: "lax"` is fine for the API-driven
SPA posture; no CSRF token plumbing needed.

### 1.6 Password change route — **P1, M**

**Current state.** None. Admin password can only be (re)set via the
`bootstrap-admin` CLI tool or by a DB wipe.

**Risk.** Once the bootstrap escape hatch is removed, an operator who
loses the printed bootstrap password can't recover without DB access
or wiping. No password rotation discipline possible.

**Fix sketch.** `POST /auth/change-password` — authenticated, requires
old password, applies same bcrypt-cost-12 hashing, calls a new
`revokeAllSessionsExcept(currentSessionId)` to force re-login on other
clients. Frontend: "Change password" form in the user dropdown.
Validates new password against a minimum-length policy (≥12 chars).
No "reset by email" flow — that needs SMTP and is out of scope (see
notifications work in pending queue).

### 1.7 bcrypt cost factor — **P2, S**

**Current state.** `passwords.ts:ROUNDS = 12`. Reasonable for 2026 but
worth a periodic bump.

**Risk.** Low; with rate limiting in place (1.2) the cost factor matters
less. Mostly an audit checkbox.

**Fix sketch.** Bench bcrypt on the target Dokploy host. If a single
hash completes in <250 ms, bump to 13. Document the decision in
`docs/OPERATIONS.md` and the cost in a comment in `passwords.ts`.

---

## 2. Rate limiting

Covered above for `/auth/*` (P0). The remaining surface:

### 2.1 Scan-trigger endpoint — **P1, S**

**Current state.** `POST /api/scopes/:id/scan` and the equivalent
`/api/scans` trigger have no rate limit. A logged-in user (or bug) can
enqueue arbitrarily many scans; the worker concurrency of 1 means they
queue up but the BullMQ Redis state grows unboundedly and the UI shows
a confusing pending pile.

**Risk.** Self-DoS (queue blowup); cost (each scan can run claude-p at
$1–3 in LLM tokens). Internal user could deliberately or accidentally
burn through a budget.

**Fix sketch.** Rate-limit scan triggers to 10/min per user, 60/hour
per repo. Use `@fastify/rate-limit` keyed by `request.user?.id` (and
`request.params.id` for the per-repo cap). Same Redis backend as 1.2.

### 2.2 Pagination on list endpoints — **P1, M** (part of M5e)

**Current state.** `GET /scans`, `GET /admin/repos`, `GET /admin/credentials`
all return unbounded lists. M5e §1 enumerated this as a hardening item.

**Risk.** Frontend slow-down once scan history grows past a few hundred
entries; a 10k-row response is large enough to feel sluggish even on
a fast LAN.

**Fix sketch.** Per M5e: `?page=`/`?limit=` query params with
backend-enforced max. Frontend pagination controls on the lists.
Defaults: scans 50 (max 200), repos/credentials 100 (max 500).

---

## 3. Secrets & key material

### 3.1 Replace the placeholder `MASTER_KEY` in `.env.example` — **P0, S**

**Current state.** `.env.example` ships a literal 32-byte base64 value
(`NEEv6vwFIzi5U1VgMDWmCQB8AXOtjj9esL1E7BoiLf0=`). Anyone who copies the
example without regenerating has a known key — meaning their entire
encrypted credentials table is readable by anyone with the example file.

**Risk.** Direct credential disclosure if an operator copies the example
verbatim and adds real Bitbucket / LiteLLM secrets via the credentials
admin UI. The placeholder + leftover Docker volume is a footgun.

**Fix sketch.** Replace the value with a placeholder string that is
*not* valid base64 32 bytes (e.g. `__REPLACE_ME__`) plus a one-line
generation command:
```
# openssl rand -base64 32
MASTER_KEY=__REPLACE_ME__
```
The existing `loadConfig()` already aborts on invalid key, so the
operator gets a clear error if they forget. Same treatment for the
default `POSTGRES_PASSWORD=sastbot`.

### 3.2 `MASTER_KEY` rotation procedure — **P1, M**

**Current state.** `backend/src/security/crypto.ts` uses a hardcoded
`keyVersion: 1` everywhere credentials are written. The `keyVersion`
column on `encrypted_values` is reserved but no re-encryption code
exists. `docs/OPERATIONS.md` describes the rotation procedure
manually, step-by-step, but it references a one-shot re-encryption
script that does not exist.

**Risk.** If `MASTER_KEY` is suspected leaked (laptop loss, accidental
git commit, contractor handoff), there is no way to rotate without a
DB wipe + re-onboarding every repo and credential.

**Fix sketch.** Write `backend/src/cli/rotate-master-key.ts`:
1. Takes `OLD_MASTER_KEY` and `NEW_MASTER_KEY` env vars.
2. For each row in `encrypted_values`: decrypt with old key, re-encrypt
   with new key, bump `keyVersion`.
3. Update the canary row last (so a crash mid-rotation leaves a
   recoverable state — canary check fails with old key, succeeds with
   new key once the row flips).
4. Print a summary: rows rotated, rows unchanged.

Document in `OPERATIONS.md` alongside the existing rotation section.

### 3.3 Audit `.env.example` vs running config — **P0, S**

**Current state.** Survey turned up minor inconsistencies (a SQLAlchemy
`DATABASE_URL` comment from an older draft, no clear required/optional
markers). The example is mostly correct but not actively audited.

**Risk.** Operator confusion at deploy time; missing vars get filled
in incorrectly.

**Fix sketch.** Pass through `.env.example` line-by-line against
`config.ts`'s Zod schema. For each var: mark as required/optional,
list the failure mode if missing, ensure the comment matches the
loader's actual default. Add a `(REQUIRED)` / `(optional, default X)`
suffix to each var's comment.

### 3.4 LiteLLM / Anthropic API key handling — **P1, S**

**Current state.** The LLM endpoint base URL and API key are stored
as admin credentials in the `app_settings` table, encrypted with
`MASTER_KEY`. This is correct.

**Risk.** None at rest. At runtime the key is in process memory and
appears in claude-p subprocess env. Make sure it does *not* appear in
logs (see 7.2 redaction).

**Fix sketch.** Audit `llmClient.ts` and `llmSastService.ts` for any
log line that might include the key. Add `ANTHROPIC_API_KEY` and
`LITELLM_*` to the Pino redact paths.

---

## 4. Deployment topology & hardening

### 4.1 Compose target — switch from `dev` to `prod` for prod deploys — **P0, S**

**Current state.** `docker/compose/docker-compose.yml` builds all
services with `target: dev`. The prod stages in
`docker/backend.Dockerfile` and `docker/frontend.Dockerfile` are never
exercised. Dokploy will deploy whatever the compose file says.

**Risk.** Running `pnpm dev` (`tsx watch`) in prod means: file watching,
no compiled `dist/`, dev-only source-map exposure, dev-mode Vite on the
frontend serving unminified source. Big surface area, slow startup,
nonsensical resource use.

**Fix sketch.** Create `docker/compose/docker-compose.prod.yml` (or a
`compose.override.yml`-style overlay) that:
- Sets `target: prod` on backend, worker, frontend.
- Replaces dev `command:` overrides with prod CMDs.
- Adds `prisma migrate deploy` as a one-shot init container (or keeps
  it as a shell-wrap on the backend command but with stricter error
  handling — see 5.1).
- Drops the `5173:5173` port binding (Nginx serves the built bundle).

Document in `docs/DEPLOY_HOMELAB.md` which compose file Dokploy points
at.

### 4.2 Bind Postgres + Redis to `127.0.0.1` — **P0, S**

**Current state.** `docker-compose.yml` binds `5432:5432` and `6379:6379`
to `0.0.0.0`. On a homelab host with no firewall in front, both are
LAN-reachable. Postgres password is `sastbot` (default); Redis has no
auth at all.

**Risk.** A LAN attacker (or a misconfigured router) can connect to
Redis with no credentials and dump session tokens, BullMQ queue
contents, and rate-limit counters. Postgres is somewhat protected by
the default password but only by obscurity.

**Fix sketch.** In the prod compose file: drop the `ports:` block on
both Postgres and Redis entirely. They only need to be reachable
inside the compose network. If host access is needed for backups
(see 5.4), bind to `127.0.0.1:5432:5432` and document SSH-tunnel
usage.

### 4.3 Resource limits on every service — **P1, S**

**Current state.** No `deploy.resources`, `mem_limit`, or CPU quotas
anywhere in `docker-compose.yml`. A runaway claude-p subprocess or a
Prisma query pulling 50k rows can starve the host.

**Risk.** OOM kills the wrong process; one bad scan brings down the
backend. On a 16 GB homelab host this is realistic.

**Fix sketch.** Per-service limits (rough starting points; tune on
real workload):
- `postgres`: 2 GB mem, 2 CPU
- `redis`: 512 MB mem, 1 CPU
- `backend`: 1 GB mem, 1 CPU
- `worker`: 4 GB mem, 2 CPU (claude-p can use a lot)
- `frontend` (Nginx): 256 MB, 0.5 CPU

### 4.4 Healthchecks on backend, worker, frontend — **P1, S**

**Current state.** Only `postgres` and `redis` have `healthcheck:`
blocks. The compose `depends_on` correctly waits for those at startup,
but Docker/Dokploy can't tell when the app services are actually
healthy.

**Risk.** Dokploy reports "deployed" while the backend is still
booting; Traefik routes 502s. Stuck/hung worker doesn't auto-restart
because nothing detects the hang.

**Fix sketch.**
- Backend: `curl -fsS http://localhost:8000/healthz` (improved healthz
  per 7.4).
- Worker: simple sentinel — touch `/tmp/sastbot-worker-alive` from the
  BullMQ event loop on a 30s interval; healthcheck `test`s
  `find /tmp/sastbot-worker-alive -mmin -1`.
- Frontend (Nginx): `wget --spider http://localhost/`.

Set `interval: 30s, timeout: 5s, retries: 3, start_period: 60s` on each.

### 4.5 Run as non-root — **P1, M**

**Current state.** Backend Dockerfile runs every stage as root. The
`claudeuser` (uid 1001) exists only for the claude-p subprocess. The
prod Nginx stage also runs as root.

**Risk.** Container escape (theoretical) gains root on the host;
process-level CVEs in Node or Nginx land with full privileges.

**Fix sketch.** In `docker/backend.Dockerfile` prod stage: add a
`node` non-root user (Node images already include uid 1000), `chown`
the app dir, `USER node`, fix any file-permission fallout. The
`claudeuser` (for claude-p) is a separate concern — keep that
mechanism. In `docker/frontend.Dockerfile` prod stage: add `USER
nginx` after the configtest. Test the migration carefully — Nginx
PID file paths and Node `pnpm cache` will need permissions adjusted.

### 4.6 Frontend security headers — **P0 for prod deploy, S**

**Current state.** The prod Nginx config is 6 lines: serve static,
SPA fallback, port 80. No `X-Frame-Options`, no CSP, no
`X-Content-Type-Options`, no `Referrer-Policy`.

**Risk.** XSS (no CSP) and clickjacking (no `X-Frame-Options`) have
zero defense in depth. Behind Dokploy Traefik some of these may be
added at the proxy, but you can't rely on that.

**Fix sketch.** Inline a `nginx.conf` snippet on the prod stage:
```
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" always;
```
Tune CSP to allow whatever inline styles shadcn / Tailwind emit;
`'unsafe-inline'` for `style-src` is reasonable, never for `script-src`.
Verify in browser devtools.

### 4.7 `pnpm install --frozen-lockfile` fallback — **P1, S**

**Current state.** `docker/backend.Dockerfile` runs
`pnpm install --frozen-lockfile || pnpm install`. The fallback defeats
the integrity check it just enforced.

**Risk.** A drifted lockfile silently builds in CI/Dokploy with a
different dep tree than local — supply-chain blind spot.

**Fix sketch.** Drop the `|| pnpm install`. If `--frozen-lockfile`
fails on the build host, fix the lockfile commit, don't paper over.

### 4.8 CORS / `APP_ORIGIN` — **P0, S**

**Current state.** `server.ts:48–52` registers CORS with a single
origin string from `APP_ORIGIN` (default `http://localhost:5173`).
Correct posture; risk is purely operational — if Dokploy env isn't
updated, the deploy frontend can't talk to backend.

**Risk.** Easy to forget; produces a confusing browser error rather
than a hard backend failure.

**Fix sketch.** Add a startup log line printing the active
`APP_ORIGIN` so it's obvious in deploy logs. Add a checklist item to
`DEPLOY_HOMELAB.md`.

---

## 5. Database

### 5.1 Migrations in prod — **P0, S**

**Current state.** `prisma migrate deploy` runs only via the compose
`command:` override on the backend service:
```
command: ["sh", "-c", "pnpm prisma migrate deploy && pnpm dev"]
```
The prod Dockerfile CMD (`node dist/server.js`) has no migration step.
On compose restart, if migrate fails, the shell exits non-zero and
the container restarts — infinite loop on a bad migration with no
alert.

**Risk.** Botched migration → backend in restart loop → no logs reach
anyone unless the operator goes looking. Worker silently keeps running
on the old schema in the meantime.

**Fix sketch.** In the prod compose:
- Add a `migrate` one-shot service (same image, `command: ["pnpm",
  "prisma", "migrate", "deploy"]`, `restart: "no"`).
- Backend and worker `depends_on: migrate: { condition: service_completed_successfully }`.
- If migrate fails, backend and worker don't start (clean fail). Dokploy
  reports the migrate service failure.

### 5.2 Prisma connection pool sizing — **P1, S**

**Current state.** `backend/src/db.ts` instantiates `PrismaClient` with
no pool config. Default is `cpu_count * 2 + 1` per client. With backend
and worker each holding their own pool, total connections to Postgres
can exceed the default Postgres `max_connections = 100` on a CPU-rich
host.

**Risk.** Connection exhaustion under load. Errors look generic
("Can't reach database") and are hard to diagnose.

**Fix sketch.** Set `connection_limit` in the `DATABASE_URL` query
string explicitly. Starting point: backend `connection_limit=20`,
worker `connection_limit=10`. Document in `.env.example`.

### 5.3 Indexes on hot paths — **P1, S**

**Current state.** From the survey of `backend/prisma/schema.prisma`:

| Table | Existing indexes | Gap |
|---|---|---|
| `ScanRun` | `[scopeId, createdAt desc]`, `[repoId, createdAt desc]` | Good |
| `SastIssue` | `[scopeId, fingerprint]` unique, `[scopeId, triageStatus]`, `[scopeId, latestSeverity]`, `[jiraTicketId]` | Good |
| `ScaIssue` | `[scopeId, packageName, osvId]` unique, `[scopeId, latestSeverity]`, `[scopeId, dismissedStatus]`, `[jiraTicketId]` | Good |
| `SbomComponent` | `[scanRunId]` only | **Likely needs `(scanRunId, name)` and/or `(scanRunId, purl)`** — OSV lookup joins by these |
| `Repo` | `[orgId, url]` unique, `[isActive, scheduleCron]` | Good |
| `Session` | `tokenHash` unique only | **Missing `userId` index** — session-by-user lookups seq-scan |
| `ScanFinding` | `[scanRunId]` | **Missing `componentId`, `issueId` indexes** if these are used in joins |

**Risk.** Quiet — works fine on small datasets, degrades as scan
history grows. The Components tab will slow down once a repo has dozens
of scan runs.

**Fix sketch.** Add the missing indexes via a Prisma migration. Before
adding, run `EXPLAIN ANALYZE` on the actual queries (M5e §1 already
budgeted this work — see 9.2). Specifically check:
- The SCA issues list query (joined with `SbomComponent` for "Dev"
  badge and `evidence.occurrences`).
- The session-by-user lookup in the "Sign out everywhere" path.
- The OSV batch query's component join.

### 5.4 Backup / restore — **P0, M**

**Current state.** Nothing. `OPERATIONS.md` says "Out of scope for M2.
Revisit in M7." (line 151). No `pg_dump` script, no cron, no documented
procedure beyond "rely on the host's backup policy."

**Risk.** Existential. A botched migration, disk failure, or accidental
`docker compose down -v` wipes every scan, every credential, every
session, every Jira link mapping. Recovery is "rescan from scratch"
which takes hours and costs LLM tokens.

**Fix sketch.** Three pieces, increasing effort:

1. **One-shot backup script** (`backend/src/cli/backup-db.ts` or a
   `scripts/backup.sh`): `pg_dump | gzip > /backups/sastbot-$(date).sql.gz`
   plus rotation (keep last 7 daily, last 4 weekly). Document `pg_restore`
   procedure in `OPERATIONS.md`.
2. **Compose `backup` service** running on a cron schedule (BusyBox
   crond or a small Alpine container). Mounts a `/backups` volume.
   Dokploy host backs up the volume via its own mechanism.
3. **Pre-migration backup** — wrap `prisma migrate deploy` (5.1) with a
   `pg_dump` step first, named for the migration. Lets you `pg_restore`
   to the previous state if a migration corrupts data.

Tier (1) is P0. Tiers (2) and (3) are P1.

### 5.5 Cascade behavior — verify no surprises — **P2, S**

**Current state.** Per CLAUDE.md: "FK plumbing already in place — Repo →
ScanScope → SastIssue/ScaIssue all cascade." The Repo-delete cascade
preview UX is in the pending queue. Worth verifying the FK definitions
match the stated cascade behavior.

**Risk.** Operator deletes a repo expecting cascade and either leaves
orphan rows (FK = NoAction) or wipes more than expected.

**Fix sketch.** Read `schema.prisma`, list every `onDelete:` clause,
confirm against the documented intent. Add a comment block to
`OPERATIONS.md` summarizing.

---

## 6. Worker resilience

This entire section is mostly pulled from `project_pending_features.md`
(2026-05-07 entry on scan resilience) with current-state context added.

### 6.1 BullMQ default `lockDuration` vs long LLM scans — **P0, S**

**Current state.** `backend/src/worker.ts:877` creates a Worker with
only `{ connection: getRedis() }`. BullMQ defaults:
- `lockDuration: 30 000 ms` (30 sec)
- `stalledInterval: 30 000 ms`
- `maxStalledCount: 1` → job moves to `failed` after one stall

A single LLM-driven scan takes tens of minutes to hours. The 30s lock
**expires repeatedly during a normal scan**. BullMQ then either
extends it (if the worker is healthy and renewing) or moves the job to
"stalled" status. With `maxStalledCount: 1`, one stall sends it to
`failed`, and the worker doesn't know to clean up the in-flight
claude-p subprocess.

**Risk.** Scans that complete on the worker side may appear as
"stalled→failed" in BullMQ state; or, after a host pause (laptop
sleep), the lock expires and BullMQ marks the job dead even though
the worker resumes correctly.

**Fix sketch.** Set explicit options:
```ts
new Worker(SCAN_QUEUE_NAME, handler, {
  connection: getRedis(),
  lockDuration: 5 * 60 * 1000,     // 5 min
  stalledInterval: 60 * 1000,       // check once a minute
  maxStalledCount: 2,
  removeOnComplete: { count: 500 }, // keep last 500
  removeOnFail: { count: 200 },     // keep last 200 for forensics
  concurrency: parseInt(env.SCAN_WORKER_CONCURRENCY ?? "1", 10),
});
```
The `SCAN_WORKER_CONCURRENCY` knob is also part of M5e §1.

### 6.2 Wall-clock cap + heartbeat + retry — **P1, M**

**Current state.** Already documented in detail in
`project_pending_features.md` (the "Scan resilience" entry). Quoting the
key gaps:

- `spawnClaudeAndStream` in `llmSastService.ts:287` has no `timeout`
  option and no `AbortSignal`. A hung HTTPS stream to the LLM API can
  keep claude-p alive indefinitely.
- No heartbeat / staleness detection on the streaming JSONL parser.
- No retry-on-failure when exit code != 0 and zero records were
  persisted. The 2026-05-07 Gocator scan ate $2.15 and produced 0
  records; on a clean retry it would have completed.
- A scan that produced zero SAST records gets marked `success` if SCA
  completed, masking the failure in the UI.

**Fix sketch (per pending-features memory):**
1. Wall-clock cap on subprocess (60 min detection, 30 min recheck).
2. Heartbeat: kill subprocess if stdout silent for ≥5 min.
3. Retry once on `exitCode != 0 && recordCount == 0`.
4. Don't mark scan `success` when detection produced zero records but
   was expected to run; flag a typed `sast_detection_failed` warning
   (uses the M6i `hasErrorWarnings` gate).

Effort: ~half a day. See pending-features memory for context.

### 6.3 Surface unparseable LLM record details — **P2, S**

**Current state.** Worker stores only the `parseErrors.length` ("3
unparseable records") but throws away the `{raw, reason}` payloads.

**Risk.** Operator can't tell whether 3 real findings were silently
dropped or 3 stray chatter lines were ignored.

**Fix sketch.** Per pending-features memory: extend `ScanWarning` with
optional `details: unknown`, persist first 5 parse errors (cap each
`raw` to 2 KB), render in the warning expandable block. Effort: 25
min.

### 6.4 Within-phase progress streaming — **P2, M**

**Current state.** `llm_detection` and `llm_recheck` phases initialize
`setPhase` once at start (`done: 0`) and stay at 0 until phase end.
Visually indistinguishable from a hang.

**Risk.** Operator UX during long runs. Not a deploy blocker.

**Fix sketch.** Per pending-features memory: tap claude-p's incremental
`usage` events, bump `done = input_tokens + output_tokens`, throttle DB
writes to ≤ once / 5 sec. ~2–3 hours.

### 6.5 Graceful shutdown of in-flight scans — **P1, S**

**Current state.** `worker.ts` handles SIGTERM/SIGINT and calls
`worker.close()`. BullMQ waits for the current handler to finish — by
**default 5 seconds**. After that, the job stays marked active in
Redis with no handler to claim it.

**Risk.** Dokploy redeploy mid-scan: BullMQ marks the scan as stalled
(per 6.1's fix) and retries it on next worker boot — losing the
in-flight LLM work and burning tokens again.

**Fix sketch.** Two pieces:
- Pass `worker.close(false)` to allow the current job to finish *or*
  set a longer timeout. With the wall-clock cap from 6.2, this is
  bounded.
- On SIGTERM, set a "draining" flag — refuse new jobs even before
  close returns. Log the shutdown sequence at info level.

---

## 7. Observability

### 7.1 `/healthz` is non-functional — **P0, S**

**Current state.** `backend/src/routes/health.ts:13–24` returns
`{ status: "ok", version: "0.1.0" }` unconditionally. It does not
ping the DB or Redis. The Dokploy Traefik probe will succeed even
if Postgres is down.

**Risk.** Bad route from Dokploy's perspective; alerting on `/healthz`
is meaningless.

**Fix sketch.** Two endpoints:
- `/healthz` — liveness only. Stays as-is (process is responding).
  Used by Docker healthcheck per 4.4.
- `/readyz` — readiness. Pings Postgres via `prisma.$queryRaw\`SELECT 1\``
  and Redis via `redis.ping()`. Returns 503 with a JSON breakdown if
  either fails. Used by Traefik / monitoring.

### 7.2 Pino redaction — **P0, S**

**Current state.** Pino has no `redact` config. `authorization` and
`cookie` headers appear in request logs at `info` level. Session
tokens, LiteLLM API key (if passed as a bearer), and other secrets
end up in logs.

**Risk.** Logs ship to disk + (eventually) any aggregation system; any
operator with log access has session tokens for every active user.

**Fix sketch.** Configure Pino in both `server.ts` and `worker.ts`:
```ts
pino({
  level,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      'res.headers["set-cookie"]',
      '*.password',
      '*.secret',
      '*.apiKey',
      'env.ANTHROPIC_API_KEY',
      'env.MASTER_KEY',
    ],
    censor: '[REDACTED]',
  },
});
```
Verify with a manual `curl` and a check of the JSON log output.

### 7.3 Metrics endpoint — **P2, M**

**Current state.** None. No `prom-client`, no `/metrics`.

**Risk.** No visibility into long-term trends: scan duration
distribution, queue depth, LLM token spend over time, error rate.
Operationally fine for a single-operator deploy; mandatory once
multiple repos run on schedule.

**Fix sketch.** Add `prom-client`, expose `/metrics` on the backend
(bind to a separate internal port if exposing publicly is a concern).
Key metrics:
- `sastbot_scans_total{status}` counter
- `sastbot_scan_duration_seconds` histogram by phase
- `sastbot_llm_tokens_total{model, kind}` counter (input/output)
- `sastbot_queue_depth` gauge (BullMQ active/waiting/failed)
- `sastbot_http_requests_total{method, route, status}` (via
  `fastify-metrics` or hand-rolled)

Document Prometheus scrape config in `OPERATIONS.md`. Grafana
dashboard JSON checked into `docs/grafana/`.

### 7.4 Error tracking — **P2, S**

**Current state.** None. Errors hit stdout/stderr via Pino and the
operator notices when something fails.

**Risk.** Slow MTTR. Errors that don't kill the process (e.g. a
caught exception in a per-job handler) are invisible until the
operator scrolls logs.

**Fix sketch.** Either:
- **Sentry** (commercial / self-hosted) — `@sentry/node` for backend
  and worker, `@sentry/react` for frontend. Reasonable starter tier.
- **Plain webhook on unhandled exceptions** — POST to Google Chat /
  Slack via the notifications service (pending feature). Cheaper but
  less rich.

P2 because the notifications system in the pending queue covers most
of the "tell me when something breaks" need.

### 7.5 On-call escalation — **P1, S** (mostly doc work)

**Current state.** None. Single-operator deploy means *you* are
on-call by default. No SLA, no escalation path.

**Risk.** When the system grows past one operator, "who pages whom"
is undefined.

**Fix sketch.** Add an `On-call & escalation` section to
`OPERATIONS.md`: primary contact, what each severity level means,
"how do I know it's broken" (UI banner / health endpoint / Dokploy
status), and rough SLA expectations ("scan completion within X hours,
service uptime targeted at Y%").

---

## 8. Tests & CI

### 8.1 Test coverage — current state — **(informational)**

- Backend: 8 test files in `backend/tests/`. Coverage: security
  primitives (crypto, passwords), config validation, git clone logic,
  SBOM post-processing, OSV service. **No route tests. No service
  integration tests for auth, sessions, or scan orchestration.**
- Frontend: 1 smoke test (`frontend/tests/smoke.test.tsx`). No
  component tests.
- No e2e tests anywhere.

### 8.2 Auth & session route tests — **P1, M**

**Current state.** No tests exercise `POST /auth/login`, the session
cookie path, `requireAdmin`/`authenticate` middleware, or
`bootstrap`. Hand-tested only.

**Risk.** Regressions on the auth surface are silent. A change to the
cookie flag (1.5) or the session rotation (1.3) can ship broken.

**Fix sketch.** Integration tests against a real Fastify instance +
Prisma + test Postgres (vitest `beforeAll` spawning a container or
re-using `docker compose exec`). Cover:
- Login success / wrong password / unknown email
- Session resolves authenticated requests
- Session expiry returns 401
- Logout revokes
- Rate limit (once 1.2 ships) returns 429
- Bootstrap creates exactly one admin

### 8.3 Worker / scan-orchestration tests — **P2, L**

**Current state.** No tests on `worker.ts`, `llmSastService.ts`,
`sbomService.persistComponents`, or `osvService.queryBatch`. These
are the riskiest code paths and the most expensive to debug
post-deploy.

**Risk.** A change to canonical-name handling (CLAUDE.md mentions
this is fragile) or the dev-only-component classifier silently
breaks scan output.

**Fix sketch.** Mock the LLM (stub claude-p with a fixture stream).
Test the full orchestration: ingest a fixture SBOM, run the
augmentation pass, query OSV (recorded fixtures via VCR/Polly-style),
verify the DB state after.

### 8.4 CI pipeline — **P1, M**

**Current state.** None. No `.github/workflows/`, no
`bitbucket-pipelines.yml`. Per the LMI conventions memory, the
target Bitbucket instance has no Pipelines support.

**Risk.** Lint / typecheck / test never run unless the operator
remembers. PR review (when the project moves to a shared repo) has
nothing to gate on.

**Fix sketch.** Two options, ship the cheaper one first:

- **(a) Local pre-push git hook.** Husky runs
  `pnpm -C backend lint && pnpm -C backend typecheck && pnpm -C backend test`
  and the frontend equivalents before push. Free, manual.
- **(b) GitHub Actions** workflow (the repo was on personal GitHub at
  the time per `reference_deployment.md`).
  Standard Node 20 matrix, run lint + typecheck + tests on PR. Free
  for public repos; private repo gets generous free minutes.

Ship (a) first; revisit (b) once the repo is hosted publicly or on
a CI-enabled forge.

---

## 9. Approved-but-unshipped milestones

Pulled from `project_pending_features.md`. These are not new work —
they're already specced. Including them here so the prod-ready plan
is complete.

### 9.1 M5d — Scheduled scans — **P2, L**

Per the pending-features memory:
- New `backend/src/scheduler.ts` process.
- BullMQ repeat jobs (`sastbot-scan-tick` every 60s,
  `sastbot-jira-sync` every 5 min).
- `schedulerService.reconcileSchedules()`.
- Frontend: cron preset dropdown on repo edit form.
- Dep: `cron-parser`.

**Production-readiness relevance.** Scheduling is *the* feature that
makes SASTBot a service rather than a manual tool. Without it,
operators run scans by hand. Not a deploy blocker; needed before the
notifications work (pending queue) is meaningful.

### 9.2 M5e — Operational hardening — **P1, L**

Per the pending-features memory, M5e bundles:
- `@fastify/rate-limit` on `/auth/login` + `/auth/logout` — **already
  surfaced as 1.2 / P0**; ship it now, don't wait for the full
  bundle.
- Pagination on `/scans`, `/admin/repos`, `/admin/credentials` — **9.2
  / P1** (also 2.2).
- `SCAN_WORKER_CONCURRENCY` env var — **already needed for 6.1**.
- `EXPLAIN ANALYZE` on 4 key queries — **already needed for 5.3**.

Effectively, M5e's work is folded into items above. Don't treat M5e
as a separate milestone; treat the individual items as P0/P1 as
ordered.

### 9.3 Bootstrap escape-hatch removal — **P0, S** (= 1.1)

Already covered in 1.1.

### 9.4 Scan resilience — **P1, M** (= 6.1 + 6.2)

Already covered in 6.1 and 6.2.

### 9.5 Notifications — **P2, XL**

Per the pending-features memory: depends on M5d. Multi-channel (email,
webhook), Google Chat is the primary target. Needs SMTP config or
webhook-only.

**Production-readiness relevance.** "Tell me when a scheduled scan
finds something new" is the operator's compensating control for not
manually triggering. Not a P0 deploy blocker, but the first thing the
operator will ask for after scheduled scans land.

### 9.6 Dashboard merge + "Open findings" finish — **P2, M**

Per the pending-features memory. `/dashboard` has a placeholder "after
M3" section that was never completed; merge into `/scopes` header band.
Not a deploy blocker.

---

## 10. Documentation & runbook

### 10.1 `docs/OPERATIONS.md` gaps — **P1, M**

Per the survey, OPERATIONS.md covers bootstrap, logs, build scripts,
master-key rotation (partial — references a script that doesn't exist),
prisma migrations, disaster-recovery table, backfills, Jira setup, git
errors, scan-path config, cancel-scan behavior.

**Missing for on-call (in priority order):**

1. **Backup / restore procedure** — concrete `pg_dump` / `pg_restore`
   commands, retention policy, verification. P0, lands with 5.4.
2. **Master-key rotation script** — referenced but doesn't exist. P1,
   lands with 3.2.
3. **Incident response / severity triage** — what counts as P0/P1/P2,
   who acts, expected response time. P1, doc-only.
4. **Log access in production** — how to tail Pino JSON, how to
   `jq` for a specific scan_run_id, how to access Dokploy logs vs.
   container logs. P1, doc-only.
5. **Redis queue inspection** — how to list pending / active /
   stalled / failed BullMQ jobs, how to retry a failed job, how to
   drain the queue. P2, doc-only.
6. **Health endpoint usage** — once 7.1 ships, how to interpret
   `/healthz` vs `/readyz` responses, what 503 fields mean. P1, doc-only.
7. **Common-failure remediation** — extend the existing disaster-recovery
   table with: claude-p hang, OSV outage, LiteLLM endpoint unreachable,
   Dokploy redeploy mid-scan, full DB disk. P1, doc-only.

### 10.2 `README.md` — add a Deploy section — **P2, S**

**Current state.** README is dev-only quick-start, no deploy section.

**Fix sketch.** One-paragraph "Deploying to production" pointing to
`docs/DEPLOY_HOMELAB.md` (personal) and a (yet-to-write) generic
`docs/DEPLOY.md` that documents the prod compose file (4.1) and the
required env vars (3.3).

### 10.3 `DEPLOY_HOMELAB.md` — keep current — **P1, S**

**Current state.** Exists and is gitignored per
`reference_deployment.md`. Carries the homelab IP and webhook URL.

**Fix sketch.** As prod items ship, add a per-fix entry: which env
vars to update, what to check after redeploy. Treat it as a personal
deploy diary.

---

## Suggested sequencing

Not a commitment — just one defensible order if the operator wants
to ship in tiers.

### Tier 1 (deploy-blocker batch, ~2 days)

Everything tagged **P0**. In order:

1. 3.1 — Replace placeholder MASTER_KEY in `.env.example` (15 min)
2. 1.1 — Remove or hard-guard `BOOTSTRAP_ADMIN_PASSWORD` (1 hr)
3. 1.5 — Force `SESSION_COOKIE_SECURE` in prod (30 min)
4. 4.2 — Bind Postgres/Redis to 127.0.0.1 (15 min)
5. 4.6 — Frontend security headers (1 hr)
6. 7.2 — Pino redaction (1 hr)
7. 7.1 — Real `/healthz` + new `/readyz` (1 hr)
8. 4.1 — Prod compose target + Dockerfile prod stage (half day)
9. 5.1 — Migrations as one-shot service in prod compose (1 hr)
10. 4.8 — Log `APP_ORIGIN` at boot + deploy checklist (15 min)
11. 5.4 (tier 1) — pg_dump backup script + restore doc (half day)
12. 1.2 — `@fastify/rate-limit` on auth routes (1 hr)
13. 3.3 — Audit `.env.example` against config.ts (30 min)
14. 6.1 — Explicit BullMQ Worker options (15 min)

### Tier 2 (shared-deploy batch, ~3–4 days)

Everything tagged **P1**.

15. 1.3 / 1.4 / 1.6 — Session rotation + failed-login logging +
    password change route (half day each)
16. 2.1 / 2.2 — Scan-trigger rate limit + list pagination (half day each)
17. 4.3 / 4.4 / 4.5 — Resource limits + healthchecks + non-root
    containers (half day total)
18. 4.7 — Drop pnpm install fallback (15 min)
19. 5.2 / 5.3 — Pool sizing + missing indexes (after EXPLAIN ANALYZE)
    (half day)
20. 5.4 (tier 2/3) — Backup service + pre-migration backup (half day)
21. 6.2 — Wall-clock cap + heartbeat + retry on claude-p (half day)
22. 6.5 — Graceful shutdown verification (1 hr)
23. 3.2 — Master-key rotation script (half day)
24. 3.4 — Audit LLM key handling in logs (1 hr)
25. 7.5 / 10.1 — On-call doc + operations runbook gaps (half day each)
26. 8.2 — Auth route integration tests (half day)
27. 8.4 — Husky pre-push hook (1 hr)

### Tier 3 (first-month-of-operation batch)

Everything tagged **P2**.

28. M5d scheduler (1 day) — 9.1
29. Notifications (2–3 days) — 9.5
30. Metrics endpoint + Grafana (half day) — 7.3
31. Error tracking (Sentry-or-webhook) — 7.4
32. Within-phase progress streaming — 6.4
33. Surface parse errors on warnings — 6.3
34. Dashboard merge — 9.6
35. Worker / scan-orchestration tests — 8.3
36. bcrypt cost bump after benchmarking — 1.7
37. Cascade behavior audit — 5.5
38. README deploy section — 10.2

---

## Out of scope (explicitly not part of M7)

- **OSV C/C++ coverage gap** (mentioned in 2026-05-12 PROGRESS.md
  addendum). It's a real gap but it's a feature improvement, not a
  prod-readiness blocker. Track separately.
- **Multi-tenancy.** The schema is multi-tenant-ready (`org_id`
  scoping), but actual tenant isolation, per-tenant secrets, and the
  admin UI to create new orgs are unbuilt. Out of scope unless the
  deploy actually serves multiple tenants.
- **OIDC / SSO integration.** `authBackend` is pluggable for this
  reason; adding an OIDC backend is real work and only matters once
  shared with a team that has SSO.
- **Frontend bundle hardening** beyond CSP — Subresource Integrity,
  bundle splitting, etc. Track as a later perf/security pass.
- **Cost-tracking dashboard / LLM spend budgets.** Token totals are
  already persisted per scan but no per-org budget or alerting is
  wired. Worth doing after metrics (7.3) lands.
