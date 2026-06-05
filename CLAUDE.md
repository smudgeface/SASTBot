# CLAUDE.md — Contributor & AI-agent guide

This file is the lean entry point for humans and AI agents contributing to SASTBot. It
covers the dev workflow, versioning policy, and conventions. **Deeper material lives in
`docs/` — start at [`docs/README.md`](docs/README.md) for the documentation map, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for subsystem notes & invariants.**

## TL;DR

```bash
cp .env.example .env                                           # once
docker compose -f docker/compose/docker-compose.yml --env-file .env up --build # bring up all services
```

Then:
- Frontend: <http://localhost:5173>
- Backend: <http://localhost:8000> (OpenAPI at `/docs`, schema at `/openapi.json`)
- Postgres: `localhost:5432` (user `sastbot`, password `sastbot`, db `sastbot`)
- Redis: `localhost:6379`

First boot creates no admin — open the frontend and complete the first-run setup screen (`/setup`) to create your administrator account (or restore a backup to migrate). The dev-only `BOOTSTRAP_ADMIN_PASSWORD` env var still auto-creates the admin and skips setup for local iteration (rejected under `NODE_ENV=production`).

**User management (M17) + roles (M18).** Local accounts are managed under `/admin/users` (`routes/adminUsers.ts` → `services/userService.ts`); self-service password change is `POST /auth/change-password`. Two invariants are enforced in `userService` (advisory-locked, NOT just the UI): never leave **zero active admins** (demote/disable/delete of the last admin → 409) and **no self-lockout** (an admin can't change their own role/active or delete themselves). Admin-created/reset accounts get `mustChangePassword=true`; `plugins/auth.ts` blocks them (403 `password_change_required`) from everything except change-password/logout/me until they change it. When adding any path that mutates users/roles, keep both invariants. OIDC/Google-Workspace SSO is the planned Phase 2 — the `AuthBackend` interface in `security/authBackend.ts` is the hook.

**Three roles — privilege ladder `user < member < admin` (M18).** `plugins/auth.ts` exposes `authenticate` < `requireMember` < `requireAdmin` (a single `ROLE_RANK` table; unrecognized DB role values rank as `user` — fail closed). **`user`** reads everything + adds notes. **`member`** also works the triage queue — the 11 finding/Jira/component mutations in `routes/scopes.ts` (SAST triage, SCA dismiss, Jira link/unlink/refresh, component edit/delete/ignore/unignore) are `requireMember`. **`admin`** also owns all configuration (`admin*` routes) and scan control (`scans.ts` cancel/delete, `adminRepos` scan-trigger) — those stay `requireAdmin`. The last-admin invariant counts `role==="admin"` only, so a `member` never satisfies it (demoting the last admin → member is rejected). `role` is free TEXT (no CHECK constraint, no migration). **Gotcha:** `services/mappers.ts` `userToOut`/`userToAdminOut` MUST pass the real role through `normalizeRole` — they once collapsed any non-admin to `user`, which breaks `/auth/me` serialization for a member. Frontend gates the same split via `lib/permissions.ts` (`canModifyFindings` = admin|member, `canAdminister` = admin). When adding a finding-state mutation, gate it `requireMember`; a config/scan mutation, `requireAdmin`.

## ⚠️ Versioning policy — READ BEFORE TOUCHING SCHEMA OR CUTTING A RELEASE

Two versions matter, and they have different rules:

### 1. App version — SemVer, manual bump

- **Runtime single source of truth:** the `APP_VERSION` constant in `backend/src/routes/version.ts`. Every runtime version surface (`GET /version`, `GET /healthz`, the OpenAPI `info.version`, the SARIF tool version) imports from here. **Do not** hardcode a version string anywhere else in `backend/src/` or `frontend/src/`.
- **Three files must move together every bump** (drift causes operators to see lying version numbers — historically this has bitten us at every minor bump):
  1. `backend/package.json` `version` field
  2. `frontend/package.json` `version` field (+ `frontend/package-lock.json` top-level `version` if `npm install` won't run cleanly — pnpm-lock.yaml has no version field)
  3. `backend/src/routes/version.ts` `APP_VERSION` constant
- **Current baseline:** `0.16.0` (pre-1.0 — API is still evolving).
- **When to bump:**
  | Change | Bump |
  |---|---|
  | Bug fix, doc tweak, internal refactor with no operator-visible effect | PATCH (`0.16.0 → 0.16.1`) |
  | New backwards-compatible feature: new endpoint, new optional field, new admin UI, new env knob | MINOR (`0.16.0 → 0.17.0`) |
  | Breaking API change, schema migration that destroys data, removed feature, changed default behaviour | MAJOR (pre-1.0 still warrants a MINOR bump until we declare 1.0; reserve MAJOR for the 1.0+ era) |
- **How to bump:** edit all three files above, run `pnpm install` / `npm install` to refresh lockfiles, commit as `chore: bump version to vX.Y.Z` (or fold into the feature commit that justified the bump). Verify with `curl -s http://localhost:8000/version | jq .app` after restart — if it shows the old value, the running process didn't pick up `APP_VERSION` (restart again).
- **Surfaces:** `GET /version` (public), `GET /healthz`, OpenAPI `info.version` at `/openapi.json` / `/docs`, SARIF `tool.driver.version`, admin Settings page footer.
- **Spawning an agent that ships a feature?** Add an explicit "bump version (all three files: package.json ×2 + `APP_VERSION` in `backend/src/routes/version.ts`)" line to the brief. Agents have missed `APP_VERSION` even when the brief lists the two package.jsons.

### 2. DB schema version — Prisma-derived, automatic

- **Single source of truth:** the lexicographically-last folder under `backend/prisma/migrations/`. That folder name (e.g. `20260528173420_rename_include_dev_deps`) IS the schema version.
- **No manual bump.** When you run `pnpm prisma migrate dev --name describe_change`, a new timestamped folder appears. Commit it. That's the bump.
- **The `_prisma_migrations` table** in the live DB records what's actually been applied. `GET /version` reports both `schema` (applied) and `expected_schema` (what the code expects); a mismatch is rendered amber in the UI.
- **Always commit the migration folder** generated by `prisma migrate dev`. A schema change in `schema.prisma` without a committed migration folder is a bug — the next deploy will fail or, worse, silently diverge.

### When making a change that touches both — the order that matters

Before writing any migration, work through `docs/MIGRATIONS_CHECKLIST.md` — it covers renames, NOT NULL on populated tables, big-table locking, JSON shape changes, and the worker-backfill contract.

1. Edit `prisma/schema.prisma`.
2. `pnpm prisma migrate dev --name describe_change` → generates migration folder.
3. Implement the feature using the new schema.
4. **If the feature is operator-visible, bump app version** (both `package.json` files) in the same commit or an adjacent one.
5. `docs/PROGRESS.md` entry mentions the version bump and the migration name.

### Backup/restore depends on this

The backup tarball (`GET /admin/db/backup`) embeds both versions in `metadata.json`. The restore endpoint (`POST /admin/db/restore`) compares the dump's `schema_version` to the running app's `expected_schema_version`:

- equal → restore as-is
- dump older → restore + auto-run `prisma migrate deploy`
- dump newer → **refuse with HTTP 422**

A wrong schema-version bump breaks cross-version restore — operators can't migrate forward from a backup they made yesterday.

See `docs/user-manual/admin-versioning.md` (also at `/manual/admin-versioning` in-app) for the operator-facing version of this policy.

## Tech stack

| Concern | Choice |
|---------|--------|
| Backend | Node.js 20, TypeScript (strict, ESM), Fastify, Zod (validation + OpenAPI) |
| DB / ORM | Postgres 16 + Prisma (+ `prisma migrate` for schema changes) |
| Auth | `bcrypt`, DB-backed session cookies, pluggable auth backend (OIDC-ready) |
| Crypto | Node's built-in `crypto` module, AES-256-GCM per-value with master key from `MASTER_KEY` |
| Workers | BullMQ on Redis (same image as the backend; different command) |
| Frontend | React 18, Vite, TypeScript, Tailwind, shadcn/ui, TanStack Query, Zustand |
| Types | Shared surface via `@fastify/swagger` → `/openapi.json` → frontend can run `npx openapi-typescript` |
| Package manager | `pnpm` (backend) and `npm` (frontend) |
| Tests | `vitest` on both sides |
| Jira | Read-only Jira Cloud integration. Link issue keys; pull status/resolution/assignee/fix-versions. No ticket creation. |

## Repository layout

```
SASTBot/
├── backend/                     # Node.js + Fastify + Prisma
│   ├── package.json
│   ├── tsconfig.json
│   ├── tsconfig.build.json
│   ├── prisma/
│   │   ├── schema.prisma
│   │   └── migrations/          # generated by `prisma migrate dev`
│   ├── prompts/                 # M6: sast_system.md, sast_detection.md, sast_recheck.md
│   └── src/
│       ├── server.ts            # Fastify app entrypoint
│       ├── worker.ts            # BullMQ worker entrypoint
│       ├── config.ts            # Zod-validated env
│       ├── db.ts                # Prisma singleton
│       ├── security/
│       │   ├── crypto.ts        # AES-GCM + canary
│       │   ├── passwords.ts     # bcrypt wrapper
│       │   ├── sessions.ts      # DB-backed session tokens
│       │   └── authBackend.ts   # pluggable auth interface
│       ├── plugins/auth.ts      # Fastify auth plugin (authenticate, requireMember, requireAdmin)
│       ├── routes/              # health, auth, adminRepos, adminSettings, adminCredentials, scans, scopes (M5)
│       ├── services/            # repoService, settingsService, credentialService, issueService,
│       │                        #   jiraClient, jiraTicketService, sbomService, osvService, bootstrap,
│       │                        #   reachabilityService, cveKnowledgeService, llmClient,
│       │                        #   llmSastService (M6 — claude-p orchestrator),
│       │                        #   promptLoader (M6 — text-file prompt loader),
│       │                        #   cvss4 (CVSS v4.0 macro-vector calculator)
│       ├── queue/               # BullMQ queue + connection
│       └── cli/                 # bootstrap-admin, dry-run-llm-sast (M6),
│                                 #   probe-claude-structured-output (M13 — claude CLI behaviour probe)
├── frontend/                    # React + Vite + TypeScript
│   ├── package.json
│   ├── vite.config.ts           # proxies /auth /admin /scans /healthz to backend:8000
│   └── src/                     # routes, components/ui (shadcn), api/queries, stores
├── docker/
│   ├── compose/
│   │   └── docker-compose.yml
│   ├── backend.Dockerfile       # Node 20 multi-stage (dev/build/prod)
│   └── frontend.Dockerfile      # Vite dev / Nginx prod
├── docs/
│   ├── README.md                # documentation map — START HERE
│   ├── ARCHITECTURE.md          # subsystem notes & invariants
│   ├── PROGRESS.md              # milestone log (chronological)
│   ├── SCAN_LIFECYCLE.md        # scan-run state machine
│   ├── MIGRATIONS_CHECKLIST.md  # pre-migration checklist
│   ├── OPERATIONS.md            # ops runbook
│   ├── DEPLOY_PROXMOX.md        # current prod deploy guide
│   ├── user-manual/             # operator manual (synced into the SPA)
│   └── memory/                  # completed milestone plans & historical records
├── .env.example
├── .gitignore
├── CLAUDE.md                    # this file
└── README.md
```

## Common tasks

### Run backend tests
```bash
docker compose -f docker/compose/docker-compose.yml exec backend pnpm test
```

### Run frontend tests
```bash
docker compose -f docker/compose/docker-compose.yml exec frontend npm test
```

### Create a new Prisma migration
```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate dev --name describe_change
```
Commit the generated `prisma/migrations/<timestamp>_describe_change/` folder.

### Apply migrations manually
The backend runs `prisma migrate deploy` as part of its startup command in compose. To invoke by hand:
```bash
docker compose -f docker/compose/docker-compose.yml exec backend pnpm prisma migrate deploy
```

### Regenerate Prisma client after schema edits
```bash
docker compose -f docker/compose/docker-compose.yml exec backend pnpm prisma generate
```
Restart the backend afterwards.

### Regenerate frontend OpenAPI types
Backend must be running:
```bash
cd frontend
npm run gen:types
```
Writes to `frontend/src/api/schema.d.ts`. Commit the result.

### Create a bootstrap admin manually
```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm run bootstrap-admin --email you@example.com
```
Prints a random password to stdout.

### Bring up / tear down
```bash
docker compose -f docker/compose/docker-compose.yml --env-file .env up --build  # up
docker compose -f docker/compose/docker-compose.yml down             # stop
docker compose -f docker/compose/docker-compose.yml down -v          # stop AND wipe postgres volume
```

## Conventions

### Backend
- **Async/await everywhere.** No callbacks, no `.then()` chains.
- **Zod schemas are the single source of truth** for request + response shapes. Register them with `fastify-type-provider-zod` so `@fastify/swagger` emits them into `/openapi.json`.
- **Services wrap Prisma.** Routes call services; services own the transaction boundary (`prisma.$transaction` when multiple writes need to be atomic, e.g. repo + inline credential).
- **Secrets as references.** Credentials are rows in `credentials`; other tables (`repos`, `app_settings`) reference them by ID. Never inline ciphertext in `repos` or `app_settings`.
- **Fail fast on startup.** `server.ts` calls `ensureCanary()` before `listen()` — a bad `MASTER_KEY` aborts boot with a clear error.
- **Multi-tenant ready.** Every domain table has an `org_id`. M1 seeds a single `default` org; all data scoped to it. Use the `orgId` helper from the auth plugin — don't hardcode.
- **No `any`** outside clearly marked boundary adapters. Derive types with `z.infer`.
- **All domain routes live under `/api/*`** with bare paths in route files; `server.ts` adds the prefix. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#routing--request-conventions) for the full routing convention.

### Frontend
- **Server state via TanStack Query.** Every API call has a typed hook under `src/api/queries/`.
- **Client state via Zustand.** Only for UI state (theme, snapshot of current user). Never duplicate server state in Zustand.
- **shadcn/ui as the base.** Components are copied into `src/components/ui/`. Customize freely; no runtime package to pin.
- **Types come from backend.** Don't hand-write API response types — regenerate via `npm run gen:types`.

### Docs
- **[`docs/README.md`](docs/README.md) is the documentation map.** Living docs stay at the top of `docs/`; completed milestone plans and historical records go under `docs/memory/` (move them there with `git mv` when the work ships).
- **README.md stays generic.** No personal IPs, hostnames, or credentials. This repo will migrate to the user's work environment.
- **Homelab/Dokploy specifics** go in gitignored docs (`docs/DEPLOY_HOMELAB.md`, `docs/DEPLOY_DOKPLOY_*.md`) — they're personal-infra-only and never enter the tracked tree.
- **PROGRESS.md is chronological.** One entry per milestone, dated, with "what shipped" and "what we learned". It's the raw material for a final presentation.

## For AI agents

**Start here:** [`docs/README.md`](docs/README.md) maps the whole `docs/` tree.
Deep subsystem knowledge and hard-won invariants live in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — read the relevant note **before** changing
scan-pipeline, SCA/SBOM, SAST, component-model, or routing code. Most notes encode a bug we
already paid for once.

- **Orient in ≤3 tool calls:** `git log --oneline -10`, `tail -40 docs/PROGRESS.md`, `docker compose ps`. `docs/PROGRESS.md` holds the current milestone and what was learned.
- **🔖 Versioning is not optional.** Before adding a schema migration → confirm the migration folder is committed (that IS the schema version). Before cutting a release or shipping an operator-visible change → bump **all three** version surfaces in one commit: `backend/package.json`, `frontend/package.json`, and `APP_VERSION` in `backend/src/routes/version.ts`. Agents have repeatedly missed `APP_VERSION`. After bumping, `curl -s http://localhost:8000/version | jq .app` must show the new value. See the "⚠️ Versioning policy" section above.
- **📖 Keep the user manual current.** When a code change is operator-visible (new screen, changed flow, new env var, new endpoint, new admin action) update the matching section under `docs/user-manual/` (the canonical source of truth; the frontend build syncs it into the SPA via `frontend/scripts/sync-manual.mjs` on `predev`/`prebuild`). Manual drift is a worse bug than a stub manual — users will follow stale instructions and assume the app is broken. Sections live one-per-file; the manifest (slug/title/group) is `frontend/src/manual/index.ts` — **adding a new page means a new `.md` under `docs/user-manual/` AND a manifest entry**. After shipping, browser-test the affected section at `/manual/<slug>`. The protocol-reference page is automatic (driven by `/openapi.json`), but the `tags` / `summary` / `description` you put on Fastify routes ARE the protocol doc — keep them accurate.
- Never commit real secrets. `.env` is gitignored; `.env.example` is the canonical source of variable names.
- The canonical remote is **LMI Bitbucket Cloud** (`origin`); a secondary GitHub mirror also exists under the `github` remote. The exact workspace/project and both remote URLs are kept in local agent memory, **not in-repo**. Never push to any remote without explicit user approval.
- **Keep LMI-internal and personal details out of the tracked tree entirely** — the public GitHub mirror would expose them. No Bitbucket workspace/project identifiers, no internal IPs/hostnames (internal git servers, LLM gateways), no personal homelab IPs. Real values live in local agent memory or gitignored docs (`docs/DEPLOY_HOMELAB.md`).
- When running commands that touch Docker, use `docker compose -f docker/compose/docker-compose.yml …` — there's no compose file at the repo root by design.
- **Diagnostic CLIs** for probing LLM/scan behaviour without burning a full scan are under `backend/src/cli/` — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#diagnostic-clis).

### Model selection and context management

SASTBot is a long-running project. Use Claude models deliberately to keep costs reasonable.

**Model tiers:**

| Model | When to use |
|-------|-------------|
| **Opus** | Architecture decisions, milestone planning, novel debugging, security-sensitive code review, the first pass on a milestone where choices compound. Use it for judgment, not bulk. |
| **Sonnet** | The default for implementation work once direction is set: writing routes, services, Zod schemas, UI forms, wiring tests. ~5× cheaper than Opus with equivalent coding quality. |
| **Haiku** | Trivial edits, renames, doc tweaks, running existing scripts, formatting. |

Switch with `/model claude-sonnet-4-6` (or `haiku` / `opus`).

**Rule of thumb:** when the conversation shifts from *"what should we do"* to *"do this"*, drop down a tier.

**Sub-agents:** when spawning an `Agent`, pass `model: "sonnet"` explicitly unless the task is genuinely novel design — sub-agents otherwise inherit the parent's model and Opus sub-agents are expensive for mechanical work.

**Context management — when to `/clear`:**

- Clear at natural milestone boundaries (after a commit + push, once PROGRESS.md is updated).
- Before clearing, ensure the next session can re-orient in ~3 tool calls: `git log --oneline -10`, `cat docs/PROGRESS.md`, check MEMORY.md.
- Do **not** clear mid-debug or with uncommitted state.
- After a clear, open on Sonnet; switch to Opus only for the plan phase.

**Habits that keep costs low:**

- Commit + push frequently. Every commit is a clean resumption point.
- Keep `docs/PROGRESS.md` current — it is the written-down compression of context that survives a session clear.
- Prefer `curl`-level verification over Chrome DevTools QA when there are no UI changes; snapshots and screenshots are token-heavy.
- Avoid long pauses mid-session: the Anthropic prompt cache TTL is 5 minutes. A break under 5 min keeps the cache warm (cheap resume); over 5 min forces a full re-read.

## Environment variables

See `.env.example` for the authoritative list. Required:

| Variable | Purpose |
|----------|---------|
| `MASTER_KEY` | 32-byte base64-encoded key for AES-GCM credential encryption. Backend refuses to start if missing/invalid. |
| `DATABASE_URL` | Postgres URL (`postgresql://…`). Compose sets this automatically from the `POSTGRES_*` vars. |
| `REDIS_URL` | BullMQ broker. Compose sets this automatically. |
| `SESSION_COOKIE_SECURE` | `true` in prod, `false` in local dev. |
| `APP_ORIGIN` | Allowed CORS origin for the frontend (defaults to `http://localhost:5173` in dev). |
| `BOOTSTRAP_ADMIN_EMAIL` | Optional. Default `admin@sastbot.local`. |
| `PORT` | Optional. Default `8000`. |
