# SASTBot — Development Progress Log

Chronological record of milestones. Each entry is dated and covers two things: **what shipped** and **what we learned**. Raw material for the eventual project presentation.

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

**Next — M3: SCA vertical slice**
Real git clone using the stored credentials. cdxgen (Node, in-process) produces a CycloneDX 1.7 SBOM. Persist components + versions + PURLs + licenses. Call OSV.dev for CVE matches. Findings UI (list + detail). SBOM download as JSON. Verify against a repo with known-vulnerable deps.
