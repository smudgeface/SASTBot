# SASTBot

LLM-augmented SAST/SCA tool for EU Cyber Resilience Act (CRA) compliance.

SASTBot scans git repositories for security issues using:

- **SCA** (Software Composition Analysis) — dependency extraction, CycloneDX 1.7 SBOM generation, CVE/EOL/deprecated checks via OSV.dev and endoflife.date
- **SAST** (Static Application Security Testing) — [Opengrep](https://opengrep.dev/) with LLM-augmented triage, reachability analysis, and code context
- **Issue identity** — stable Issue rows (not per-scan findings) so triage decisions, Jira links, and status survive repeated scans
- **Jira read-only sync** — link Jira ticket keys to issues; SASTBot pulls status, resolution, assignee, and fix versions from Jira Cloud
- **Scope-centric views** — `/scopes` landing page with severity breakdown, per-issue status workflow (pending → To do → planned → fixed), shareable issue links

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend  │────▶│   Backend   │────▶│  Postgres   │
│  React/Vite │     │   Fastify   │     │             │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐     ┌─────────────┐
                    │    Redis    │────▶│   Workers   │
                    │  (BullMQ)   │     │  Node/TS    │
                    └─────────────┘     └──────┬──────┘
                                               │
                                               ▼
                                        ┌─────────────┐
                                        │  LiteLLM    │
                                        │   gateway   │
                                        └─────────────┘
```

## Quick start (local)

Prerequisites: Docker Desktop (or any engine with Compose v2).

```bash
git clone https://github.com/smudgeface/SASTBot.git
cd SASTBot
cp .env.example .env   # generate a fresh MASTER_KEY (see .env.example)
docker compose -f docker/compose/docker-compose.yml up --build
```

On first boot the backend seeds the default org and prints a bootstrap admin password to the container logs. Log in at <http://localhost:5173> with `admin@sastbot.local` and the printed password, then change it via the admin UI.

| Service | URL |
|---------|-----|
| Frontend | <http://localhost:5173> |
| Backend API | <http://localhost:8000> |
| OpenAPI docs | <http://localhost:8000/docs> |
| OpenAPI schema | <http://localhost:8000/openapi.json> |

## Repository layout

```
SASTBot/
├── backend/                 # Node.js + TypeScript + Fastify + Prisma + BullMQ
├── frontend/                # React + Vite + TypeScript
├── docker/
│   └── compose/             # docker-compose.yml for dev & deploy
├── docs/
│   ├── PROGRESS.md          # milestone log
│   ├── OPERATIONS.md        # ops/runbook
│   └── M5_PLAN.md           # M5 implementation plan (phases 5a–5f)
├── CLAUDE.md                # contributor + AI-agent guide
└── README.md
```

## Configuration

All configuration flows through environment variables (see `.env.example`). The admin UI persists runtime settings (Jira, LLM gateway, etc.) in the Postgres `app_settings` table; credentials are AES-256-GCM encrypted at rest using `MASTER_KEY`.

## Development

See [`CLAUDE.md`](CLAUDE.md) for detailed developer and AI-agent guidance, including how to run tests, regenerate the frontend OpenAPI types, add Prisma migrations, and bootstrap a local admin.

## Milestones

Progress is tracked in [`docs/PROGRESS.md`](docs/PROGRESS.md). Rough roadmap:

1. **M1 — Skeleton** ✓ auth, admin UI, repo CRUD, encrypted credentials
2. **M2 — CI + BullMQ + deploy** ✓ deployable stack, scan pipeline plumbing
3. **M3 — SCA vertical slice** ✓ cdxgen + OSV.dev + findings UI
4. **M4 — SAST vertical slice** ✓ Opengrep + LLM triage + reachability
5. **M5 — Issue identity + scope UX + Jira** ✓ stable issue model, scope-centric views, Jira read-only sync, status lifecycle
6. **M5d — Scheduled scans** ⬜ BullMQ cron, scheduler process, UI preset + preview
7. **M5e — Operational hardening** ⬜ rate limiting, pagination audit, worker concurrency
8. **M6 — API hardening + CRA exports** ⬜ API keys, audit log, CRA bundle
9. **M7 — Scheduling + ops polish** ⬜

## Security

SASTBot handles sensitive credentials (Git tokens, LLM API keys, Jira tokens). Key principles:

- All credentials are AES-256-GCM encrypted in Postgres; the master key lives only in the `MASTER_KEY` env var.
- The backend refuses to start if `MASTER_KEY` is missing, the wrong length, or cannot decrypt the canary row.
- Passwords are bcrypt-hashed. Sessions are server-side (DB-backed) so logout/revoke works.
- **Never commit a real `.env` file.** A committed `.env.example` documents the variables.

Security issues? Open a private advisory on the GitHub repo.

## License

TBD (likely Apache 2.0 — confirm before public release).
