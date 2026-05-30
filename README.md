# SASTBot

LLM-augmented SAST/SCA tool for EU Cyber Resilience Act (CRA) compliance.

SASTBot scans git repositories for security issues using:

- **SCA** (Software Composition Analysis) — CycloneDX 1.7 SBOM via cdxgen, CVE/EOL/deprecated checks via OSV.dev and endoflife.date, CVSS v3.1 + v4.0 base-score calculation from advisory vectors
- **SAST** (Static Application Security Testing) — LLM-driven detection (claude-p agentic pass) with `still_present` recheck verification across scans; worker-built ±3-line code-context snippets read directly from the source file
- **SARIF export** — every scan emits a SARIF v2.1.0 document (CWE references via the spec-idiomatic taxonomies / relationships idiom) viewable in-app and downloadable for hand-off to dashboards, CI gates, or compliance evidence collection
- **Issue identity** — stable Issue rows (not per-scan findings) so triage decisions, Jira links, and status survive repeated scans
- **LLM-augmented summaries** — every issue has a one-line action-oriented summary generated from the rule/advisory text, populated on scan and via worker-startup backfill
- **Reachability analysis** — for CVE issues at the configured severity threshold, ripgrep + LLM confirm whether the vulnerable function is actually called from your code; verdicts include confidence + call-site code blocks, with one-click "Mark Invalid" / "Won't fix" suggestions for high-confidence "not reachable" results
- **Jira read-only sync** — link Jira ticket keys to issues; SASTBot pulls status, resolution, assignee, and fix versions from Jira Cloud (linking auto-transitions pending/To do issues to Planned)
- **Scope-centric views** — `/scopes` landing page with stacked severity bar, per-issue status workflow (pending → To do → planned → fixed), shareable issue links, clickable file paths to your repo browser via per-repo URL template
- **Configurable scan paths** — multiple scan paths per repo become independent scopes; nested overlaps are de-duplicated automatically; per-repo `ignore_paths` skip vendored or generated subtrees

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
git clone https://bitbucket.org/<your-workspace>/sastbot.git
cd sastbot
cp .env.example .env   # generate a fresh MASTER_KEY (see .env.example)
docker compose -f docker/compose/docker-compose.yml --env-file .env up --build
```

> **Note:** `--env-file .env` is required because the compose file lives in `docker/compose/` and Compose resolves `.env` relative to that directory, not the repo root.

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
│   └── OPERATIONS.md        # ops/runbook
├── CLAUDE.md                # contributor + AI-agent guide
└── README.md
```

## User documentation

The complete operator manual lives at [`docs/user-manual/`](docs/user-manual/) —
section-per-feature markdown (quick start, scanning, SCA/SAST triage, components
& SBOM, Jira, and the admin sections: credentials, settings, **configuration**,
backup & restore, versioning, deployment, troubleshooting).

The **same manual is browsable inside the running app** at `/manual` (no login
required), where it also renders a live API reference from the backend's OpenAPI
schema. The on-disk files under `docs/user-manual/` are the source of truth; the
frontend build syncs them into the SPA at build time.

## Versioning — read before cutting a release

SASTBot tracks **two** versions, both surfaced at `GET /version` and in the admin Settings footer:

| Version | Source | When it changes |
|---------|--------|------------------|
| **App version** (SemVer) | `backend/package.json` AND `frontend/package.json` (must match) | **Manual bump** in a dedicated commit. Currently `0.16.0`. PATCH for bug fixes, MINOR for backwards-compatible features, MAJOR reserved for post-1.0 breaking changes. |
| **DB schema version** | Latest folder in `backend/prisma/migrations/` (also recorded in the `_prisma_migrations` table) | **Automatic** — running `pnpm prisma migrate dev --name …` produces the new folder. Commit it; that IS the bump. |

The backup tarball produced by `GET /admin/db/backup` embeds both versions. The restore endpoint compares them to the running backend and either restores as-is, auto-migrates forward, or refuses (newer-than-running). Bumping the app version when shipping a schema or operator-visible change is what makes cross-version restore safe — don't skip it.

Contributors and AI agents: see the prominent **⚠️ Versioning policy** section near the top of [`CLAUDE.md`](CLAUDE.md) for the full rules and the exact order of operations for combined schema + feature changes.

## Configuration

All configuration flows through environment variables, an optional YAML file, or CLI arguments (see [docs/user-manual/admin-configuration.md](docs/user-manual/admin-configuration.md), also at `/manual/admin-configuration` in-app, for the full reference and precedence rules). The admin UI persists runtime settings (Jira, LLM gateway, etc.) in the Postgres `app_settings` table; credentials are AES-256-GCM encrypted at rest using `MASTER_KEY`.

## Development

See [`CLAUDE.md`](CLAUDE.md) for detailed developer and AI-agent guidance, including how to run tests, regenerate the frontend OpenAPI types, add Prisma migrations, and bootstrap a local admin.

## Milestones

Progress is tracked in [`docs/PROGRESS.md`](docs/PROGRESS.md). The project has shipped through **M14 / v0.16.0**. Key milestones:

- **M1–M3** ✓ Auth, admin UI, encrypted credentials, deployable stack, SCA pipeline (cdxgen + OSV.dev + findings UI)
- **M4–M5** ✓ SAST pipeline (LLM-driven, no Opengrep), reachability analysis, issue identity, scope-centric views, Jira read-only sync
- **M6** ✓ Full LLM-mode SAST (claude-p agentic detection + recheck); Opengrep removed; SARIF v2.1.0 export; LLM SBOM augmentation pass
- **M7** ✓ Two-table component model (`sbom_components` + `scope_components`); deterministic component matcher; operator component edits
- **M8–M10** ✓ Artifact store (per-scan SBOM + SARIF files), scan-detail improvements, backup/restore v2 with version-aware migration
- **M11–M14** ✓ Scope-component evidence snippets, dismissed-status lifecycle hardening (`not_found`, `ignored`), operator-visible UX polish; current release v0.16.0

## Security

SASTBot handles sensitive credentials (Git tokens, LLM API keys, Jira tokens). Key principles:

- All credentials are AES-256-GCM encrypted in Postgres; the master key lives only in the `MASTER_KEY` env var.
- The backend refuses to start if `MASTER_KEY` is missing, the wrong length, or cannot decrypt the canary row.
- Passwords are bcrypt-hashed. Sessions are server-side (DB-backed) so logout/revoke works.
- **Never commit a real `.env` file.** A committed `.env.example` documents the variables.

Security issues? Open a private advisory on the GitHub repo.

## License

TBD (likely Apache 2.0 — confirm before public release).
