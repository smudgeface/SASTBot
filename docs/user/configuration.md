# SASTBot configuration

SASTBot reads configuration from three sources, merged in this precedence order
(lowest → highest priority, so a higher-priority source overrides a lower one):

| Priority | Source | Key format |
|----------|--------|-----------|
| 1 (lowest) | Environment variables | `SCREAMING_SNAKE_CASE` (e.g. `MASTER_KEY`) |
| 2 | YAML config file | `snake_case` (e.g. `master_key`) |
| 3 (highest) | CLI arguments | `--kebab-case` (e.g. `--master-key=...`) |

All three forms normalise to the same canonical key internally before validation,
so it is safe to mix sources — set secrets in the environment and override
non-secret tunables via YAML or CLI without repeating yourself.

## YAML config file

Point SASTBot at a YAML file by setting the `SASTBOT_CONFIG_FILE` environment
variable. If that variable is unset, SASTBot searches these locations in order
and uses the first file it finds:

1. `/etc/sastbot/config.yaml` (production convention)
2. `backend/config.local.yaml` in the repo root (dev convenience)

A missing file is silently skipped. A file that exists but cannot be parsed
aborts startup with a clear error message.

Both `/etc/sastbot/config.yaml` and `backend/config.local.yaml` are gitignored
and must never be committed.

## Worked example

The same `redis_url` setting expressed in each form:

**Environment variable**

```bash
export REDIS_URL=redis://redis:6379/0
```

**YAML config file** (`backend/config.local.yaml` or `/etc/sastbot/config.yaml`)

```yaml
redis_url: "redis://redis:6379/0"
```

**CLI argument**

```bash
node dist/server.js --redis-url=redis://redis:6379/0
# or
node dist/server.js --redis-url redis://redis:6379/0
```

All three are equivalent. If all three are present, the CLI value wins.

## Configuration keys

### Required

| Key (env form) | YAML form | CLI form | Description |
|----------------|-----------|----------|-------------|
| `MASTER_KEY` | `master_key` | `--master-key` | Base64-encoded 32-byte AES-GCM master key. Generate with: `python3 -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"`. The backend refuses to start if this is missing, wrong length, or cannot decrypt the canary row. |
| `DATABASE_URL` | `database_url` | `--database-url` | Postgres connection URL (`postgresql://user:pass@host:5432/db`). Can be composed automatically from the `POSTGRES_*` variables when running under Docker Compose. |

### Optional — with defaults

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `REDIS_URL` | `redis_url` | `--redis-url` | `redis://redis:6379/0` | BullMQ broker URL. |
| `APP_ORIGIN` | `app_origin` | `--app-origin` | `http://localhost:5173` | CORS allowed origin for the frontend. Set to your deploy URL in production. |
| `SESSION_COOKIE_SECURE` | `session_cookie_secure` | `--session-cookie-secure` | `false` | Mark session cookies as `Secure` (HTTPS only). Set `true` in production. Accepts `true`, `1`, `yes`, `on` (and lowercase variants). |
| `BOOTSTRAP_ADMIN_EMAIL` | `bootstrap_admin_email` | `--bootstrap-admin-email` | `admin@sastbot.local` | Email address for the bootstrap admin account created on first boot. |
| `LOG_LEVEL` | `log_level` | `--log-level` | `info` | Pino log level. One of `trace`, `debug`, `info`, `warn`, `error`, `fatal`. |
| `PORT` | `port` | `--port` | `8000` | TCP port the backend listens on. |
| `CLONE_CACHE_DIR` | `clone_cache_dir` | `--clone-cache-dir` | `/app/clones` | Directory where the worker keeps retained per-repo git clones between scans. In Docker Compose this is a named volume shared between the `backend` and `worker` services. |

### Auth rate-limiting

`/auth/login` and `/auth/logout` are protected by a per-IP sliding-window
rate limiter (Redis-backed). When a client exceeds the limit, the backend
returns HTTP 429 with a `Retry-After` header. The login UI renders a countdown
and blocks the submit button for the duration.

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `AUTH_RATE_LIMIT_MAX` | `auth_rate_limit_max` | `--auth-rate-limit-max` | `10` | Maximum requests to `/auth/login` or `/auth/logout` per IP per window before returning HTTP 429. |
| `AUTH_RATE_LIMIT_WINDOW_MS` | `auth_rate_limit_window_ms` | `--auth-rate-limit-window-ms` | `60000` | Length of the rate-limit sliding window in milliseconds. Default is 60 000 ms (1 minute). |

The limiter uses Redis so limits survive backend process restarts. If Redis is
unreachable, the limiter falls back to in-memory counting for the current
process lifetime — no one is locked out by a Redis outage.

If you are running SASTBot behind a reverse proxy (nginx, Traefik, etc.), verify
that `X-Forwarded-For` is being forwarded correctly. The backend sets
`trustProxy: true` in Fastify, so it reads the client IP from that header.
Confirm your proxy is not forwarding a stale or attacker-controlled value.

### Dev-only (remove before production)

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `BOOTSTRAP_ADMIN_PASSWORD` | `bootstrap_admin_password` | `--bootstrap-admin-password` | _(unset)_ | When set, the bootstrap admin is created with this exact password instead of a random one. Convenient when iterating with `docker compose down -v`. **Setting this key when `NODE_ENV=production` is a hard boot-time config error** — the backend refuses to start and prints: `BOOTSTRAP_ADMIN_PASSWORD must not be set in production (NODE_ENV=production). Remove it from your environment or config file.` This makes it impossible to accidentally ship the dev escape hatch to a shared deployment. |

### Docker Compose convenience variables

These are consumed by `docker-compose.yml` and the `DATABASE_URL` composer; they
are not validated by the Zod schema directly.

| Variable | Description |
|----------|-------------|
| `POSTGRES_USER` | Compose + database URL composer. |
| `POSTGRES_PASSWORD` | Compose + database URL composer. |
| `POSTGRES_DB` | Compose + database URL composer. |
| `POSTGRES_HOST` | Database URL composer (default port `5432`). |
| `POSTGRES_PORT` | Database URL composer (default `5432`). |
| `SASTBOT_CONFIG_FILE` | Path to the YAML config file. Overrides the default search path. |

## Database backup

SASTBot provides an admin-only endpoint (`GET /admin/db/backup`) that streams a
full database backup as an HTTP download. The backup is triggered from the
**Settings** page in the admin UI via the "Download backup" button.

### Backup format

The download is a `tar.gz` archive (`.tar.gz`) containing exactly two files:

| File | Description |
|------|-------------|
| `dump.pgcustom` | A `pg_dump --format=custom --compress=9` snapshot of the database. |
| `metadata.json` | Version metadata: `app_version`, `schema_version`, `expected_schema_version`, `exported_at`, `sastbot_dump_format_version`. |

The filename is `sastbot-backup-<UTC-timestamp>-<schema-short>.tar.gz` where
`<schema-short>` is the first 14 characters of the schema version (the
`YYYYMMDDHHMMSS` timestamp prefix of the latest Prisma migration).

Inspecting a backup from the command line:

```bash
tar -tzf backup.tar.gz                       # list contents
tar -xzOf backup.tar.gz metadata.json | jq   # inspect metadata
```

### How it works

1. `pg_dump --format=custom --compress=9 --file dump.pgcustom` writes the dump
   to a temp dir inside the backend container.
2. `metadata.json` is written to the same temp dir.
3. `tar -czf - -C <tmpdir> dump.pgcustom metadata.json` streams the archive into
   the HTTP response. The response header is `Content-Type: application/gzip`.
4. The temp dir is removed on completion (or error).

The connection password is passed via the `PGPASSWORD` environment variable
(never via command-line arguments, which would be visible in process listings).

### Requirements

The backend image includes `postgresql-client-16` (installed from the
PostgreSQL APT repository to match the Postgres 16 server version in compose)
and the standard `tar` utility. No additional configuration is needed.

### No configurable knobs

There are currently no environment variables for the backup endpoint.

---

## Database restore

SASTBot provides an admin-only endpoint (`POST /admin/db/restore`) that accepts
a backup upload and restores it into the application database. The restore
operation is available from the **Settings** page in the admin UI, below the
"Download backup" button.

### Supported input formats

| Format | Detection | Notes |
|--------|-----------|-------|
| SASTBot tarball (`.tar.gz`) | Gzip magic bytes `0x1f 0x8b` | Preferred. Contains version metadata for automatic migration-forward. |
| Legacy raw dump (`.dump`) | `PGDMP` ASCII magic | Restores unconditionally; no version checks. |

The backend auto-detects the format from the first 4 bytes of the uploaded file.

### Tarball restore workflow

1. The upload is streamed to a temp file in `/tmp`.
2. The tarball is extracted; only `dump.pgcustom` and `metadata.json` are
   allowed (path-traversal defence).
3. `metadata.json` is read and validated. If it is missing or malformed the
   restore continues with a warning (treated as legacy).
4. The dump's `schema_version` is compared to the running backend's
   `expected_schema_version`:

   | Comparison | Action |
   |---|---|
   | Equal | Restore as-is. |
   | Dump is **older** | Restore, then run `prisma migrate deploy` automatically. |
   | Dump is **newer** | **Refused** (HTTP 422) — upgrade the backend first. |

5. `pg_restore --clean --if-exists --no-owner --no-privileges` runs against
   `DATABASE_URL`.
6. If the dump was older: `prisma migrate deploy` runs in the same process.
   If migration fails, HTTP 500 is returned with the Prisma stderr — the DB is
   in a partially-migrated state and temp files are retained for inspection.
7. On full success: temp files are deleted, the backend responds
   `{ ok: true, restarting: true, migrations_applied: [...] }`, and calls
   `process.exit(0)` so Docker's restart policy brings it back up.

### Legacy `.dump` restore

Restore proceeds unconditionally. The response includes a `migration_warning`
noting that no version metadata was present — inspect the DB state after restart.

### Confirmation UI

The Settings page enforces a two-step confirmation:

1. Select a `.tar.gz` or `.dump` file from disk.
2. Click **Restore…** to open a confirmation dialog.
3. Type `RESTORE` exactly in the confirmation field to enable the button.
4. Click **Restore database** to begin the upload.

After the upload completes, the page enters a "Backend is restarting…" state and
polls `/healthz` every 2 seconds. When the backend responds with HTTP 200, the
page reloads automatically. If migrations were applied, the migration names are
listed in the restarting banner.

### Worker container restart

The worker container shares the same database but runs as a separate process.
It is **not** signalled by the restore — its existing database connections will
become stale. After a restore completes, restart the worker manually:

```bash
docker compose -f docker/compose/docker-compose.yml restart worker
```

### Command-line restore (outside the UI)

Extract the dump from the tarball, then restore:

```bash
tar -xzf sastbot-backup-*.tar.gz             # extracts dump.pgcustom + metadata.json
pg_restore --clean --if-exists --no-owner --no-privileges \
  -d "postgresql://sastbot:sastbot@localhost:5432/sastbot" \
  dump.pgcustom

# Then restart the backend and worker:
docker compose -f docker/compose/docker-compose.yml restart backend worker
```

If the dump is from an older schema version, also run:

```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate deploy
```

### Configurable knobs

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `DB_RESTORE_MAX_BYTES` | `db_restore_max_bytes` | `--db-restore-max-bytes` | `2147483648` (2 GiB) | Maximum allowed size for a restore upload. Uploads exceeding this limit are rejected with HTTP 413 before they land on disk. Raise this if you have a database larger than 2 GiB. |

### Requirements

Same as the backup endpoint — `postgresql-client-16` and `tar` must be installed
in the backend image (both are present by default).

### Worker concurrency

| Key (env form) | YAML form | CLI form | Default | Max | Description |
|----------------|-----------|----------|---------|-----|-------------|
| `SCAN_WORKER_CONCURRENCY` | `scan_worker_concurrency` | `--scan-worker-concurrency` | `2` | `4` | Number of BullMQ scan jobs the worker processes in parallel. Each concurrent scan consumes a process slot on the worker host and forks a `claude -p` subprocess. Increase cautiously — the bottleneck is typically LLM throughput and host memory, not CPU. Hard-capped at 4. |

### API pagination

The following endpoints support server-side pagination via query parameters.
When `page` or `page_size` is omitted, the default applies.

| Endpoint | Default `page_size` | Max `page_size` | Notes |
|----------|---------------------|-----------------|-------|
| `GET /scans` | 50 | 200 | Sorted newest-first (`created_at DESC`). |
| `GET /admin/repos` | 100 | 500 | Sorted by repo creation order. |
| `GET /admin/credentials` | 100 | 500 | |

All three return a paginated envelope:

```json
{
  "items": [ … ],
  "total": 42,
  "page": 1,
  "page_size": 50
}
```

**Query parameters**:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `page` | integer ≥ 1 | `1` | Page number (1-based). Requesting a page beyond the last page returns an empty `items` array (not an error). |
| `page_size` | integer ≥ 1 | endpoint default | Number of items per page. Capped at the endpoint maximum. |

Example:
```
GET /scans?page=2&page_size=20
```
Returns items 21–40, sorted newest-first.

### LLM subprocess watchdog timers (scan resilience)

SASTBot enforces two independent watchdogs on every `claude -p` subprocess to
protect against runaway or hung scans.

**Wall-clock cap**: if the subprocess runs longer than the configured limit, it
receives SIGTERM; if it has not exited after 5 seconds it receives SIGKILL.

**Stdout staleness**: if no stdout chunk arrives from the subprocess within the
configured window, the subprocess is killed in the same way.

Both watchdogs emit an `error`-severity scan warning (`llm_sast_detection_failed`
or `llm_recheck_failed`) so the scan is visible as degraded in the UI and
remediation logic is gated off. The existing SAST/SCA findings from prior scans
are preserved.

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `CLAUDE_DETECTION_TIMEOUT_MS` | `claude_detection_timeout_ms` | `--claude-detection-timeout-ms` | `3600000` (60 min) | Wall-clock cap on the `claude -p` SAST detection subprocess. On timeout: SIGTERM, 5 s grace, then SIGKILL. Raise this for very large monorepos that legitimately need more than an hour. The original GoWeb scan ran 6 h 37 m before failing — this cap is a safety net, not the primary stop signal (the token-budget `--effort` flag stops the model first on healthy runs). |
| `CLAUDE_RECHECK_TIMEOUT_MS` | `claude_recheck_timeout_ms` | `--claude-recheck-timeout-ms` | `1800000` (30 min) | Wall-clock cap on the `claude -p` recheck subprocess. Recheck is a narrower pass than detection and rarely needs more than 30 minutes. |
| `CLAUDE_STDOUT_STALENESS_MS` | `claude_stdout_staleness_ms` | `--claude-stdout-staleness-ms` | `300000` (5 min) | Kill the subprocess if no stdout chunk arrives for this many milliseconds. Guards against a hung LLM endpoint that has accepted the TCP connection but stopped producing data. 5 minutes is generous for a healthy endpoint; lower it (e.g. to 60 000) in environments where endpoint hangs are frequent and fast recovery is preferred over waiting. |

### Retry on subprocess failure

When a `claude -p` subprocess exits with a non-zero code **and** produced no
records at all (not even a `complete` record), SASTBot automatically retries
**once** using the same prompts and the same full token budget:

- A fresh `$HOME` tmpdir is created for the retry so no state from the first
  attempt can interfere.
- An `info`-severity warning (`llm_sast_detection_retry` or
  `llm_recheck_retry`) is emitted documenting that the retry occurred and that
  both attempts consumed tokens.

**Doubled-spend risk**: if the first attempt consumed tokens before crashing
(e.g. mid-run OOM), the operator may be billed for both runs. The retry warning
includes an explicit note about this. The retry is not performed if the
subprocess was killed by SASTBot's own watchdog timers (timeout or staleness) —
those indicate the endpoint is likely still problematic and a retry would just
repeat the hang.

## Validation errors

If a required key is missing or a value is invalid, the backend (and worker)
abort immediately at startup with a message like:

```
ConfigError: Invalid configuration:
  - MASTER_KEY: MASTER_KEY is required (base64 of 32 bytes)

Sources checked: env vars, YAML file, CLI args.
```

The error message names the failing key and the constraint that was violated.
Check all three sources (env, YAML file, CLI) before concluding the key is truly
absent.

## Per-repo LLM token budgets

Each repository can override the default token budget for the four LLM phases
that consume Claude Code CLI tokens. These are DB-level settings configured via
the **Edit repository** dialog in the admin UI (the "Token budgets" collapsible
section, just below "LLM effort").

| Field | Phase | System default |
|-------|-------|---------------|
| SBOM augmentation | `llm_sbom` — LLM SBOM curation: adds vendored libs cdxgen missed, drops first-party noise | 200 000 |
| SBOM recheck | `llm_sbom_recheck` — confirms previously-known components still present after a new scan | 50 000 |
| SAST detection | `llm_detection` — open-ended agentic SAST pass | 300 000 |
| SAST recheck | `llm_recheck` — narrow per-issue recheck for findings not re-emitted in the latest scan | 50 000 |

**When to override:**

- **Raise** the SAST detection budget for large monorepos where Claude Code
  needs more exploration budget (e.g. large C++ repos with many translation units).
- **Lower** the SAST detection budget on trivially small repos to cap cost — the
  default 300k is rarely consumed on such repos.
- **Raise** the SBOM augmentation budget on repos with unusually large vendored
  directories (deep `extern/` trees with dozens of third-party libs).
- The recheck budgets rarely need adjustment.

**Behaviour:** the live-progress bar in the Scopes list and Scope detail page
shows tokens consumed vs. the budget (`done / total tokens (max)`). The budget
is a cap, not a target — the LLM stops when it reaches it. If a scan
consistently hits the cap, raise it.

**NULL = system default.** Clearing a budget field (empty input in the dialog)
resets it to NULL, which causes the worker to use the compiled-in default on the
next scan. Budgets are per-repo only — there is no per-org override.
