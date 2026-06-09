# Admin: configuration

This is the full reference for every configuration key SASTBot accepts at
startup. Runtime settings managed through the admin UI (Jira, LLM gateway,
per-repo options) are documented in [Settings page](admin-settings) and
[Repositories](repositories); this page covers the **boot-time** configuration
read by the backend and worker.

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
aborts startup with a clear error message. Both paths are gitignored and must
never be committed.

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
| `AUTH_RATE_LIMIT_WINDOW_MS` | `auth_rate_limit_window_ms` | `--auth-rate-limit-window-ms` | `60000` | Length of the rate-limit sliding window in milliseconds (default 60 000 ms = 1 minute). |

The limiter uses Redis so limits survive backend process restarts. If Redis is
unreachable, it falls back to in-memory counting for the current process
lifetime — no one is locked out by a Redis outage. Behind a reverse proxy
(nginx, Traefik, etc.), verify `X-Forwarded-For` is forwarded correctly: the
backend sets `trustProxy: true` and reads the client IP from that header.

### Dev-only (remove before production)

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `BOOTSTRAP_ADMIN_PASSWORD` | `bootstrap_admin_password` | `--bootstrap-admin-password` | _(unset)_ | When set, the bootstrap admin is created with this exact password instead of a random one. Convenient when iterating with `docker compose down -v`. **Setting this key when `NODE_ENV=production` is a hard boot-time config error** — the backend refuses to start. This makes it impossible to accidentally ship the dev escape hatch to a shared deployment. |

### Docker Compose convenience variables

These are consumed by `docker-compose.yml` and the `DATABASE_URL` composer; they
are not validated by the Zod schema directly.

| Variable | Description |
|----------|-------------|
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | Compose + database URL composer. |
| `POSTGRES_HOST` / `POSTGRES_PORT` | Database URL composer (default `5432`). |
| `SASTBOT_CONFIG_FILE` | Path to the YAML config file. Overrides the default search path. |

### Worker concurrency

| Key (env form) | YAML form | CLI form | Default | Max | Description |
|----------------|-----------|----------|---------|-----|-------------|
| `SCAN_WORKER_CONCURRENCY` | `scan_worker_concurrency` | `--scan-worker-concurrency` | `2` | `4` | Number of BullMQ scan jobs the worker processes in parallel. Each concurrent scan consumes a process slot and forks a `claude -p` subprocess. Increase cautiously — the bottleneck is typically LLM throughput and host memory. Hard-capped at 4. |

### LLM subprocess watchdog timers (scan resilience)

SASTBot enforces two independent watchdogs on every `claude -p` subprocess to
protect against runaway or hung scans. **Wall-clock cap:** if the subprocess
runs longer than the limit it gets SIGTERM, then SIGKILL after 5 s.
**Stdout staleness:** if no stdout chunk arrives within the window, the
subprocess is killed the same way. Both emit an `error`-severity scan warning so
the scan is marked degraded and remediation logic is gated off; prior findings
are preserved.

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `CLAUDE_DETECTION_TIMEOUT_MS` | `claude_detection_timeout_ms` | `--claude-detection-timeout-ms` | `3600000` (60 min) | Wall-clock cap on the SAST detection subprocess. Raise for very large monorepos. The model normally self-paces and stops first; this is the runaway safety net. |
| `CLAUDE_RECHECK_TIMEOUT_MS` | `claude_recheck_timeout_ms` | `--claude-recheck-timeout-ms` | `1800000` (30 min) | Wall-clock cap on the recheck subprocess (a narrower pass than detection). |
| `CLAUDE_STDOUT_STALENESS_MS` | `claude_stdout_staleness_ms` | `--claude-stdout-staleness-ms` | `300000` (5 min) | Kill the subprocess if no stdout arrives for this many ms. Guards against an endpoint that accepted the connection but stopped producing data. |

On a non-zero exit **with no records produced**, SASTBot retries **once** with a
fresh `$HOME` tmpdir and the same budget, emitting an `info` warning (note: both
attempts consume tokens). It does **not** retry if its own watchdog killed the
subprocess (the endpoint is likely still unhealthy).

### Backup & restore knobs

The backup/restore **workflow** (UI steps, formats, version-aware migration) is
documented in [Backup & restore](admin-backup-restore). The only configurable
knob is the restore upload size limit:

| Key (env form) | YAML form | CLI form | Default | Description |
|----------------|-----------|----------|---------|-------------|
| `DB_RESTORE_MAX_BYTES` | `db_restore_max_bytes` | `--db-restore-max-bytes` | `2147483648` (2 GiB) | Maximum allowed size for a restore upload. Larger uploads are rejected with HTTP 413 before landing on disk. Raise this if your database exceeds 2 GiB. |

The backend image includes `postgresql-client-16` (matched to the Postgres 16
server) and `tar`; no extra configuration is required for backup or restore.

### API pagination

`GET /scans` (default page size 50, max 200), `GET /admin/repos` and
`GET /admin/credentials` (default 100, max 500) support `page` (≥ 1) and
`page_size` query parameters and return a `{ items, total, page, page_size }`
envelope. Omitting the params applies the defaults; a page beyond the last
returns an empty `items` array (not an error).

## LLM pacing (no token budgets)

There are no per-repo token budgets (removed in v0.25.0). Token counts on this
setup do not predict cost, so a token "budget" was not a meaningful cost control.
Instead, each LLM pass **self-paces** — the model decides when it has covered the
work — and the **wall-clock cap** (`CLAUDE_DETECTION_TIMEOUT_MS`, default 60 min)
is the runaway backstop. During a scan, the LLM phases report **live token
counts** (input / output / cache-hit / cache-new) as the progress signal rather
than a percentage-of-budget bar. Per-repo `--effort` still tunes how hard the
detection and recheck passes work.

## Validation errors

If a required key is missing or a value is invalid, the backend (and worker)
abort immediately at startup:

```
ConfigError: Invalid configuration:
  - MASTER_KEY: MASTER_KEY is required (base64 of 32 bytes)

Sources checked: env vars, YAML file, CLI args.
```

The message names the failing key and the constraint violated. Check all three
sources (env, YAML file, CLI) before concluding a key is truly absent.
