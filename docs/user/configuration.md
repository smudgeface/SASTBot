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

### How it works

- `pg_dump` runs **inside the backend container** and connects to the same
  `DATABASE_URL` that the application itself uses.
- The connection password is passed via the `PGPASSWORD` environment variable
  (never via command-line arguments, which would be visible in process listings).
- The dump is streamed directly into the HTTP response — it is never buffered
  in memory — so it is safe for databases of any size.
- Format: `--format=custom --compress=9`. The resulting `.dump` file is
  smaller than a plain SQL dump and supports parallel restore.

### Restoring a backup

```bash
pg_restore --clean --if-exists -d <dbname> sastbot-backup-<timestamp>.dump
```

Or to a fresh database:

```bash
createdb <newdb>
pg_restore -d <newdb> sastbot-backup-<timestamp>.dump
```

### Requirements

The backend image includes `postgresql-client-16` (installed from the
PostgreSQL APT repository to match the Postgres 16 server version in compose).
No additional configuration is needed — the binary is on `PATH` and the
connection details are derived automatically from `DATABASE_URL`.

### No configurable knobs

There are currently no environment variables for the backup endpoint.
The binary path (`pg_dump`) is hardcoded and resolved from `PATH`.

## Coming soon

The following configuration keys are planned but not yet implemented. They will
be filled in by later production-readiness streams:

| Key (env form) | Stream | Description |
|----------------|--------|-------------|
| `SCAN_WORKER_CONCURRENCY` | Stream B | Number of scans the BullMQ worker processes in parallel. Default 2, max 4. |
| `CLAUDE_DETECTION_TIMEOUT_MS` | Stream C | Wall-clock cap on the `claude -p` SAST detection subprocess. Default 3 600 000 (60 min). |
| `CLAUDE_RECHECK_TIMEOUT_MS` | Stream C | Wall-clock cap on the `claude -p` recheck subprocess. Default 1 800 000 (30 min). |
| `CLAUDE_STDOUT_STALENESS_MS` | Stream C | Kill the subprocess if no stdout for this many milliseconds. Default 300 000 (5 min). |

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
