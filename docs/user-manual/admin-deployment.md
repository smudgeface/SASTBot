# Admin: deployment

This section is for the operator standing up a fresh SASTBot
instance. For an existing instance you probably want
[Versioning & upgrades](admin-versioning) or
[Backup & restore](admin-backup-restore) instead.

## Architecture at a glance

A SASTBot deployment is five containers built from this repo:

| Service | Image | Role |
|---|---|---|
| `postgres` | `postgres:16` | The database. Volume: `sastbot_pgdata`. |
| `redis` | `redis:7` | BullMQ broker. Volume: `sastbot_redisdata`. |
| `backend` | Built from `docker/backend.Dockerfile` | Fastify API, OpenAPI/Swagger docs, admin endpoints. |
| `worker` | Same image as backend | Long-running BullMQ worker that runs scans. Different `command`. |
| `frontend` | Built from `docker/frontend.Dockerfile` | Vite (dev) or Nginx (prod) serving the SPA. |

Backend and worker share an image; they differ only by entrypoint
command. Two shared volumes link them:

- `sastbot_repo_cache` mounted at `/app/clones` — retained clones.
- `sastbot_artifacts` mounted at `/var/lib/sastbot/artifacts` —
  per-scan SBOM + SARIF artifact files.

## Required environment variables

Set these via `.env` next to `docker/compose/docker-compose.yml`, or
via the Dokploy / your-orchestrator UI:

| Variable | Required? | What it does |
|---|---|---|
| `MASTER_KEY` | Yes | 32-byte base64-encoded AES-256-GCM key. Encrypts credential ciphertexts. **Once set, do not change it.** Without it, the canary check fails on boot. |
| `DATABASE_URL` | Auto from compose | `postgresql://...`. Default uses the compose's `postgres` service. |
| `REDIS_URL` | Auto from compose | `redis://redis:6379/0`. |
| `APP_ORIGIN` | Yes in prod | CORS allowlist for the frontend origin. Defaults to `http://localhost:5173` for dev. |
| `SESSION_COOKIE_SECURE` | `true` in prod | Required when behind HTTPS. `false` for plain-HTTP dev. |
| `ALLOW_INSECURE_COOKIES` | Optional | Override that lets `SESSION_COOKIE_SECURE=false` boot under `NODE_ENV=production` — for a deliberately trusted internal HTTP-only deploy. Without it the backend refuses to start in that combination. Cookies travel in clear text while on; only safe on a trusted LAN. Default `false`. |
| `BOOTSTRAP_ADMIN_EMAIL` | Optional | Email of the auto-created admin on first boot. Default `admin@sastbot.local`. |
| `PORT` | Optional | Backend listen port. Default `8000`. |
| `LOG_LEVEL` | Optional | Pino log level. Default `info`. |
| `BACKUP_DIR` | Prod only | Where the entrypoint writes pre-deploy backups. Default `/backups`. |
| `BACKUP_RETENTION_COUNT` | Prod only | How many backups to keep. Default `10`. |
| `ALLOW_DEPLOY_WITHOUT_BACKUP` | Optional | `true` skips the pre-deploy backup. Use only when recovering from a stuck deploy loop. |
| `SASTBOT_TAKE_BACKUP` | Optional | Set `false` on the worker compose service so worker restarts don't double-back-up. |
| `SASTBOT_RUN_MIGRATIONS` | Optional | Set `false` on the worker so it doesn't race the backend on `migrate deploy`. |
| `ARTIFACT_DIR` | Optional | Where the worker writes SBOM + SARIF files. Default `/var/lib/sastbot/artifacts`. Match the volume mount. |
| `CLONE_CACHE_DIR` | Optional | Where retained clones live. Default `/app/clones`. Match the volume mount. |

## MASTER_KEY

Generate a key the first time only:

```sh
openssl rand -base64 32
```

Save the result in your `.env` AND in your password manager:

```env
MASTER_KEY=NA2K1ZF6lDpzdpwH...rqU=
```

The backend's startup `ensureCanary()` decrypts a known ciphertext to
verify the key works. If decryption fails, the backend aborts boot
with a clear error.

**Once you have credentials in the system, you cannot rotate
MASTER_KEY without re-entering every credential.** The ciphertexts
are not recoverable without the old key. Treat the key the same as
you'd treat the root password to a credential vault: written down in
exactly one place, never edited casually.

### MASTER_KEY rotation

If you do need to rotate (compromised key, etc.):

1. Take a backup. Note: the canary won't decrypt against the new key,
   so this backup is "rescue" only.
2. Note every credential by name (the credentials page shows kinds
   and names; values are not exportable).
3. Stop the backend.
4. Set the new `MASTER_KEY`.
5. **Delete the canary row** from the DB (this lets the new key
   re-bootstrap the canary).
6. Start the backend.
7. Recreate every credential via the admin UI.

There's no automated rotation flow because in practice this is rare
and the operator should be a real human re-keying the vault.

## Bringing the stack up — first time

From the repo root:

```sh
cp .env.example .env
# Set MASTER_KEY and review the other vars
docker compose -f docker/compose/docker-compose.yml --env-file .env up --build
```

Watch for the bootstrap admin line in the backend logs:

```sh
docker compose -f docker/compose/docker-compose.yml logs backend | grep BOOTSTRAP
```

That password is printed once. Capture it. From here, follow
[Quick start](quick-start) §2 onward.

## Production deployment

The prod target uses a different entrypoint (`docker/backend-entrypoint.sh`)
which:

1. Takes a pre-deploy backup of the DB.
2. Verifies the gzip CRC.
3. Rotates older backups to `BACKUP_RETENTION_COUNT`.
4. Runs `prisma migrate deploy`.
5. Regenerates the Prisma client.
6. Execs the actual command (server or worker).

Behind a reverse proxy (Traefik, Caddy, nginx-ingress, Dokploy's
built-in):

- Terminate TLS at the proxy.
- Forward `/` to the frontend container's `:80`.
- Forward `/api/*` and `/healthz`, `/version`, `/openapi.json`, `/docs`
  to the backend container's `:8000`. The frontend's Nginx config
  has matching `location /api/` rules for the bundled case.
- Set `SESSION_COOKIE_SECURE=true`.
- Set `APP_ORIGIN=https://your-public-host`.
- Do NOT publish backend / postgres / redis ports on the host. Only
  the frontend (or the reverse proxy in front of it) needs an
  external interface.

### Pull-based deployment (pre-built images)

If your host does not build images from source — for example a
manually-managed Proxmox VM that pulls pre-built images from a
container registry — use `docker/compose/docker-compose.proxmox.yml`
with `.env.proxmox.example`. The step-by-step IT runbook (registry
login, env vars, first boot, TLS, backups, the pull-a-new-tag upgrade
flow, and troubleshooting) lives in `docs/DEPLOY_PROXMOX.md` in the
repository.

## Volume sizing

| Volume | Growth model | Typical size after 6 months |
|---|---|---|
| `sastbot_pgdata` | Findings + scan history. Scales with `#scopes × scans/scope × #issues`. | 1–10 GB |
| `sastbot_redisdata` | BullMQ queues. Small. | < 100 MB |
| `sastbot_repo_cache` | Per-repo retained clones. `#repos × repo size`. | 1–50 GB depending on repos |
| `sastbot_artifacts` | Per-scan SBOM + SARIF. `#scans × ~100 KB each`. | 100 MB – few GB |
| `/backups` | `BACKUP_RETENTION_COUNT × dump size`. | 100 MB – few GB |

Set up filesystem-level snapshots (ZFS, btrfs, LVM, cloud disk
snapshots) of `sastbot_pgdata` and `sastbot_artifacts` for true
disaster recovery. The DB backup tarball covers content but the
artifact files are not in it.

## Health checks

- `GET /healthz` — returns `{ status: "ok", version }`. Use as the
  container liveness check.
- `GET /version` — JSON with `app`, `schema`, `expected_schema`. Use
  as the deploy-success verification.

## Common deploy mistakes

| Mistake | Symptom | Fix |
|---|---|---|
| Forgot `--env-file .env` | `MASTER_KEY` env is empty; backend refuses to boot | Always pass `--env-file` |
| Published backend port to host | The frontend talks directly to backend, bypassing proxy auth headers | Remove the `ports:` block on the backend in prod compose |
| Different `MASTER_KEY` on backend vs worker | Worker can't decrypt credentials when running a scan | Use the same env file for both |
| Stale `node_modules` named volume after rebuild | Backend serves an old Prisma client | The entrypoint now regenerates on every boot since v0.9.7; if not, `docker compose exec backend pnpm prisma generate` and restart |
| `SESSION_COOKIE_SECURE=true` over plain HTTP | Login succeeds on the API but the browser drops the cookie; refresh logs you out | Either move to HTTPS or set it to `false` (dev only) |
