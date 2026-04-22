# SASTBot — Operations runbook

Day-to-day ops, deploy, and recovery procedures. Keep this document
generic — **no internal hostnames, IPs, or webhook secrets**. Those live
in `docs/DEPLOY_HOMELAB.md` (gitignored) for personal setup and in the
equivalent internal runbook for work.

## Services

| Compose service | Role |
|-----------------|------|
| `postgres` | Postgres 16. Primary store for users, repos, credentials, settings, scan_runs, encryption canary. |
| `redis` | Redis 7. BullMQ broker (job queue only, no business data). |
| `backend` | Fastify HTTP API on port 8000. |
| `worker` | BullMQ consumer. Same image as `backend`, different command. Runs scan jobs. |
| `frontend` | Vite dev server on port 5173 (prod image serves the built bundle through Nginx). |

## Bootstrap admin

First-boot seeds the default org and creates `admin@sastbot.local` with a
random password. The password is printed once to the backend logs:

```bash
docker compose -f docker/compose/docker-compose.yml logs backend | grep BOOTSTRAP
```

Create another admin explicitly (any time):

```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm run bootstrap-admin --email you@example.com
```

## Reading logs

```bash
# Backend (HTTP + startup)
docker compose -f docker/compose/docker-compose.yml logs -f backend

# Worker (BullMQ job execution)
docker compose -f docker/compose/docker-compose.yml logs -f worker

# Last 100 lines, all services
docker compose -f docker/compose/docker-compose.yml logs --tail=100
```

Fastify emits structured JSON logs (pino). `pino-pretty` is available in
the image for local development:

```bash
docker compose -f docker/compose/docker-compose.yml logs backend \
  | docker compose -f docker/compose/docker-compose.yml exec -T backend pnpm exec pino-pretty
```

## Running the build scripts

All build/CI logic lives in `scripts/` as Python modules. Run from the
repo root:

```bash
python -m scripts.ci             # full pipeline: typecheck → lint → test → openapi-drift → image build
python -m scripts.ci --skip-build
python -m scripts.ci --only test

python -m scripts.typecheck
python -m scripts.lint
python -m scripts.test
python -m scripts.check_openapi
python -m scripts.build_images --target prod
python -m scripts.deploy
```

The compose stack must be up for `typecheck`, `lint`, `test`, and
`check_openapi` (they run inside the containers to pin Node/pnpm
versions). `build_images` and `deploy` only need Docker.

See [`scripts/README.md`](../scripts/README.md) for details.

## Deploying

SASTBot is deployed to any Dokploy instance reachable over HTTP. The
deploy is driven by `scripts/deploy.py`:

```bash
export DOKPLOY_WEBHOOK_URL="http://<dokploy-host>:3000/api/deploy/compose/<webhook-id>"
export DOKPLOY_REF="refs/heads/main"
export DOKPLOY_REPO_FULL="<owner>/<repo>"

python -m scripts.deploy
```

The webhook URL contains a secret — **do not commit it**. For personal
development the URL is recorded in `docs/DEPLOY_HOMELAB.md` (gitignored).

Rollback: Dokploy keeps previous container revisions; use its UI to roll
back. A failed deploy leaves the previous version running.

## Master-key rotation

The `MASTER_KEY` env var encrypts every `credentials.ciphertext` and the
`encryption_canary` row. Rotation is a controlled multi-step procedure
because credentials cannot be decrypted without the old key.

**Current state (M1/M2):** rotation is **not yet automated**. The
`credentials.key_version` and `encryption_canary.key_version` columns are
reserved hooks — they will be used by the rotation tool in M6.

**Procedure (manual, until M6 ships):**

1. Maintenance window: deploy with `docker compose down` (no new requests).
2. Dump `credentials` and `encryption_canary` contents as a safety backup.
3. For each row in `credentials`: decrypt with the old key in a one-shot script, re-encrypt with the new key, set `key_version = 2`.
4. Re-create the `encryption_canary` row with the new key.
5. Update the `MASTER_KEY` env var in Dokploy / the deploy target.
6. `docker compose up` — the canary check at boot will succeed against the new key.
7. Verify: log in, open a credential-bearing view, confirm outbound calls still work (Jira status sync, etc.).

Never delete the old key before you have confirmed the new canary
validates and at least one end-to-end decrypt works.

## Database migrations

Prisma manages schema changes. Migrations live in
`backend/prisma/migrations/`. The compose `backend` command runs
`prisma migrate deploy` at every container start, so pushing a commit
with a new migration folder applies it on the next deploy.

Create a new migration during development:

```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate dev --name describe_change
```

Commit the generated folder. `db push` is **not** used outside early
development.

## Disaster recovery

| Scenario | Recovery |
|----------|----------|
| Postgres volume corrupted | Restore from backup (see your infra's backup policy). Fresh DB will recreate bootstrap admin on next boot; credentials are lost — users must re-enter them. |
| Redis lost | Re-enqueue any in-flight scans from the UI. Redis holds only transient job state. |
| Wrong `MASTER_KEY` set | Backend refuses to start with `CryptoCanaryError`. Fix the env var and restart. |
| Frontend build broken after deploy | Roll back via Dokploy UI. The compose file pins explicit image tags; `:latest` is fine for dev but prefer specific tags in production. |
| Worker stuck / crashlooping | Check worker logs. Kill the stuck job from the BullMQ UI (if enabled) or flush the queue in Redis CLI. |

## Scheduled backups

Out of scope for M2. The underlying host's backup policy applies
(Dokploy volumes live under `/etc/dokploy/`). Revisit in M7.
