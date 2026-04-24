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

---

## Issue identity (M5+)

SASTBot stores **Issues** as the stable unit of analysis and **Findings** as per-scan detection events. This separation means:

- Triage decisions (status, Jira link, notes) live on the Issue and survive re-scans.
- A finding's `issueId` FK links it to the parent Issue. Never delete Issue rows that have active Jira links or non-trivial triage decisions.
- `lastSeenScanRunId` on each Issue advances every scan where the issue is detected. When it no longer matches `scope.lastScanRunId`, the issue is "resolved" (not seen in latest scan).
- The worker auto-sets `triageStatus='fixed'` on SAST issues not detected in a scan, unless they're already terminal (`fixed`, `wont_fix`, `suppressed`, `false_positive`).

**Status progression (SAST):**
```
pending → [Confirm] → confirmed ("To do")
confirmed → [Link Jira ticket] → planned
planned → [scan no longer detects issue] → fixed (auto)
pending/confirmed → [Won't fix / Invalid] → wont_fix / false_positive
```

**Status progression (SCA):**  
`active → confirmed ("To do") → planned (Jira linked) → dismissed (acknowledged/wont_fix/false_positive)`

## Jira integration (M5c+)

SASTBot is **read-only** with respect to Jira — it never creates tickets.

**Setup:**
1. Settings → Jira section: set Base URL (`https://yourorg.atlassian.net`), Account email, and create a `jira_token` credential with your Atlassian API token.
2. Click "Check connection" → should show "✓ Connected as Your Name".
3. From any issue expanded row, click "+ Link Jira ticket" and enter a ticket key (e.g. `SEC-123`).

**Sync cadence:**
- Open/In-progress tickets: re-synced every 15 minutes (handled by Phase 5d scheduler, not yet wired).
- Done tickets: re-synced every 60 minutes.
- On-demand: "Refresh" button in the Jira card on any linked issue.

**Resolutions:** Available via `GET /admin/jira/resolutions`. The resolution name is stored as a raw string and displayed in the Jira card. Common values at lmitechnologies: Done, Fixed, Invalid, Won't Do.

**Attention indicator:** Issues with `triageStatus=planned` where the linked Jira ticket has `statusCategory=done` show an amber ⚠ badge. This means Jira says it's resolved but the scan hasn't confirmed the code fix yet. Either the next scan will mark the issue `fixed`, or the ticket was closed with a dismissal resolution (Invalid/Won't Do) and the SASTBot issue should be manually set to Invalid/Won't fix.

**Troubleshooting:**
- `401 Unauthorized`: wrong email or API token. Auth uses `Basic base64(email:token)` — both fields are required.
- `403 Forbidden`: the account lacks permission to view the specific ticket.
- `404 Not found`: ticket key doesn't exist. The link is rejected and no JiraTicket row is created.
- `syncError` on a ticket: visible as amber chip in the Jira card. Refresh to retry.

## Git repository connection check

From Repositories → `⋯` menu → "Check access": runs `git ls-remote --heads` against the repo URL with the stored credential. Returns the list of remote branches on success, or a clear error on failure.

Common errors:
- `Authentication failed`: wrong credential kind or value. Bitbucket Server requires `https_basic` (username + API token as password), not `https_token`.
- `Remote branch not found`: the configured `default_branch` doesn't exist on the remote. Update the repo's default branch.
- `not appear to be a git repository`: `file://` URL is wrong path, or the repo hasn't been initialized.
