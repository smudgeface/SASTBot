# Troubleshooting

## Scan warning codes

The audit page and the scan-detail page surface scan warnings as
chips. Each warning has a `code`, a `severity` (`info` or `error`),
and an operator-facing `message`. Error-severity warnings prevent the
scope's `lastScanRunId` from advancing — see
[Overview](overview#trustworthiness-gate).

| Code | Severity | Cause | Fix |
|---|---|---|---|
| `clone_failed` | error | `git clone` returned non-zero for a non-specific reason. | Check the worker logs for the underlying message. Often a transient network issue; re-run. |
| `auth_failed` | error | Clone failed because the credential was rejected. | Verify the credential value (rotated upstream?). Use **Check connection** on the repo to retest. |
| `branch_not_found` | error | The configured default branch doesn't exist on the remote. | Edit the repo, set the correct branch. |
| `remote_unreachable` | error | DNS or TCP failure reaching the remote (often VPN). | Check VPN, then re-run. |
| `scope_path_missing` | error | The configured scan path doesn't exist in the cloned tree. | Edit the repo's scan paths to match the actual layout. |
| `cdxgen_failed` | error | Anchore cdxgen exited non-zero. | Check the worker logs. Often a transient lockfile-parse issue; re-run usually clears it. |
| `llm_sbom_augmentation_failed` | error | The LLM SBOM augmentation pass errored out. The fallback Stage-1-only SBOM is used instead. | Check LLM endpoint health (Settings → LLM → Save & test). |
| `llm_sast_detection_failed` | error | claude-p exited non-zero or was killed by the wall-clock / staleness watchdog. | Check LLM endpoint. The trustworthiness gate prevented findings from being damaged. Re-run. |
| `llm_*_parse_errors` (drop ratio ≥ 50%) | error | The LLM emitted records that failed Zod parsing on more than half of its output. | LLM endpoint drift. Inspect the warning's `details` array for samples; if it's a single mistype, schema may need an alias. |
| `llm_*_parse_errors` (drop ratio < 50%) | info | Some records were unparseable but the majority survived. | No action needed; SASTBot still uses the parsed ones. |
| `llm_sast_detection_retry` | info | First detection attempt failed; auto-retry succeeded. | No action needed. Both attempts billed against your LLM quota. |
| `recheck_capped` | info | SBOM recheck hit the per-scan candidate cap. Components beyond the cap stayed active from prior scans. | Usually fine. If you suspect missed cleanups, bump the cap in code. |

## Common UI symptoms

### "Most recent scan failed trustworthiness check" banner

The most recent scan emitted at least one error-severity warning. Its
findings were written to the audit but did NOT advance the scope's
truth set. Open the scan detail page to see which warning fired.
Re-run when the underlying issue is fixed (LLM endpoint, clone access,
etc.).

### Credential picker shows "Loading credentials…" forever

The `/api/admin/credentials` request didn't return. Check the network
panel:

- 401 — your session expired. Sign in again.
- 5xx — backend issue. Check container logs.
- Timeout — backend is wedged. Restart with `docker compose ... restart backend`.

### `/version` reports the old app version after upgrade

The container is still running on the old image. `docker compose ... ps`
to confirm the image tag, and re-`up --build` if needed. If the
image is right but the version is stale, the runtime didn't pick up
the new `APP_VERSION` — restart.

### `/version` reports `schema` ≠ `expected_schema` (amber in sidebar)

The DB hasn't applied a migration the running code expects. In prod
the entrypoint runs `prisma migrate deploy` on boot; if it didn't
take, run manually:

```sh
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  exec backend pnpm prisma migrate deploy
```

If `_prisma_migrations` reports an error, the migration body has a
problem — escalate to a developer.

### Backend refuses to boot with "MASTER_KEY canary failed"

The `MASTER_KEY` env var doesn't match what was used when the
existing canary row was written. Either:

- Set the correct key from your password manager.
- Or if you've genuinely lost the key, delete the database volume
  (`docker volume rm sastbot_sastbot_pgdata`) and start fresh — all
  credentials are unrecoverable without the original key.

### SBOM viewer shows "No artifact file" for an old scan

Scans run before M9 Stream B (v0.9.0) don't have on-disk artifact
files. Re-run the scan to produce one.

### Frontend can't reach `/api`

Two common shapes:

- Dev: Vite dev proxy not running. Restart `frontend` compose service.
- Prod: reverse proxy not routing `/api/*` to backend. Check the
  nginx config or your Traefik labels.

### Scan stuck in `cloning`

Often a VPN issue — the worker can't reach the corporate Git host.
Test from the worker:

```sh
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  exec worker git ls-remote https://your-corp-git/repo.git
```

If that hangs, VPN is the culprit.

### Scan stuck in `llm_detection` or `llm_recheck`

Often the LLM endpoint is slow or hung. The worker has a wall-clock
watchdog (default 1200s for detection) and a staleness watchdog
(default 300s without stdout). If both expire, the scan transitions
to `failed` with `llm_sast_detection_failed`. If neither has fired
yet, the scan is genuinely waiting on the LLM.

You can cancel the scan from the audit page; it'll terminate at the
next phase boundary.

### Restore endpoint refuses with HTTP 422

The dump's schema is *newer* than the running backend expects. Upgrade
the backend image to a version whose `expected_schema_version` is at
least the dump's, then retry the restore.

### Browser shows "Backend restarting…" overlay after restore

That's the post-restore restart flow. The frontend polls `/healthz`
and auto-reloads when the backend comes back. If it sits there for
more than 60 seconds, the backend didn't come back — check container
logs. In dev with `tsx watch`, the watcher survives the
`process.exit(0)` and you'll need to manually
`docker compose ... restart backend`.

## Where to look first

```sh
# Live container state
docker compose -f docker/compose/docker-compose.yml --env-file .env ps

# Recent backend logs
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  logs --tail 100 backend

# Recent worker logs (where scans run)
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  logs --tail 100 worker

# Quick health
curl -s http://localhost:8000/healthz
curl -s http://localhost:8000/version | jq

# DB sanity (replace creds as needed)
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  exec postgres psql -U sastbot -d sastbot -c "SELECT COUNT(*) FROM scan_runs;"
```

## When in doubt

Capture the current state before you change anything:

```sh
# A fresh backup via the UI is the safest snapshot
# OR a raw pg_dump if the UI is wedged:
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  exec postgres pg_dump -U sastbot -F c sastbot > /tmp/emergency.dump
```

Then iterate. With the backup in hand, you can undo any destructive
operator action.
