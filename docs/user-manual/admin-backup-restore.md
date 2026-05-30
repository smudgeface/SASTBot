# Admin: backup & restore

SASTBot ships with a complete backup/restore loop built into the admin
UI. Backups are self-describing tarballs that can survive upgrades and
schema migrations.

## Backup

**Admin → Settings → Database backup & restore → Download backup** runs
a `pg_dump` of the entire database, packages it with metadata, and
streams the result to your browser as `sastbot-backup-<TIMESTAMP>-<SCHEMA>.tar.gz`.

The tarball contains exactly two files:

| File | Format | Purpose |
|---|---|---|
| `dump.pgcustom` | PostgreSQL custom-format (`pg_dump -F c`) | The DB content |
| `metadata.json` | JSON | Versions, format, timestamps |

`metadata.json`'s shape:

```json
{
  "dump_format_version": 2,
  "app_version": "0.10.0",
  "schema_version": "20260522110000_drop_scan_run_sbom_sast_jsonb",
  "expected_schema_version": "20260522110000_drop_scan_run_sbom_sast_jsonb",
  "taken_at": "2026-05-24T10:42:00Z",
  "kind": "manual"
}
```

The two version fields matter for the restore guard (next section).

> Backups capture the database only. On-disk artifacts
> (`/var/lib/sastbot/artifacts/sbom/`, `/sarif/`) and the retained
> clone cache (`/app/clones/`) are not in the tarball. For full
> disaster recovery, snapshot those volumes separately at the
> filesystem level — they're cheap to recreate by re-scanning,
> so a regular DB backup + filesystem snapshot of artifacts is the
> recommended posture.

## Auto-backup at boot (prod)

In production, the entrypoint script takes a pre-deploy backup on
every container start (`SASTBOT_TAKE_BACKUP=true`, the default).
Tarballs land in `/backups` (volume-mounted) and are rotated to keep
the most recent `BACKUP_RETENTION_COUNT` (default 10).

A backup that fails (gzip CRC fails, pg_dump errors, etc.) aborts the
deploy unless `ALLOW_DEPLOY_WITHOUT_BACKUP=true` is set. The
restart-loop is a feature, not a bug: an undeployable container is
better than a successful container that wasn't backed up.

In dev (the compose `dev` target), there's no entrypoint-backup;
backups are operator-triggered via the UI.

## Restore

**Restore from backup** accepts a tarball produced by **Download
backup**, or a legacy `.dump` file from before the metadata tarball
existed.

Two modes:

1. **Full restore (rebuild from scratch)** — default. Replaces the
   entire database with the backup's content. Use when recovering
   from data loss or migrating to a new instance.
2. **Runtime-only restore** — preserves the current users,
   credentials, repositories, and app settings; restores only scan
   findings + components + artifacts to the backup state. Use to undo
   a bad scan run without losing configuration changes made since the
   backup.

Either mode requires typing `RESTORE` into the confirm field; this is
deliberate friction to prevent accidental clicks.

## The version guard

Before applying the dump, the restore endpoint compares the dump's
`schema_version` against the running backend's `expected_schema_version`:

| Comparison | Outcome |
|---|---|
| Equal | Restore as-is. |
| Dump older | Restore + automatically run `prisma migrate deploy` to bring the schema up to the running code's expectation. |
| Dump newer | **Refuse with HTTP 422.** The running backend is too old to interpret the dump. Upgrade to a backend whose `expected_schema_version` is at least the dump's, then retry. |

The endpoint also enforces a `dump_format_version` minimum. If the
tarball uses an older format than the backend supports, restore
refuses with a clear "this backup was taken by an unsupported older
version" message.

## Restart after restore

A successful restore triggers a `process.exit(0)` on the backend so
the container restarts and re-bootstraps cleanly from the new state.
In production (under Dokploy / docker-compose `restart: unless-stopped`),
the container comes back automatically. In dev with `tsx watch`, the
watcher survives the exit; manual restart needed:

```sh
docker compose -f docker/compose/docker-compose.yml --env-file .env \
  restart backend
```

The frontend polls `/healthz` after a restore is reported successful,
shows the operator a friendly "Backend restarting…" overlay, and
auto-reloads when `/healthz` returns 200 with the new schema.

## Recovery scenarios

| Scenario | Recommended approach |
|---|---|
| Bad scan run produced garbage | Delete the scan from the audit page; or runtime-only restore from yesterday's backup |
| DB corruption / lost volume | Full restore from the most recent good backup |
| Upgraded to a broken release | Downgrade the image first, then full restore |
| Migrating to a new host | Full restore against the empty target DB |
| Lost `MASTER_KEY` | Backup-and-restore won't save you. Without the key the credential ciphertexts are unrecoverable. See [Deployment](admin-deployment) for `MASTER_KEY` provisioning. |

## What restore does NOT touch

- The encryption canary in `credentials` — restored from the dump, so
  the running `MASTER_KEY` must match the one in use when the dump was
  taken.
- On-disk artifact files (`sbom/*.json`, `sarif/*.sarif.json`) — these
  are not in the tarball. Old scans' viewers will return 404 unless
  the volume was snapshotted separately.
- The retained clone cache.
