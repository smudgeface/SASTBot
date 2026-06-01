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
  "kind": "manual",
  "master_key_fingerprint": "a1b2c3d4e5f60718"
}
```

The two version fields matter for the restore guard (next section). The
`master_key_fingerprint` is a non-reversible HMAC of the `MASTER_KEY` the
dump's data was encrypted under — it reveals nothing about the key, and the
restore guard uses it to catch a key mismatch *before* applying the dump.

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

## The MASTER_KEY guard (cross-key migrations)

A **full** restore replaces the encryption canary and every credential
ciphertext — all of which were encrypted under the **source instance's
`MASTER_KEY`**. If you restore that dump onto an instance running a
*different* key, the canary fails to decrypt on the next boot and the backend
**refuses to start**, and every stored credential is undecryptable.

To catch this before any damage, a full restore compares the dump's
`master_key_fingerprint` to the running instance's:

| Comparison | Outcome |
|---|---|
| Match | Restore proceeds. |
| Differ, **source key supplied + verified** | **Re-key on restore** — see below. |
| Differ, no source key | **Refuse with HTTP 422**, naming both fingerprints and offering the two options below. |
| Differ, wrong source key | **Refuse with HTTP 422** — the supplied key doesn't match the backup. |
| Dump has no fingerprint (legacy backup) | Skipped — can't verify; the boot-time canary still backstops a true mismatch. (Re-key on restore needs a fingerprinted backup — v0.18.0 or newer.) |

### Re-key on restore (migrating between installations)

You have two ways to migrate a backup onto an instance running a **different**
`MASTER_KEY`:

1. **Match the key first.** Set `MASTER_KEY` on the target to the value the
   backup was taken with, restart, then full-restore. The target permanently
   adopts the source key.
2. **Re-key on restore (recommended for cross-install migration).** Leave the
   target's own `MASTER_KEY` as-is. In the restore dialog, expand **"Restoring a
   backup from a different installation?"** and paste the **source** instance's
   `MASTER_KEY` into the **Source MASTER_KEY** field. The restore verifies that
   key against the backup's fingerprint, runs `pg_restore`, then re-encrypts the
   canary and every credential from the source key to **this** instance's key —
   atomically, in one transaction. The instance keeps its own key and all
   secrets stay usable. The success banner reports how many credentials were
   re-encrypted.

The source key travels once over your authenticated session, is never written to
disk or logs, and is zeroed from memory immediately after use. If the re-key
fails part-way, it rolls back: the restored data is intact (still source-key
encrypted) and no mixed-key rows are committed — retry with the correct source
key, or set `MASTER_KEY` to the source value and restart.

Either way, **without the original key the encrypted data is unrecoverable by
design.** (Runtime-only restores don't touch the canary or credentials, so this
guard doesn't apply to them.)

## Rotating the MASTER_KEY

If you need to retire a `MASTER_KEY` you believe is compromised, use
**Admin → Settings → Rotate MASTER_KEY** instead of the old manual "delete the
canary row and re-enter every credential" dance. It re-encrypts the canary and
every stored credential from the current key to a new one, atomically.

1. **Take a backup first.**
2. Paste a new 32-byte base64 key, or click **Generate** to make one in your
   browser. **Save it** — you'll need it in the next step.
3. Type `ROTATE` to confirm. The server re-encrypts all at-rest secrets to the
   new key and reports the new key's fingerprint.
4. **The backend does *not* restart automatically.** This is deliberate: the
   running process still holds the *old* key in its environment. Update
   `MASTER_KEY` in your `.env` (the backend **and** worker share it) to the new
   value and restart both services **now**. Until you do, the instance cannot
   decrypt credentials, and a restart under the old key would fail the canary.

If the rotation itself fails, nothing changes — the instance keeps running
normally on the current key and no restart is needed.

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
| Migrating to a new host | Either re-key on restore (paste the source instance's key into **Source MASTER_KEY** in the restore dialog — the target keeps its own key), or set `MASTER_KEY` on the target to the source value **first** then full restore. See [the MASTER_KEY guard](#the-master_key-guard-cross-key-migrations). |
| Suspected key compromise | Rotate the key in place — **Admin → Settings → Rotate MASTER_KEY** — then update `MASTER_KEY` in the environment and restart. See [Rotating the MASTER_KEY](#rotating-the-master_key). |
| Lost `MASTER_KEY` | Backup-and-restore won't save you. Without the key the credential ciphertexts are unrecoverable. See [Deployment](admin-deployment) for `MASTER_KEY` provisioning. |

## What restore does NOT touch

- The encryption canary in `credentials` — restored from the dump, so
  the running `MASTER_KEY` must match the one in use when the dump was
  taken.
- On-disk artifact files (`sbom/*.json`, `sarif/*.sarif.json`) — these
  are not in the tarball. Old scans' viewers will return 404 unless
  the volume was snapshotted separately.
- The retained clone cache.
