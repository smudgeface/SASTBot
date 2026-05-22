# Backup and restore

SASTBot stores all application state — repos, credentials, settings, scan findings, SBOM data — in a single Postgres database. This page explains how to back up that database and how to restore from a backup.

---

## Creating a backup

### Manual backup (Admin UI)

Go to **Admin → Settings → Database backup & restore** and click **Download backup**. The browser will download a `sastbot-backup-<timestamp>.tar.gz` archive.

The archive contains two files:

| File | Contents |
|------|----------|
| `dump.pgcustom` | Full PostgreSQL custom-format dump (`pg_dump --format=custom --compress=9`) |
| `metadata.json` | App version, schema version, and export timestamp |

Keep this file somewhere safe. It is the only artifact you need to restore the entire application.

### Pre-deploy automatic backup (Dokploy host)

Before each deployment SASTBot writes an automatic backup to `/backups/` inside the backend container. The last 10 backups are retained; older ones are pruned automatically.

To retrieve a pre-deploy backup from the host:

```bash
# List available backups
docker exec <backend-container-name> ls /backups/

# Copy a specific file to the current directory on the host
docker cp <backend-container-name>:/backups/sastbot-backup-<timestamp>.tar.gz ./
```

Replace `<backend-container-name>` with the actual container name shown by `docker ps`.

---

## Restore modes

The restore endpoint (`POST /api/admin/db/restore`) accepts a `mode` query parameter that controls which tables are replaced.

### Full restore (default: `mode=full`)

Drops and rebuilds the entire database from the dump. Use this when:

- Recovering from data loss or corruption.
- Migrating the application to a new server.
- The backup was taken before you deleted repos or changed your org structure.
- You are unsure which mode to pick — **full restore is always safe**.

**What happens:** all existing data is discarded; the entire database is rebuilt from `dump.pgcustom`. If the dump's schema is older than the running backend, `prisma migrate deploy` runs automatically to bring it forward.

### Runtime-only restore (`mode=runtime`)

Preserves the auth and configuration tables and restores only scan data from the backup. Use this when:

- A recent scan run produced bad or corrupt findings and you want to roll back to the pre-scan state.
- You have made settings or credential changes since the backup was taken that you do not want to lose.

**What is preserved (kept from the current live database):**

| Table | Purpose |
|-------|---------|
| `orgs` | Organisation records |
| `users` | User accounts and password hashes |
| `sessions` | Active login sessions |
| `credentials` | Encrypted API keys and tokens |
| `repos` | Repository definitions and scan configuration |
| `app_settings` | LLM gateway, Jira, NVD, and other admin settings |
| `encryption_canary` | Master-key validation record |

**What is restored (rebuilt from the backup):**

| Table | Purpose |
|-------|---------|
| `scan_scopes` | Scan scope definitions |
| `scan_runs` | Individual scan run records and metadata |
| `sbom_components` | Per-scan SBOM component audit data |
| `scan_findings` | Raw finding records |
| `sast_findings` | SAST-specific finding detail |
| `sast_issues` | Deduplicated SAST issues |
| `sca_issues` | SCA / CVE issues |
| `jira_tickets` | Linked Jira ticket references |
| `cve_knowledge` | CVE knowledge-base cache |
| `scope_components` | Scope-level durable component state |
| `scan_run_components` | Per-run component join table |

`_prisma_migrations` is always restored from the dump regardless of mode.

---

## Constraints and edge cases

### FK integrity (runtime mode only)

In `runtime` mode the preserved tables (`repos`, `orgs`, …) remain as they are in the live database. If you deleted a repo or org **after** the backup was taken, the restored scan data will reference IDs that no longer exist. The backend detects this before making any changes and returns HTTP 422 with a message identifying the missing references.

**Remedy:** use Full restore instead (`mode=full`).

### Schema-version constraint (runtime mode only)

`mode=runtime` requires that the dump's `schema_version` exactly matches the running backend's `expected_schema_version`. The automatic migrate-forward logic that `mode=full` provides does not work cleanly when overlaying old-schema rows into new-schema tables.

If the dump is older (taken before you upgraded the backend), the backend returns HTTP 422 pointing you at `mode=full`.

**Remedy:** use Full restore, which will restore the data and then migrate the schema forward in one step.

### Dump newer than running backend

If the dump's `schema_version` is newer than the running `expected_schema_version` (i.e. you are trying to restore a backup from a newer SASTBot onto an older backend), the restore is refused in **both** modes.

**Remedy:** upgrade the backend image to at least the version that produced the backup, then retry.

See [versioning.md](versioning.md) for the full schema-version matching rules and how version information is surfaced in the UI and `GET /version`.

---

## How to perform a restore

1. Go to **Admin → Settings**.
2. In the **Database backup & restore** section, choose a restore mode:
   - **Full restore** — rebuilds the entire database (safe default).
   - **Runtime-only restore** — preserves settings and users, restores scan data only.
3. If you selected **Runtime-only restore**, read the caution note: if you have deleted any repos or upgraded the backend since the backup was taken, use Full restore instead.
4. Click **Choose file** and select your `.tar.gz` backup (or a legacy `.dump` file).
5. Click **Restore…** — a confirmation dialog will open.
6. Review the warning and type `RESTORE` in the confirmation box.
7. Click **Restore database**.

The backend will upload the file, validate it, apply the restore, and then call `process.exit(0)` to restart with fresh database connections. The Settings page polls `/healthz` every two seconds and reloads automatically once the backend is reachable again.

---

## After a restore

Verify that the schema is fully up to date:

```bash
curl http://localhost:8000/version | jq
```

`schema` and `expected_schema` should be identical. If they differ, run:

```bash
docker compose -f docker/compose/docker-compose.yml exec backend pnpm prisma migrate deploy
docker compose -f docker/compose/docker-compose.yml restart worker
```

The admin Settings page footer also displays schema status in amber if a migration is pending.
