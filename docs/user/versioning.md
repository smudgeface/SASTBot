# SASTBot versioning

This page explains the version identifiers SASTBot surfaces, how they relate to
each other, and what happens on each restore mismatch case.

## App version

SASTBot follows [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).
The canonical source is the `version` field in `backend/package.json`; the same
string is mirrored in `frontend/package.json`.

The current release is `0.16.0`. Versions below `1.0.0` signal that the project
is still in active development and the API / DB schema may change between
deployments.

## Schema version

The **schema version** is the `migration_name` of the most recently applied
Prisma migration, as recorded in the `_prisma_migrations` table. Example:

```
20260528173420_rename_include_dev_deps
```

The prefix is a `YYYYMMDDHHMMSS` timestamp, so lexicographic comparison between
two migration names is equivalent to chronological comparison — a fact the
backup/restore machinery relies on.

The **expected schema version** is the lexicographically-last directory name
under `backend/prisma/migrations/`. It represents what the running code was
compiled against. In a healthy deployment these two values match.

## The `/version` endpoint

`GET /version` is a public endpoint (no authentication required) that returns:

```json
{
  "app": "0.16.0",
  "schema": "20260528173420_rename_include_dev_deps",
  "expected_schema": "20260528173420_rename_include_dev_deps",
  "sastbot_dump_format_version": 1
}
```

| Field | Meaning |
|-------|---------|
| `app` | SemVer app version from `backend/package.json`. |
| `schema` | Latest applied migration name from `_prisma_migrations`. |
| `expected_schema` | Latest migration directory in `backend/prisma/migrations/`. |
| `sastbot_dump_format_version` | Integer constant (currently `1`). Bumped when the backup tarball format changes in an incompatible way. |

If `schema` and `expected_schema` differ, the database has unapplied migrations.
Run `prisma migrate deploy` inside the backend container to bring it up to date:

```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate deploy
```

The admin **Settings** page footer displays a condensed version of this
information: `SASTBot v0.16.0 · schema 20260528173420`. If the schema and
expected schema differ, the footer renders in amber to signal that a migration
is pending.

## Backup tarball format (`sastbot_dump_format_version`)

SASTBot backups are `.tar.gz` archives containing two files:

```
dump.pgcustom   — pg_dump --format=custom --compress=9 snapshot
metadata.json   — version metadata (see below)
```

`metadata.json` shape:

```json
{
  "app_version": "0.16.0",
  "schema_version": "20260528173420_rename_include_dev_deps",
  "expected_schema_version": "20260528173420_rename_include_dev_deps",
  "exported_at": "2026-05-17T10:30:00.000Z",
  "sastbot_dump_format_version": 1
}
```

`sastbot_dump_format_version` is an integer that the restore endpoint reads.
Version `1` (the current version) means exactly the two-file layout described
above. If the format ever changes in an incompatible way (e.g. a different dump
file name, a different extraction procedure), this integer will be bumped and
older SASTBot deployments will reject the newer archive.

## Restore behaviour by mismatch case

The restore endpoint (`POST /admin/db/restore`) handles three cases based on
comparing the backup's `schema_version` to the running backend's
`expected_schema_version`. Comparison is lexicographic — correct because
migration names start with `YYYYMMDDHHMMSS_` timestamps.

### Case 1: schema versions match

The most common case after a routine backup-restore cycle.

**Action:** `pg_restore` runs, the DB is in the expected state, no migrations
are needed.

**Response:**
```json
{ "ok": true, "restarting": true, "migrations_applied": [] }
```

### Case 2: dump schema is older than expected

You are restoring a backup taken before a migration was applied (e.g. rolling
back to a point-in-time snapshot, then upgrading immediately).

**Action:** `pg_restore` runs to restore the data, then `prisma migrate deploy`
runs inside the same process to bring the schema forward to what the running code
expects.

**Response:**
```json
{
  "ok": true,
  "restarting": true,
  "migrations_applied": ["20260528173420_rename_include_dev_deps"]
}
```

If `prisma migrate deploy` fails:
- HTTP 500 is returned with the Prisma stderr.
- The database is in a **partially-migrated state** — do not serve traffic until
  you have manually completed the migration.
- The temp extraction directory is retained for inspection (path shown in the
  error response).

### Case 3: dump schema is newer than expected

You are trying to restore a backup taken from a newer version of SASTBot onto an
older backend. This is refused because `pg_restore` would succeed but the older
code wouldn't understand the newer schema.

**Action:** HTTP 422, restore is **not attempted**.

**Resolution:** Upgrade the backend image to at least the version that produced
this backup, then retry the restore.

### Case 4: app version mismatch, schema match

The app version in the backup (`app_version`) differs from the running backend's
app version, but the schema versions match. This is benign — it indicates the
backup was taken from a deployment at a different code revision but the same DB
schema.

**Action:** Restore proceeds normally. An `app_version_warning` field is included
in the response body.

### Case 5: legacy `.dump` file (no metadata)

A `.dump` file uploaded directly (the Stream F legacy format) has no version
metadata. The restore endpoint auto-detects this from the file's magic bytes.

**Action:** `pg_restore` runs unconditionally. The response includes a
`migration_warning` noting that no version checks were performed.

**Recommendation:** Use tarball backups from the "Download backup" button whenever
possible. Keep legacy `.dump` files only for disaster recovery from pre-Stream-F
deployments.

## Checking version alignment after a restore

After any restore, verify that the DB has caught up:

```bash
curl http://localhost:8000/version | jq
```

`schema` and `expected_schema` should be identical. If they differ:

```bash
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate deploy
docker compose -f docker/compose/docker-compose.yml restart worker
```
