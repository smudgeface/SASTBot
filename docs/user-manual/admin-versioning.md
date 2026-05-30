# Admin: versioning & upgrades

SASTBot has two versions that matter, and they have different rules.
Understanding them is critical for safe upgrades and restores.

## The two versions

| Version | Source of truth | When it changes |
|---|---|---|
| **App version** | `APP_VERSION` constant in `backend/src/routes/version.ts` (mirrored in both `package.json`s) | Manually bumped on every release, following SemVer. |
| **Schema version** | The lexicographically-last folder name under `backend/prisma/migrations/` | Automatically bumps whenever a developer runs `prisma migrate dev`. |

Both are surfaced by `GET /version`:

```json
{
  "app": "0.10.0",
  "schema": "20260522110000_drop_scan_run_sbom_sast_jsonb",
  "expected_schema": "20260522110000_drop_scan_run_sbom_sast_jsonb",
  "sastbot_dump_format_version": 2
}
```

`schema` is what's currently applied to the live database (from
`_prisma_migrations`). `expected_schema` is what the running code
expects (the migrations bundled in the image). A mismatch shows up as
amber in the sidebar footer; it usually means a migration didn't run.

## App-version SemVer

| Change | Bump |
|---|---|
| Bug fix, doc tweak, internal refactor — no operator-visible effect | PATCH (`0.10.0 → 0.10.1`) |
| New backwards-compatible feature: new endpoint, new optional field, new admin UI, new env knob | MINOR (`0.10.0 → 0.11.0`) |
| Breaking API change, schema migration that destroys data, removed feature, changed default | MAJOR (reserved for the 1.0+ era; pre-1.0 still uses MINOR for breaking changes) |

Pre-1.0 (where SASTBot currently lives) the API is still evolving and
operators should treat MINOR bumps as potentially incompatible. The
backup/restore version guard exists specifically to make this safe —
see [Backup & restore](admin-backup-restore).

## Upgrading the app

Best-practice upgrade flow:

1. Read the release notes (PROGRESS.md entry for the new version).
2. **Take a backup** from the running version's UI.
3. Pull the new image (or rebuild compose).
4. Bring the stack up. The prod entrypoint will:
   - Take a *second* backup (pre-deploy auto-backup).
   - Run `prisma migrate deploy` to apply any new migrations.
   - Regenerate the Prisma client (`pnpm prisma generate`).
   - Start the backend / worker.
5. Verify `/version`:
   ```sh
   curl -s http://your-host/version | jq
   ```
   Both `schema` and `expected_schema` should reflect the new
   migration timestamp; `app` should reflect the new version.

Downgrading is possible but riskier: a newer backup against an older
schema-expectation triggers the version guard's HTTP 422.

## Rollback

If a deploy breaks badly:

1. Bring the old image back up (Dokploy: re-pin to the previous tag).
2. Restore the pre-deploy backup that was taken at the bad deploy's
   start.
3. Investigate what went wrong from the audit page + container logs.

## What `/version` reports, by surface

`APP_VERSION` is the single source of truth. The literal `0.10.0` (or
whatever your build is) is consumed by:

- `GET /version` — JSON response field `app`.
- `GET /healthz` — `version` field.
- `/openapi.json` — `info.version`.
- SARIF — `runs[0].tool.driver.version`.
- CycloneDX SBOM — `metadata.tools.components[*].version` for the
  SASTBot tool entry.
- The admin sidebar footer — `SASTBot v0.10.0`.

If any of those disagree after an upgrade, something has gone wrong
with the bump (typically `APP_VERSION` got missed in one of the three
files). Run `curl -s /version | jq .app` first; if it shows the old
value, the running process didn't pick up `APP_VERSION` — restart.

## When schema and app versions move together

A migration is paired with the feature that needed it. If you're
deploying a release that adds (say) a new column on
`scan_runs`:

- A new migration folder `prisma/migrations/<ts>_add_…/` exists in
  the new image.
- The schema version `(schema)` shifts to that folder's timestamp.
- The app version `(app)` bumps per the SemVer table.

Both happen as part of the same release. If you ever see schema-newer
than-app on a deployed instance, something's odd — most likely
someone applied a development migration directly without bundling
the corresponding code.

## The dump format version

Backups carry their own version: `dump_format_version` in
`metadata.json`. The current value is `2`. This is a separate axis
from the app and schema versions; it changes only when the tarball
*layout* changes (e.g. if SASTBot ever started compressing or
encrypting the dump). The restore endpoint refuses tarballs with a
`dump_format_version` lower than the backend's minimum.
