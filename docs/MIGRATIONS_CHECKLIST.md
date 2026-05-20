# Migrations checklist

Work through this before merging any PR that touches `backend/prisma/schema.prisma` or adds a folder under `backend/prisma/migrations/`. Each item is here because we (or someone like us) got bitten by skipping it.

If anything below is unclear, read `CLAUDE.md`'s "Versioning policy" section first — that's the source of truth.

## 1. Name the migration accurately

The folder name **is** the schema version (`getExpectedSchemaVersion()` reads the lexicographically-last name). It also lands in commit messages, release notes, and backup metadata.

- Use `pnpm prisma migrate dev --name short_imperative_summary`.
- Prefix optional: a milestone tag (`m8_…`) is fine when the work belongs to a tracked milestone.
- Avoid generic names like `update_schema` or `fix`. Someone reading `git log` six months from now needs the gist.

## 2. Commit the migration folder

Editing `schema.prisma` without committing the generated migration folder is a bug. The next deploy either fails (drift detected) or silently re-runs `prisma generate` against a schema the live DB doesn't have.

```bash
git add backend/prisma/schema.prisma backend/prisma/migrations/<timestamp>_<name>
```

If the migration produced unexpected SQL, **edit `migration.sql` before committing**, then `pnpm prisma migrate reset` and re-apply. Do not edit a migration after it has been applied to any deployed environment.

## 3. Renames lose data unless you hand-edit the SQL

Prisma's default for a renamed column or table is `DROP` + `ADD`. That's a silent data-loss event in production.

After `prisma migrate dev`, **open `migration.sql`** and look for `DROP COLUMN` / `DROP TABLE` paired with `ADD COLUMN` / `CREATE TABLE` of the new name. Replace with:

```sql
ALTER TABLE foo RENAME COLUMN old_name TO new_name;
-- or
ALTER TABLE old_name RENAME TO new_name;
```

There are real examples of this pattern in the tree — see `20260422185652_rename_credential_label_to_name` and `20260426040800_m6h_rename_optional_to_dev`.

## 4. Adding `NOT NULL` to a populated table is two migrations

A `NOT NULL` constraint on a column the table doesn't already have data for will fail on `prisma migrate deploy` against any non-empty production DB. The pattern is:

1. Migration A: add column as `NULL`able with a sensible default or `NULL`.
2. Code change: write to the column from new requests; add a worker backfill (see §9) for existing rows.
3. Migration B: once the backfill is complete in all environments, switch the column to `NOT NULL`.

Skipping the second migration is fine if the column has a constant default — the default fills new rows and you can leave existing rows `NULL` if your code tolerates it.

## 5. Adding a column with a default on a large table

Postgres 11+ adds a column with a constant default in O(1) — it's stored as table metadata and only filled in on write. Volatile defaults (`now()`, `gen_random_uuid()`) still rewrite the table.

SASTBot's largest tables today are `sbom_components`, `sast_issues`, and `scan_warnings`. If you're adding a column with a non-constant default to one of these, expect a long lock; consider doing it in two steps (add nullable → backfill → set default for future inserts).

## 6. Index changes — use `CREATE INDEX CONCURRENTLY` for big tables

`CREATE INDEX` takes an `ACCESS EXCLUSIVE` lock and blocks writes for the duration. On `sbom_components` or `sast_issues` that's not acceptable in production.

Prisma generates plain `CREATE INDEX`. To use the concurrent form, edit `migration.sql` after generation:

```sql
CREATE INDEX CONCURRENTLY foo_bar_idx ON foo (bar);
```

`CONCURRENTLY` cannot run inside a transaction. Prisma wraps each migration in one by default; you'll need to add `-- prisma+postgres NoTransaction` (or split the index into its own migration that does only this). When in doubt, ask before merging.

## 7. Foreign-key + cascade changes — grep first

Changing `onDelete: Cascade` to `Restrict` (or back) reshapes failure modes. Before merging:

```bash
grep -rn "<TableName>" backend/src/services backend/src/routes
```

If callers rely on cascade behaviour (e.g. the per-scan `sbom_components` rows that disappear when a `scan_run` is deleted), you need an explicit cleanup path. Likewise, going from `Restrict` → `Cascade` can silently widen blast radius — operators who used to get a clear "can't delete X, Y references it" now lose Y too.

## 8. JSON columns: Prisma does not enforce shape

`@db.JsonB` is opaque to Prisma. The compiler will not catch you if you change the embedded shape.

When changing JSON shape:

1. Code reads **both** old and new shapes for at least one release.
2. Worker backfill rewrites existing rows to the new shape (see §9).
3. Code stops reading the old shape only after the backfill has run in every environment.
4. Document the shape in a Zod schema or TypeScript type near the producer.

Recent examples: `sbom_components.occurrences`, `scope_components.evidence`. Both are validated at the read site by a hand-written narrowing function.

## 9. Worker backfills — when a migration alone isn't enough

If existing rows need to be populated based on app logic (not pure SQL), add an idempotent backfill function and invoke it from `backend/src/worker.ts` at boot. Existing examples in `worker.ts`: `backfillLlmSummaries`, `backfillScanRunSeverities`, `backfillManifestPathPrefixes`, `backfillSastSarif`. Others live in their service files and are imported into `worker.ts` (`backfillCvssScores`, `backfillManifestOrigin` in `osvService.ts`; `backfillReachability` in `reachabilityService.ts`).

The contract:

- **Filter for own work.** Don't scan every row every boot — use `WHERE col IS NULL` or `notIn: attempted` so the function is cheap to leave in place.
- **Idempotent.** Re-running must be a no-op if there's nothing to do.
- **Failure is not fatal to boot.** Wrap the call in `.catch((err) => logger.warn(…))` — the worker should still come up if a backfill row blows up.
- **Leave the call in place.** Future restores of older dumps will need it again.

**Do NOT** write a boot backfill that reads from `sbom_components` and inserts into `scope_components` — that exact pattern caused M7's row-duplication incident. Scope-level state is bootstrapped natively by the scan flow (`persistScanComponentsToScopeState` + `componentMatch`); see CLAUDE.md "Two-table component model".

If a one-off rewrite is needed (e.g. de-duplicating an existing table), prefer a one-off SQL pass inside a `prisma migrate` migration over a worker backfill — see `20260515090000_dedup_sbom_components_by_purl` for the pattern.

## 10. Postgres enums are append-only without manual SQL

Adding a new value to an existing enum is safe and Prisma handles it. Removing or renaming a value requires explicit DDL:

```sql
-- Postgres has no DROP VALUE. The pattern is:
ALTER TYPE my_enum RENAME TO my_enum_old;
CREATE TYPE my_enum AS ENUM (...);   -- new value set
ALTER TABLE foo ALTER COLUMN bar TYPE my_enum USING bar::text::my_enum;
DROP TYPE my_enum_old;
```

Migrate-deploy will fail with a confusing error if you skip this and just drop the value in the Prisma enum.

## 11. Multi-table refactors — the dual-write pattern

When splitting one table into two (or merging two into one), do not switch over in a single PR. The pattern (used in M7 for `sbom_components` → `scope_components`):

1. **Migration:** create the new table; leave the old one in place.
2. **Code, release N:** dual-write to both. Reads still come from the old table.
3. **Backfill:** populate the new table from existing data.
4. **Code, release N+1:** reads come from the new table. Old table still receives writes for rollback safety.
5. **Migration:** drop the old table.

Skipping any step removes the ability to roll back a failed deploy.

## 12. App-version bump rules

After any schema change, decide whether the app version needs to move (the migration folder name covers schema versioning automatically — this is about the SemVer in both `package.json` files).

| Schema change | App-version bump |
|---|---|
| Pure internal refactor, no operator-visible difference | PATCH (`0.2.0 → 0.2.1`) |
| New column / table that feeds a new endpoint or UI | MINOR (`0.2.0 → 0.3.0`) |
| Removed column / table, or column rename in an externally-visible payload | MINOR pre-1.0; MAJOR post-1.0 |
| Destructive migration (drops data the operator cared about) | MINOR pre-1.0 + clear PROGRESS.md note; MAJOR post-1.0 |

Bump **both** `backend/package.json` AND `frontend/package.json` in the same commit. The footer in the admin Settings page reads from the frontend value, and `GET /version` reads from the backend constant in `version.ts` — drift = operators see a lie.

## 13. Test the restore round-trip

The two-version model (app vs schema) only protects operators if cross-version restore works. If your migration changes data shape (not just structure), exercise restore locally:

```bash
# Before your migration is applied:
curl -u admin:pw -o pre.tar.gz http://localhost:8000/api/admin/db/backup
# Apply migration, redeploy, then:
curl -u admin:pw -F file=@pre.tar.gz http://localhost:8000/api/admin/db/restore
```

The endpoint will auto-run `prisma migrate deploy` against the older dump and refuse to restore a newer-than-current dump (HTTP 422). If either path fails for your migration, that's a bug in the migration or a missing forward-compat shim.

---

## Worked example: add `repos.notify_on_completion`

A nullable boolean column controlling whether the worker emails an admin when a scan finishes. New optional setting in the repo editor UI.

1. **Schema edit** — add `notifyOnCompletion Boolean? @map("notify_on_completion")` to the `Repo` model.
2. **Generate migration** — `pnpm prisma migrate dev --name add_repo_notify_on_completion`. Inspect the generated `migration.sql`: should be a single `ALTER TABLE "repos" ADD COLUMN "notify_on_completion" BOOLEAN;`. No `DROP`, no rewrite of a large table (constant default → fast — §5). ✅
3. **NOT NULL?** No — operators with existing repos shouldn't have a value forced on them. Default is to do nothing (NULL means "unset"). Skip §4's two-step pattern.
4. **Indexes?** None added — this column won't be queried by itself. Skip §6.
5. **Cascades?** No FK change. Skip §7.
6. **JSON shape?** Not JSON. Skip §8.
7. **Backfill?** No — NULL is a valid initial state and code treats it as "no notification". Skip §9.
8. **Enum?** Boolean, not an enum. Skip §10.
9. **Multi-table?** Single table, additive. Skip §11.
10. **App-version bump** — operator-visible (new toggle in repo UI, new behaviour). MINOR bump: `0.2.0 → 0.3.0`. Both `package.json` files in the same commit, run `pnpm install` and `npm install` to update lockfiles. ✅
11. **Restore round-trip** — back up before the migration, restore after. Endpoint auto-applies the migration; the restored DB has the new column as NULL on every existing row. ✅
12. **PROGRESS.md** — entry naming the migration folder and the version bump.

Total touched files: `backend/prisma/schema.prisma`, `backend/prisma/migrations/<ts>_add_repo_notify_on_completion/`, `backend/package.json`, `backend/pnpm-lock.yaml`, `frontend/package.json`, `frontend/package-lock.json`, the feature code, the PROGRESS entry. One commit (or a tight series).
