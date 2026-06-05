# M8 — Production DB operations plan (2026-05-20)

Locked scope: ship the four items below before the company LMI Dokploy
deploy. Goal: make schema iteration and feature shipping safe under real
production traffic without losing customer data.

The existing machinery (Prisma migrations, `_prisma_migrations` tracking,
`/api/admin/db/backup` + `/api/admin/db/restore` round-trip, worker-startup
backfills, the two-version model in `/version`) is **the foundation, not
the gap**. M8 closes the operational gaps around it.

Scope items, in priority order:

1. **Pre-deploy auto-backup, host-local.** Every Dokploy deploy takes a
   backup before the new containers start. Tarball written to the host
   filesystem. Bounded retention. Backup integrity relies on the gzip
   CRC32 already built into `.tar.gz` (see "Backup integrity" below); no
   separate hash file.
2. **Migrations checklist as `docs/MIGRATIONS_CHECKLIST.md`** — referenced
   from CLAUDE.md. The think-before-you-merge guide for any schema PR.
3. **Restore tiering** — add a `mode` param to `/api/admin/db/restore`:
   `full` (current behaviour) or `runtime`. Simple two-bucket partition:
   `runtime` preserves only auth + admin-configured tables (everything
   visible under "Admin" in the nav). Everything else restores naively
   from the dump.

Explicitly **NOT in scope**:
- Off-host backups (S3/B2/NAS). Deferred — host-local is sufficient
  while a single Dokploy node runs the trial.
- Scheduled / periodic backups beyond pre-deploy. Deferred.
- Staging stack. Deferred — the trial has been adequate as a single-env
  proving ground; revisit before the company LMI deploy if needed.
- Automated post-deploy smoke verification. Nice-to-have; manual for now.
- Per-row preservation of operator overrides inside otherwise-restored
  tables (e.g. `scope_components` manual-override rows). Deferred —
  Stream 3 takes the simple whole-table partition.

## Conventions every subagent must follow

- Read CLAUDE.md before touching anything. The non-obvious rules there
  override anything implied below.
- One stream = one focused commit (or a tight series). Match the existing
  commit-message style — see `git log --oneline -10`.
- TypeScript: strict, ESM, Zod-first. `tsc --noEmit` must pass.
- Backend tests: `docker compose -f docker/compose/docker-compose.yml exec
  backend pnpm test`. All existing tests must pass; add new ones for any
  new behaviour.
- Versioning: any schema change → committed migration folder. Any
  operator-visible change → version bump in BOTH package.json files. See
  CLAUDE.md "Versioning policy".
- Never push to remote. Never commit `.env`. Don't touch the homelab IP
  or any LMI hostnames in generic docs.
- For UI changes, browser-test after `tsc` passes.

### How subagents surface questions

If you hit any decision-shaped ambiguity — anything that could change
behaviour the operator sees, or anything where the spec below is silent —
STOP, return a short note to the main agent describing the choice and the
options. Do not pick one and proceed.

---

## Stream 1 — Pre-deploy auto-backup, host-local

**Why:** Currently the operator has to remember to click "Backup" in the
admin UI before triggering a Dokploy deploy. One forgotten step + a bad
migration = data loss. The backup must happen automatically as part of
the deploy lifecycle.

**Acceptance:**
- Triggering a deploy in Dokploy results in a `.tar.gz` backup landing
  on the Dokploy host in a known directory before the new containers
  start.
- After writing the tarball, the script runs `gunzip -t` against it to
  verify the gzip stream integrity (CRC32 check). Failure → see below
  under "Backup integrity".
- Backups are named with timestamp + git commit SHA:
  `sastbot-backup-2026-05-20T14-30-00Z-efc0f57.tar.gz`.
- Retention: keep the last N backups (default N=10); older are deleted.
  Configurable via an env var (e.g. `BACKUP_RETENTION_COUNT`).
- Backup directory is a Docker named volume so it survives `compose down`
  and is the same across redeploys.

**Backup integrity — why no separate SHA256.** `.tar.gz` files have a
built-in CRC32 checksum on the gzip stream. `gunzip -t <file>` verifies
the CRC and decompresses-to-/dev/null to catch any structural corruption,
which is exactly the threat model for host-local backups (partial writes,
disk bit-flip, truncation during retention rotation). CRC32 is not
cryptographic and won't detect tampering, but the host-local scope of
M8 doesn't expose backups to a tampering adversary — they sit on the
same filesystem as the live DB. If we later add off-host backups (where
the storage tier is partly trusted), revisit with HMAC-SHA256 keyed on
something not also exposed at the storage tier. Until then, `gunzip -t`
is sufficient and avoids cross-tool sync hazards.

**Design questions to resolve in implementation:**
- Where does the script live and what invokes it?
  - **Option A:** A new `scripts/pre-deploy-backup.sh` in the repo,
    called from a Dokploy "pre-deploy hook" if Dokploy supports one (it
    does — investigate the exact mechanism in Dokploy UI).
  - **Option B:** A short-lived sidecar service in the prod compose that
    runs once per deploy, takes the backup, exits 0. This couples the
    backup to compose lifecycle, not to Dokploy's deploy event.
  - **Option C:** The backend container takes its own pre-startup backup
    via an entrypoint script before running migrations. Simplest, but the
    backup happens AFTER the new image is pulled — if image pull is the
    failure mode, you have no backup of the broken-state DB to debug
    against (probably fine).
  - Recommend Option C as the minimal viable: a short script in
    `docker/backend-entrypoint.sh` that runs `pg_dump` against the
    `postgres` service before `prisma migrate deploy`. The pg_dump goes
    through an internal endpoint or directly via `pg_dump`. Falls back
    to manual click if the entrypoint can't reach the DB.
- Direct `pg_dump` vs hitting `/api/admin/db/backup` from inside the
  backend container?
  - Direct `pg_dump` is simpler, faster, doesn't require an HTTP server
    to be up yet. Loses the `metadata.json` wrapper.
  - Hitting `/api/admin/db/backup` requires auth, which means the
    entrypoint has to know an admin credential — operationally hairy.
  - Recommend direct `pg_dump` + reconstruct the metadata.json by
    reading the migration folder and `package.json` version at build
    time. Same final tarball shape, no auth dance.
- What happens if the backup fails? Deploy proceeds vs deploy aborts?
  - Recommend: deploy aborts on backup failure for production. This is
    a fail-safe; an operator can override via an env var (e.g.
    `ALLOW_DEPLOY_WITHOUT_BACKUP=true`) for emergencies.

**Files touched (estimate):**
- `docker/backend-entrypoint.sh` — new file. The current entrypoint is
  the inline `command:` in compose; replace with a script reference.
- `docker/compose/docker-compose.prod.yml` — switch `command:` to invoke
  the new entrypoint script.
- `docker/backend.Dockerfile` — COPY the entrypoint script in.
- `backend/src/services/backupMetadata.ts` (or similar) — small util that
  emits the same `metadata.json` shape as the existing backup route,
  callable from both the HTTP route and the entrypoint script.
- `docker/compose/docker-compose.prod.yml` — add a named volume
  `sastbot_backups` mounted into the backend container at the backup
  directory.

**Tests:**
- Unit test the metadata-emission util against a known schema + version.
- Manual test: trigger a Dokploy deploy, verify tarball appears with
  hash file, verify hash matches, verify retention rotates.

---

## Stream 2 — Migrations checklist (`docs/MIGRATIONS_CHECKLIST.md`)

**Why:** Schema changes are the highest-blast-radius change we ship. A
checklist of "have you thought about X?" prevents the obvious mistakes
that have well-known patterns. Should be referenced from CLAUDE.md so
every contributor sees it before merging a schema-touching PR.

**Acceptance:**
- `docs/MIGRATIONS_CHECKLIST.md` exists, ~80–150 lines.
- CLAUDE.md "Versioning policy" section has a one-line reference: "Before
  writing any migration, work through `docs/MIGRATIONS_CHECKLIST.md`."
- The checklist covers:
  - **Naming:** migration folder name accurately describes the change.
  - **Rename pattern:** Prisma's default DROP+ADD = data loss. Manual
    SQL edit to `ALTER TABLE ... RENAME COLUMN ...` required.
  - **Adding NOT NULL to populated tables:** two-step pattern — add
    nullable + worker backfill + follow-up migration with NOT NULL.
  - **Big-table locking:** ALTER TABLE on large tables blocks writes.
    For indexes, use `CREATE INDEX CONCURRENTLY`. For column defaults
    on Postgres 11+, fast-path is automatic. Note the largest tables in
    SASTBot today (`sbom_components`, `sast_issues`, `scan_warnings`).
  - **Cascade and FK changes:** grep for usages before changing
    `onDelete` behaviour.
  - **JSON columns:** Prisma doesn't enforce shape. When changing JSON
    shape, code reads both old + new for a release; worker backfill
    rewrites; later code removes old-shape read.
  - **Enums:** Postgres enums are append-only without manual SQL.
    Removing/renaming values needs explicit DDL.
  - **Multi-table refactors:** the M7 sbom_components → scope_components
    pattern. Create new table, backfill, dual-write, eventually drop.
  - **Worker backfills:** when needed, file location (`backend/src/worker/backfills/`),
    idempotency contract (filter own work, safe to re-run).
  - **App-version bump:** schema-only changes are PATCH; new-feature
    columns are MINOR; destructive changes are MAJOR (pre-1.0: MINOR).
- A worked example at the bottom: "Add `repos.notify_on_completion`
  (nullable boolean)" walks through every checklist item.

**Files touched:**
- `docs/MIGRATIONS_CHECKLIST.md` — new.
- `CLAUDE.md` — one-line reference added under "Versioning policy".

---

## Stream 3 — Restore tiering (`mode=runtime` vs `mode=full`)

**Why:** The current restore replaces the entire DB. If an operator has
since rotated a credential or updated Jira config, those edits are lost
when restoring from yesterday's backup. The operator's mental model is:
"I want to undo bad scan data, not undo my settings."

**Acceptance:**
- `POST /api/admin/db/restore` accepts a `mode` query parameter:
  - `mode=full` (default — current behaviour). Restores everything.
  - `mode=runtime`. Restores everything **except** auth + admin-config
    tables; the current values of those tables are preserved as-is.
- The UI restore dialog has a clear radio button: "Full restore (rebuild
  from scratch)" vs "Runtime-only restore (undo scan data, keep
  settings)".
- Documented in `docs/user/backup-restore.md` (create if absent).

**Design — the table partition.** The mental model is the navigation
bar: anything an operator manages under "Admin" is preserved in
`runtime` mode. Everything else restores naively from the dump.

| Bucket | Tables | `mode=runtime` | `mode=full` |
|--------|--------|----------------|-------------|
| Auth + Admin config | `users`, `sessions`, `app_settings`, `credentials`, `repos` | **PRESERVE** current | **RESTORE** from dump |
| Everything else | `scopes`, `scope_components`, `sbom_components`, `scan_runs`, `scan_warnings`, `sast_issues`, `sca_issues`, `recheck_verdicts`, `eol_facts`, `issue_jira_links`, `cve_knowledge` (and any future scan-output / operator-curated-but-non-admin tables) | **RESTORE** from dump | **RESTORE** from dump |
| Migration tracking | `_prisma_migrations` | always RESTORE | always RESTORE |

Whole-table partition only — no per-row filtering. Manual overrides in
`scope_components` are restored from the dump (operator's recent
hand-edits since the backup are lost; this is acceptable per the user's
direction — simpler logic wins). When in doubt, document that the
operator should use `mode=full` to fully undo, or back up immediately
before restoring if hand-edits are precious.

**Implementation sketch:**
- The endpoint runs `pg_restore` into a temporary schema (`restore_temp`),
  not the public schema.
- For each table:
  - In `runtime` bucket "Auth + Admin config": do nothing (current
    `public.<table>` stays).
  - Otherwise: `TRUNCATE public.<table>; INSERT INTO public.<table>
    SELECT * FROM restore_temp.<table>;`
- Wrap in a transaction. Roll back on any failure.
- Drop `restore_temp` at the end.

**Foreign-key edge case** (document, don't engineer around):
`scan_runs.repo_id` and similar references point at preserved tables
(`repos`, `users`). If the operator deleted a repo or user between
backup and restore, restoring scan data referencing the now-deleted ID
will FK-fail and abort the transaction. The doc should warn: "If you've
deleted any admin-managed resources (repos or users) since the backup
was taken, use `mode=full` instead." The endpoint can detect this
condition (LEFT JOIN check before the restore inserts) and surface a
clear error pointing the operator at `mode=full`.

**Files touched:**
- `backend/src/routes/adminBackup.ts` (or wherever the restore endpoint
  lives) — add `mode` param parsing and the tiered-restore logic.
- `backend/src/services/restoreService.ts` — extract the tiered logic
  into a service for testability.
- `frontend/src/routes/admin/SettingsPage.tsx` — UI radio for restore
  mode + clearer copy.
- `docs/user/backup-restore.md` — new, explains the two modes and the
  FK edge case.

**Tests:**
- Backend integration test: seed dev DB with admin config + scan data,
  take a backup, modify both, restore with `mode=runtime`, verify
  admin config preserved and scan data rolled back.
- Backend integration test: restore with `mode=runtime` after deleting
  a repo → endpoint returns a clear error, transaction does not commit.
- Frontend Vitest test: radio toggles the request param correctly.

---

## Order of work

1. **Stream 2 (checklist)** — Pure docs, no risk, useful immediately.
   Sonnet can do this in one session.
2. **Stream 1 (pre-deploy backup)** — Highest blast-radius safety net.
   Touches Dockerfile, entrypoint, compose. One focused commit.
3. **Stream 3 (restore tiering)** — Backend + frontend. The biggest
   coding stream. Sonnet sub-agents could do backend + frontend in
   parallel after the table partition is locked.

Streams 1+2 can ship in either order; both must be done before any new
schema change goes to the trial. Stream 3 can sequence after.

## Known follow-ups (post-M8)

- **Staging stack.** A second Dokploy application that mirrors prod
  with a recent backup restored. Tests destructive migrations against
  real data shapes before prod runs them. Deferred until the trial has
  shaken out — revisit before the company LMI deploy.
- **Off-host backup pipeline** (S3-compatible). Required before any
  production deploy where the Dokploy host's local disk is the only
  copy of the data — currently the trial accepts that risk.
- **Scheduled backups** beyond pre-deploy (nightly, weekly). Pairs with
  the off-host pipeline.
- **Automated post-deploy smoke script** (curl /healthz /version + a
  domain endpoint, alert on mismatch). Currently manual.
- **Automated restorability verification cron.** Periodically restore
  the latest backup into a throwaway DB and run a smoke check — catches
  "the backup format silently broke" before you need it.
- **Migration dry-run tool**: `prisma migrate diff
  --from-schema-datasource --to-schema-datamodel --script` to preview
  the SQL before running it.
- **pg_dump throughput on multi-GB DBs** (currently untested at scale).
- **HMAC-SHA256 on backups** when we move to off-host storage where the
  storage tier is partly trusted. See "Backup integrity" in Stream 1.
