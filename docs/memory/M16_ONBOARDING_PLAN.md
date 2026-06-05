# M16 — First-run onboarding (replace the random bootstrap password)

**Status:** implemented 2026-06-01 (v0.20.0). Replaces the "random admin password
printed to the logs" first-boot experience with an operator-driven setup screen.

## Motivation

The auto-generated `admin@sastbot.local` password was irritating to fish out of
the logs, and conceptually the first admin should be a *real* account the
operator chooses — stored bcrypt-hashed, included in full backups, and therefore
carried across migrations like any other local account.

## Design

### Backend
- `bootstrapIfEmpty` still seeds the `default` org but no longer auto-creates an
  admin. Exception: the dev-only `BOOTSTRAP_ADMIN_PASSWORD` hatch (already a hard
  config error under `NODE_ENV=production`) still auto-creates the admin so local
  `docker compose down -v` iteration skips the setup screen.
- `GET /auth/setup-status` → `{ needs_setup }` (true iff zero admin users).
- `POST /auth/setup` `{ email, password (≥12) }` → creates the first admin and
  auto-logs-in (sets the session cookie). 409 once an admin exists. Race-safe via
  a Postgres advisory lock around the zero-admins check + insert
  (`services/setupService.ts::createFirstAdmin`).
- **Restore during the setup window.** The existing `POST /admin/db/restore` route
  is reused — its preHandler changes from `requireAdmin` to
  `requireAdminOrSetupWindow`, which allows an unauthenticated caller **only while
  zero admins exist**. Same trust window as `POST /auth/setup` itself; it slams
  shut the instant an admin exists (created by the form or carried in by the
  restored dump). The pure decision is `decideSetupGate(role, adminCount)`.

### Frontend
- New public `/setup` route (`SetupPage`) with two tabs: **Create admin** and
  **Restore a backup** (file + optional Source MASTER_KEY, reusing the M15 re-key
  path). `/login` redirects here when `needs_setup`; `/setup` redirects to
  `/login` once setup is done.

### Migration flow (chicken-and-egg, solved)
A fresh instance has no admin, but restoring a backup normally needs admin auth.
The setup-window restore closes that gap: on a fresh box, go to **Restore a
backup** on the setup screen → it restores the full backup (bringing the real
admin) → backend restarts → log in as the backup's admin. No throwaway account.

## Not in scope
- A general multi-user management UI (create/disable/role additional users) — the
  app remains effectively single-admin plus this onboarding. Tracked separately.

## Security notes
- The setup + setup-window-restore endpoints are unauthenticated but only function
  while zero admins exist — complete setup promptly on first deploy (same urgency
  as grabbing the old log password). Both are rate-limited / gated.
- Passwords are bcrypt (`passwordHash`), MASTER_KEY-independent → portable in
  backups. No schema migration needed.
