# M17 — User management, Phase 1 (local accounts + native password change)

**Status:** planned 2026-06-02. Target version **0.21.0**. First half of the
two-phase user-management roadmap ([[project_pending_features]]); Phase 2 (OIDC /
Google Workspace) is separate and builds on this.

## Goal

Give SASTBot real local user management: admins create/manage accounts, every
user can change their own password in-app, and admin-set passwords are one-time
(forced change on first login). Removes the two gaps that bit the first prod
deploy — no in-app password change, and `admin@sastbot.local` / `admin` with only
a CLI reset to harden it.

## Locked decisions (operator, 2026-06-02)

1. **Full Phase 1 as one milestone** — change-password + admin user CRUD together.
2. **Admin sets the initial password** (no SMTP/email infra); shared out-of-band.
3. **Force change on first login** via a `mustChangePassword` flag on admin-created
   and admin-reset accounts.

## Role semantics (stated default — veto if wrong)

Two roles already exist in code: `admin` and `user`. Today every domain route
(`/scopes`, `/scans`, …) requires only `authenticate` (any logged-in user);
`/admin/*` requires `requireAdmin`. Phase 1 keeps that: a **`user`** can view and
run scans and browse findings, but cannot touch repos, credentials, settings, or
user management. No new per-route gating beyond what exists.

## Schema (one migration)

Add to `users`:
- `must_change_password BOOLEAN NOT NULL DEFAULT false` — set true on admin
  create + admin reset; cleared on a successful self-change. Default false means
  existing users (and restored older dumps) are unaffected — no backfill needed.
- `name TEXT NULL` — optional display name for the user list. Nullable, trivial.

Both are safe additions to a populated table (defaulted / nullable, no rewrite,
no NOT-NULL backfill). `prisma migrate dev --name add_user_mgmt_fields`; commit
the folder (that IS the schema-version bump).

## Backend

### Self-service
- `POST /api/auth/change-password` — `{ current_password, new_password }`, any
  authenticated user. Verify current (bcrypt); enforce new ≥ `SETUP_PASSWORD_MIN_LENGTH`
  (12) and ≠ current; set new hash; clear `mustChangePassword`; **revoke the
  user's other sessions** (keep the current one). 400 on bad current / weak new.

### Forced-change gate
A request-level guard: when `req.user.mustChangePassword` is true, block every
authenticated route except an allowlist (`/auth/change-password`, `/auth/logout`,
`/auth/me`) with **403 `{ detail, code: "password_change_required" }`**. Added in
`plugins/auth.ts` after `req.user` is resolved (null user → public routes
unaffected). `must_change_password` is also surfaced on `/auth/me` (UserOut) so
the SPA can redirect proactively; the backend gate is the real enforcement.

### Admin user CRUD (`/api/admin/users`, all `requireAdmin`, org-scoped)
- `GET    /admin/users` — list (id, email, name, role, is_active, must_change_password, last_login_at, created_at).
- `POST   /admin/users` — `{ email, name?, role, password }` → create with
  `mustChangePassword=true`. 409 on duplicate email; password ≥ 12.
- `PATCH  /admin/users/:id` — `{ name?, role?, is_active? }`.
- `POST   /admin/users/:id/reset-password` — `{ password }` → set temp password,
  `mustChangePassword=true`, revoke that user's sessions.
- `DELETE /admin/users/:id` — delete (sessions cascade).

### Invariants / guard rails (security-critical)
- **Never zero active admins.** Any operation that would remove the last active
  admin (demote role away from `admin`, set `is_active=false`, or delete) is
  rejected with a clear 409. Enforced in a `prisma.$transaction` guarded by a
  Postgres advisory lock (same pattern as `createFirstAdmin`) so concurrent
  demotions can't both pass the check.
- **No self-lockout.** An admin cannot delete or disable **their own** account,
  nor demote themselves, via these routes (avoids the obvious foot-gun; the
  last-admin rule is the backstop for everything else).

### Services
New `services/userService.ts`: `listUsers`, `createUser`, `updateUser`,
`resetUserPassword`, `deleteUser`, `changeOwnPassword`, plus a
`countActiveAdmins(tx)` helper and the advisory-locked guard. Reuse
`security/passwords.ts` (bcrypt) and `security/sessions.ts` (`revokeAllSessionsForUser`
— add if missing).

### Schemas (Zod, `schemas.ts`)
`UserAdminOutSchema`, `CreateUserBodySchema`, `UpdateUserBodySchema`,
`ResetPasswordBodySchema`, `ChangePasswordBodySchema`. Extend `UserOutSchema`
with `must_change_password: boolean`. Reuse `SETUP_PASSWORD_MIN_LENGTH`.

## Frontend
- **Forced change:** a `RequireAuth`-level check — if `me.must_change_password`,
  redirect to `/account/change-password` (a focused screen) and block the rest of
  the app until it succeeds. Also handle a `password_change_required` 403 from any
  API call (belt + suspenders).
- **Self-service change password:** reachable normally from a user menu / account
  area (same screen, non-forced mode).
- **Admin Users page** `/admin/users` (RequireAdmin): table + create dialog +
  edit (name/role/active) + reset-password dialog + delete confirm. Mirror
  `ReposPage`/`CredentialsPage` patterns. Add **Users** to the sidebar ADMIN nav.
- `api/queries/users.ts` (TanStack hooks); regenerate `schema.d.ts`.

## Versioning / docs
- App **0.20.0 → 0.21.0** (3 surfaces + lockfile, 2 lines only).
- Migration folder committed (schema-version bump).
- New manual page `docs/user-manual/admin-users.md` **+ manifest entry** in
  `frontend/src/manual/index.ts`; note change-password in the account/quick-start
  flow. PROGRESS.md entry. Update CLAUDE.md "For AI agents" with the last-admin
  invariant.

## Out of scope (later)
- Phase 2: OIDC / Google Workspace SSO (separate milestone; the `AuthBackend`
  interface is already the hook).
- Email invites / SMTP, self-service signup, password-reset-by-email, audit log
  of admin user actions, per-resource ACLs beyond admin/user.

## Test plan
- `userService` unit: create sets mustChangePassword; changeOwnPassword verifies
  current + clears flag + rejects weak/same; last-admin guard rejects
  demote/disable/delete of the final admin; self-lockout rejected.
- Gate: `mustChangePassword` blocks a normal route, allows the allowlist.
- Frontend: forced-change redirect; admin users table smoke.
- Full suite + `npm ci --dry-run` before push.
