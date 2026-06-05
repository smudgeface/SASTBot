# M18 — `member` role (RBAC middle tier)

**Status:** planned 2026-06-02. Target version **0.22.0** (assuming M17 lands as
0.21.0 first). Builds directly on M17 (local user management) — the `users.role`
column and the user CRUD already exist; this adds a third role between `user`
and `admin`.

## Goal

Add a **`member`** role for developers tasked with improving product security.
They can work the triage queue and curate SBOM/findings state, but cannot run
scans or touch configuration. Privilege ladder:

```
user   <  member  <  admin
read-only   work the findings   everything
+ notes     + jira + triage + components
```

## Capabilities (the exact split)

**`member` gets everything `user` has, PLUS (the routes that move
`requireAdmin` → `requireMember`):**
- Triage SAST issues — `POST /api/sast-issues/:id/triage`
- Dismiss SCA issues — `POST /api/sca-issues/:id/dismiss`
- Link / unlink Jira tickets — `POST|DELETE /api/sast-issues/:id/jira-ticket`,
  `POST|DELETE /api/sca-issues/:id/jira-ticket`
- Refresh a Jira ticket — `POST /api/admin/jira-tickets/:key/refresh`
- Modify / remove / hide components — `PATCH`, `DELETE`,
  `POST …/ignore`, `POST …/unignore` on `/api/scopes/:id/components/:componentId`
- Add a component — the planned "Add component" route (pending feature) should be
  gated at `member` too when it ships (note it in that feature's brief).

> Per the current code, **all 11 `requireAdmin` handlers in `scopes.ts` are
> finding/Jira/component mutations** — every one moves to `requireMember`. Audit
> each before flipping; if any *scope/repo config* mutation is hiding in there,
> keep it `admin`.

**`member` still CANNOT (stays `requireAdmin`):**
- **Trigger / cancel / delete scans** — `POST /api/admin/repos/:id/scan`,
  `POST /api/scans/:id/cancel`, `DELETE /api/scans/:id`. ("For now, no scans.")
- **All configuration** — repos, credentials, settings/LLM, **users**,
  backup/restore, MASTER_KEY rotation (`adminRepos`, `adminCredentials`,
  `adminSettings`, `adminUsers`, `adminBackup`, `adminRestore`, `adminKeyRotation`).

**`user` is unchanged** — read everything + notes only.

## Backend changes

1. **Role enum everywhere → add `member`** (`backend/src/schemas.ts`, ~5 spots):
   `RoleSchema = z.enum(["admin","member","user"])`, and `UserOutSchema.role`
   (line ~46). `CreateUserBody`/`UpdateUserBody`/`UserAdminOut` already use
   `RoleSchema`. **Order the enum admin→member→user** for readable docs.
2. **Fix the mapper collapse (critical).** `services/mappers.ts` `userToOut` and
   `userToAdminOut` currently do `role: user.role === "admin" ? "admin" : "user"`
   — this reports a `member` as `user`. Change both to pass the real role through,
   validated against the enum, e.g. `role: normalizeRole(user.role)` where
   `normalizeRole` returns `admin|member|user` (default `user` for any legacy/odd
   value). Without this, `/auth/me` for a member fails response serialization
   (role not in the enum) AND the Users list mislabels them.
3. **New `requireMember` gate** in `plugins/auth.ts`, beside `requireAdmin`.
   Prefer a small privilege-rank helper so it's not scattered string checks:
   ```ts
   const RANK = { user: 0, member: 1, admin: 2 } as const;
   function rank(role) { return RANK[role] ?? 0; }
   // requireMember: 401 if no user; 403 if rank < member; else allow
   ```
   Keep `requireAdmin` as-is. `requireAdminOrSetupWindow` unchanged.
4. **Re-gate routes** in `scopes.ts`: the 11 finding/Jira/component handlers
   `requireAdmin` → `requireMember`. Leave `scans.ts` (cancel/delete) and all
   `admin*` routes on `requireAdmin`.
5. **Last-admin invariant is unaffected but VERIFY:** `userService` counts
   `role === "admin"` only, so a `member` never counts as an admin and the
   guard still protects the last *admin*. Creating/updating a user to `member`
   needs no special logic (the schema enum allows it). Add a test: demoting the
   last admin to **member** is rejected (it removes the last admin).
6. **No DB migration** — `role` is free `TEXT` (no CHECK constraint); `"member"`
   is just a new value. Confirm no constraint exists, then skip the migration.

## Frontend changes

1. `Role` type already includes `"member"` (`api/types.ts`) — good. Add `member`
   to the **role `<Select>`** options in the Users create + edit dialogs, and a
   distinct **role badge** style on the Users table.
2. **Capability gating (also fixes an M17 gap).** Today the scope-detail action
   buttons (triage, dismiss, Jira link, component edit/delete/ignore) are likely
   rendered for everyone and rely on the backend 403 — so a `user` sees buttons
   that fail. Add a tiny capability helper, e.g. `lib/permissions.ts`:
   ```ts
   canModifyFindings(role) => role === "admin" || role === "member"
   canAdminister(role)     => role === "admin"
   ```
   Gate the scope-detail finding/Jira/component actions on `canModifyFindings`
   (shown to member+admin, hidden from user). Admin pages keep `RequireAdmin`.
   **Audit `ScopeDetailPage` + the SCA/SAST/Components panels** for where those
   actions render and gate them. No new *route* guard is needed — members use the
   same scope pages, just with more buttons enabled.
3. Regenerate `schema.d.ts` after the backend enum change.

## Tests
- `requireMember` gate: admin→allow, member→allow, user→403, anon→401.
- A representative re-gated route (e.g. dismiss SCA) accepts a `member` and still
  rejects a `user`.
- Scan trigger / a config route still rejects a `member` (403).
- Last-admin guard: demote-last-admin-to-member rejected.
- `userToOut`/`userToAdminOut` round-trip `member` (regression for the collapse).
- Frontend: a `member`-role `me` shows finding actions but no admin nav; a `user`
  shows neither.

## Docs / versioning
- `docs/user-manual/admin-users.md` — expand the role table to three rows
  (admin / member / user) with the capability split above.
- Update the M17 "role semantics" note + `CLAUDE.md` (the auth bullet) to describe
  three tiers and `requireMember`.
- App **0.21.0 → 0.22.0** (3 surfaces + lockfile; MINOR — new capability). PROGRESS entry.
- Live-verify in the browser: create a `member`, confirm they can triage/dismiss/
  Jira-link/edit a component but get 403 on scan-trigger and see no admin nav.

## "Anything else?" — decisions to confirm at kickoff
- **Attribution.** With multiple non-admins changing finding state, "who
  dismissed this / set this status?" becomes useful. The schema likely doesn't
  record the actor on triage/dismiss today. **Out of scope for M18** unless you
  want it — flag as a follow-up (would need a `*_by` column + plumbing).
- **Notes.** `member` keeps note-adding (already any-user). Fine.
- **Jira config vs use.** `member` can link/refresh tickets but not configure Jira
  credentials (admin). Intended.
- **Scope/repo settings** (source_url_template, ignore_paths, reachability,
  includeDevDeps) stay **admin** — they're repo config, not "scope state."
- **Naming.** "member" matches the frontend type's existing literal. Keep it.

## Dependency note
M18 sits on top of **M17 (`feature/m17-user-management`)**, which at the time of
writing is **staged but not committed** (under review; an `.git/index.lock` was
present). The fresh session must first confirm M17 is committed/merged (or branch
M18 off the M17 branch) — don't start M18 against a tree where M17's role
plumbing isn't in place.
