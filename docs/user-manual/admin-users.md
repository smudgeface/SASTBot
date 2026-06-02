# Users

Manage local SASTBot accounts under **Admin → Users**. Every account is a local
login (email + password); passwords are stored hashed and travel with database
backups.

## Roles

| Role | Can do |
|---|---|
| **Admin** | Everything — repos, credentials, settings, backups, and user management. |
| **User** | View and run scans, browse findings. Cannot change configuration or manage users. |

## Adding a user

**Admin → Users → Add user.** Enter an email, an optional name, a role, and a
**temporary password** (click *Generate* for a strong random one). Share that
password with the person securely (e.g. your password manager's sharing, not
email).

The temporary password is **one-time**: the new user signs in with it and is
immediately required to set their own password before they can do anything else.

## Changing your own password

Any signed-in user can change their password from **Change password** in the
sidebar (or directly at `/account/change-password`). You'll need your current
password; the new one must be at least 12 characters. Changing it signs out your
other sessions.

If your account was created or reset by an admin, you'll be sent to this screen
automatically on next login and can't proceed until you set a new password.

## Editing, disabling, and resetting

- **Edit** — change a user's name or role, or toggle **Active**. Disabling an
  account blocks sign-in immediately and ends its sessions; the account and its
  data are preserved.
- **Reset password** — set a new one-time password for someone who's locked out.
  It signs them out everywhere and forces a fresh password on next login.
- **Delete** — permanently remove the account and its sessions.

## Guard rails

SASTBot won't let you lock everyone out:

- You **can't** remove the **last active admin** — demoting, disabling, or
  deleting the final admin is rejected. Promote or enable another admin first.
- You **can't** change your own role or active status, or delete your own
  account, from this page (so you can't accidentally lock yourself out). Ask
  another admin.

## What's coming

Single sign-on with your organization's Google Workspace accounts is planned as a
later phase; for now, accounts are local logins managed here.
