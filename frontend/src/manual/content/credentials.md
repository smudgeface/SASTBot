# Credentials

A credential in SASTBot is one row in the `credentials` table holding
encrypted secret material for one specific use case. Every secret
SASTBot needs at runtime — a Git password, an LLM API key, a Jira
token, an NVD key — is stored as a credential and referenced by
foreign-key from the places that use it.

## Credential kinds

| Kind | Used by | Stored fields |
|---|---|---|
| `https_token` | Repos (HTTPS clone with token-as-password) | `value` (token), optional `username` |
| `https_basic` | Repos (HTTPS clone with username + password) | `username`, `password` |
| `ssh_key` | Repos (SSH clone) | `value` (private key PEM), optional `passphrase` |
| `jira_token` | Settings → Jira | `value` (API token) — paired with account email in Settings |
| `llm_api_key` | Settings → LLM gateway | `value` (API key) |
| `nvd_api_key` | Settings → NVD | `value` (NVD developer key) |

Every credential row has a `name` (operator-supplied label) and a
`kind`. Each kind only accepts its own subset of fields; the form on
the **Admin → Credentials** page only shows fields relevant to the
selected kind.

## Encryption posture

- Every secret field is encrypted at rest with **AES-256-GCM**.
- The master encryption key is the `MASTER_KEY` env var, expected as a
  32-byte base64-encoded value.
- A **canary** row exists in the `credentials` table that lets the
  backend verify on startup that `MASTER_KEY` decrypts correctly. If
  it doesn't — typically because the env var was rotated, lost, or
  swapped — the backend refuses to boot with a loud error rather than
  silently failing every credential decrypt.
- Plaintext never leaves the backend. The frontend never receives
  secret material; it only sees the credential's name, kind, and
  reference counts.

See [Deployment](admin-deployment#master-key) for `MASTER_KEY`
provisioning and rotation guidance.

## Creating credentials

Two paths:

1. **Admin → Credentials** — top-level CRUD with the full form.
2. **Inline from another form** — Repos and Settings forms both let
   you create a credential without leaving the page. The picker on
   each has a **Create new** radio that swaps in the credential
   fields. On save, the credential is created first, then the
   referencing record (repo / setting) is saved with the new id.

## Editing credentials

The credentials page lets you update a credential's `name` and the
`value` / `password` / `private_key` fields. The kind cannot be
changed after creation; if you need to convert (e.g. from
`https_token` to `ssh_key`), create a new credential and switch the
references.

Editing the value of a credential does NOT invalidate references —
repos and settings keep pointing at the same row, they just get a new
secret next time they use it.

## Reference counts

Each credential row's display includes a `reference_count` derived
from the `references` aggregate:

- `repos` — how many repos point at this credential.
- `jira_settings`, `llm_settings`, `nvd_settings` — boolean flags for
  the global settings page references.

A reference of 0 means the credential is unused and safe to delete.

## Deletion

The **Delete** action on each row works as follows:

- All references are detached automatically — the FK is `ON DELETE SET
  NULL`, so a deleted credential leaves repos / settings with a null
  credential reference (and a warning visible in the relevant form).
- The credential row is removed from the DB.

There's no "soft delete" / recoverable bin. If you want to "park" a
credential, just rotate the value and rename it (e.g. prefix with
`zz_`) — the row remains and references are preserved.

## Rotation playbook

Rotating a credential typically means: the underlying secret was
re-issued (e.g. Atlassian rolled the API token, GitHub's PAT expired,
your Anthropic key was rotated).

1. **Admin → Credentials** → edit the credential.
2. Replace the `value` (or `password`, etc.) field.
3. Save.

Behind the scenes the existing row is updated in place; references
don't change; the new ciphertext replaces the old one.

For a `MASTER_KEY` rotation — that's a different operation. See
[Deployment](admin-deployment#master-key-rotation).

## Reusing credentials across repos

Common pattern: one `https_token` credential pointing at a corporate
Bitbucket / GitHub token, referenced by every internal repo. Rotating
the underlying token then only requires one credential update.

The form's credential picker filters by kind, so the dropdown only
shows credentials matching the URL shape of the repo you're
creating / editing.
