# Quick start

This page gets you from a fresh SASTBot deployment to your first scan in
about fifteen minutes. It assumes the administrator has already brought
the stack up (see [Deployment](admin-deployment) if not).

## 1. Create your admin account

The very first time SASTBot boots against an empty database, it has **no
users**. Open the frontend in your browser (the default is
`http://localhost:5173`) and you'll be taken straight to a first-run setup
screen. Enter an email and a password (at least 12 characters) and click
**Create admin & sign in** — you're logged in immediately as the administrator.

This account is a normal user account: it's stored with a bcrypt-hashed
password and is included in database backups, so it travels with your data when
you migrate or restore.

> **Migrating from another installation?** The setup screen also has a **Restore
> a backup** tab — upload a full backup and SASTBot restores it (bringing the
> backup's user accounts with it) instead of creating a new admin. See
> [Backup & restore](admin-backup-restore).

> **Tip (developers):** setting the dev-only `BOOTSTRAP_ADMIN_PASSWORD` env var
> skips this screen and auto-creates the admin with that password, so a
> `docker compose down -v` lets you log straight back in. It's a hard config
> error under `NODE_ENV=production`.

## 2. Get going

Once you're in, head to the next step to set up the LLM gateway. You can change
your password anytime from **Change password** in the sidebar, and add more
accounts under **Admin → Users** — see [Users](admin-users).

## 3. Configure the LLM gateway

SASTBot relies on an LLM endpoint for SAST detection, SCA reachability
assessment, and finding summarisation. Without it, scans cannot produce
findings.

1. Go to **Admin → Settings**.
2. Fill in the **LLM gateway** card:
   - **Base URL** — your gateway (e.g. a LiteLLM proxy, an Anthropic
     console endpoint, or a corporate AI gateway)
   - **API format** — `anthropic-messages` works with both the Anthropic
     API and most gateways
   - **Model** — the model slug, e.g. `claude-opus-4-7`
   - **Credential** — pick or create an `llm_api_key` credential
3. Click **Save & test connection**. If the gateway responds with at
   least one token, the test passes and the green checkmark appears.

If you don't have an LLM gateway yet, see [Settings page](admin-settings)
for the supported shapes.

## 4. Add a repository

1. Go to **Admin → Repositories** and click **Add repository**.
2. Fill in:
   - **Name** — your label (e.g. *FSS*)
   - **URL** — `https://…` or `git@…:…/repo.git`
   - **Protocol** — `https` or `ssh`
   - **Default branch** — what to clone (e.g. `main`, `master`)
   - **Credential** — pick or create one matching the URL kind
     (`https_token`, `https_basic`, or `ssh_key`)
   - **Scan paths** — `/` for the whole repo, or one or more subpaths
     like `/services/api`, `/services/web` if you want them tracked
     independently
3. Click **Create**.

For each scan path you give the repo, SASTBot creates a **scope** — that's
the unit you actually look at in the UI. See [Scopes](scopes).

## 5. Run your first scan

1. Go to **Scopes** (the landing page after login).
2. Pick the scope you just created and click the run icon at the right
   end of its row.
3. The scope row updates live with the current phase (cloning, cdxgen,
   llm_sbom, osv, llm_detection, llm_recheck, …). A full scan on a
   typical repo takes 10–25 minutes; most of it is the LLM passes.

While it runs you can:

- Click the scope name to open the scope detail page and watch the
  banner update.
- Switch to **Scans** for a flat, chronological audit view.

## 6. Read the results

When the scan completes:

- The scope detail page lands you on the **SCA** tab — CVEs found in your
  third-party dependencies, with severity, CVSS, and a **Reachable**
  badge for the ones the LLM judged exploitable from your code.
- **SAST** tab — first-party CWE findings. Each row expands to a code
  snippet with the offending lines highlighted.
- **Components** tab — every library SASTBot saw, including ones added
  or kept by the LLM during SBOM augmentation.

You can dismiss / suppress / link to Jira from the row-expanded panels on
each tab. See [SCA findings](sca-issues) and [SAST findings](sast-issues)
for the full lifecycle.

## 7. Export CRA artifacts

From the scope detail page header:

- **Download SBOM** — CycloneDX 1.7 JSON for this scope (reflects any
  operator edits).
- The most recent scan's **SAST SARIF** is accessible from
  **Scans → \<id\> → SARIF view**, with a download button.

You can hand both to your CRA documentation pipeline.

---

That's the loop. The rest of this manual goes deeper on each step.
