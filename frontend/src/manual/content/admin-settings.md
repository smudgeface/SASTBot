# Admin: settings page

**Admin → Settings** holds the deployment-wide settings — distinct from
per-repo knobs which live on each repo's edit form. There is exactly
one `app_settings` row per deployment; the page reads and writes it
directly.

## Jira

- **Base URL** — your Atlassian Cloud tenant, e.g.
  `https://your-org.atlassian.net`. Used as the prefix for every
  Jira API call SASTBot makes.
- **Account email** — the Jira account that owns the API token. Sent
  as the username in HTTP Basic against `/rest/api/3/…`.
- **Credential** — pick or create a `jira_token` credential.

**Save & test connection** does a real `GET /rest/api/3/myself` call
against Jira with the saved credentials. A green checkmark means the
token authenticated and the user profile came back. A failure surface
the upstream HTTP code and message inline.

If you leave Jira unconfigured, the **Link Jira ticket** button is
hidden everywhere in the UI. The rest of SASTBot continues to work.

## LLM gateway

SASTBot relies on an LLM for SAST detection, reachability assessment,
SBOM augmentation, and issue summarisation. Without it, scans fail
loudly.

- **Base URL** — your LLM endpoint. Common shapes:
  - Anthropic API: `https://api.anthropic.com`
  - A LiteLLM proxy: `https://your-litellm.internal/`
  - A corporate AI gateway with Anthropic-compatible routes
- **API format** — `anthropic-messages` is the universal choice. The
  claude-p CLI speaks this protocol natively.
- **Model** — the model slug. Examples: `claude-opus-4-7`,
  `claude-sonnet-4-6`, or any model your gateway exposes.
- **Credential** — pick or create an `llm_api_key` credential.

**Save & test connection** sends a real prompt to the endpoint and
verifies at least one token comes back, recording latency + token
usage inline. Failures surface the upstream error.

> Token usage from the test is rounded to the nearest 1 cent and is
> negligible (single-digit tokens). It's there so you can verify the
> gateway is metering correctly before committing to a real scan.

## LLM-assisted analysis

- **Reachability minimum severity** — `Critical only`, `High and
  above`, `Medium and above`, `Low and above`. Only CVEs at or above
  this severity get the LLM reachability assessment. The default is
  `High and above` — a reasonable balance of cost vs signal.
- **Per-repo SAST effort and token budgets** — *not* on this page. They
  live on each repository's edit page.

## NVD API key

The National Vulnerability Database (NVD) is queried for C/C++
components that OSV.dev didn't cover. NVD's free tier rate-limits to
5 requests / 30 s; an API key raises that to 50 / 30 s. The key is
free; obtain it at
[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

- **Credential** — pick or create an `nvd_api_key` credential.

Without a key, SASTBot still queries NVD but throttles more
conservatively. On a scan with many C/C++ components this can add
several minutes to the `nvd` phase.

## Database backup & restore

The lower half of the page hosts backup/restore. See its dedicated
section in [Backup & restore](admin-backup-restore) — too much
detail to put here.

## Save semantics

Each section has its own **Save** button. The backend's PATCH
endpoint accepts partial updates — fields not present in the request
body are left alone — so saving the Jira section doesn't accidentally
clear LLM settings.

The credential pickers use an "omit instead of null" pattern: when the
picker shows a saved credential and the operator hasn't touched the
field, the save payload omits the credential id entirely. This
prevents the v0.9.7-era display race from being able to silently null
out a credential even in a Radix mismatch edge case.

A successful save returns the updated row; the page hydrates from
that row and shows the new values.
