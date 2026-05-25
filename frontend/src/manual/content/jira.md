# Jira integration

SASTBot integrates with Jira Cloud as a **read-only** consumer. It can
link an existing ticket to a SAST or SCA issue, mirror the ticket's
status / resolution / assignee / fix-versions back into the SASTBot
UI, and surface a clickable link. It does **not** create or update
tickets.

The design choice is deliberate: many CRA programs require that
remediation tickets be owned by the engineering team's workflow tool,
not the SAST tool. SASTBot defers to Jira on lifecycle and only
reflects what Jira says.

## Setup

Two pieces of configuration are needed:

1. **Jira credential** (`jira_token` kind) — an API token from
   `https://id.atlassian.com/manage-profile/security/api-tokens`.
2. **Settings → Jira** — base URL (e.g. `https://your-org.atlassian.net`),
   account email, and the credential.

After saving, the green checkmark from **Save & test connection** means
SASTBot was able to authenticate and fetch the user's own profile.

## Linking a ticket

From any expanded SAST or SCA issue:

1. Click **Link Jira ticket**.
2. Type or paste the ticket key (e.g. `SAST-128`).
3. SASTBot fetches the ticket from Jira and stores a snapshot row.
4. The expanded panel now shows the ticket key, summary, status,
   assignee, fix-versions, and a "Open in Jira" external link.

The link is bidirectional in *display*, not in Jira. If the same key
is linked to multiple SASTBot issues, each issue shows the same ticket
information independently.

## Status reflection

A polling job (M5d-pending; currently manual via the **Refresh** link
on each row) re-fetches each linked ticket and updates the snapshot.
The next time the operator opens the row, they see the current Jira
status.

## Auto-transitions

Linking a Jira ticket to a SAST issue in `pending` or `confirmed`
state auto-transitions the issue to `planned`. The rationale: if work
is on someone's queue, the issue is no longer "I need to decide what
to do about this", it's "the team is on it". The transition is one-way;
unlinking the ticket does not revert the state.

SCA issues are not auto-transitioned. A linked ticket on an SCA issue
is purely informational.

## Unlinking

The link panel has an **Unlink** action. Removes the ticket reference;
leaves the issue's triage state where it is.

## Search by ticket key

The Scopes page filter strip and the SAST/SCA tab filter strips both
accept Jira ticket keys in the free-text search. Searching `SAST-128`
narrows the table to just the issues with that ticket linked.

## What gets stored

For each link:

- The Jira ticket key, e.g. `SAST-128`.
- The ticket's `summary`, `status.name`, `resolution.name`,
  `assignee.displayName`, `fixVersions[]`.
- The polling `last_synced_at` timestamp.
- A SASTBot-internal `jira_tickets` row with the above; the issue row
  has a FK to it.

No Jira comments, attachments, or full descriptions are pulled.
SASTBot is intentionally a shallow consumer.

## What's NOT supported (and probably won't be)

- **Ticket creation from SASTBot.** Out of scope.
- **Ticket transitions from SASTBot.** Out of scope.
- **Jira Server / Data Center.** Cloud only. The auth flow assumes
  Atlassian API tokens.
- **Multiple Jira instances.** One `Settings → Jira` config per
  SASTBot deployment.

## Failure modes

If the Jira API is unreachable or the credential is invalid:

- Linking a new ticket returns an error to the operator.
- Existing linked tickets keep their last-known snapshot; the
  **Refresh** click on the row shows the error.

A missing Jira config (no base URL, no credential) hides the **Link
Jira ticket** button on expanded issue rows. The rest of SASTBot
continues to function.
