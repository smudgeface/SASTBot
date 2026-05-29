# Scopes

A **scope** is one scan path within a repository. It's the primary unit
of triage in SASTBot — issues, components, and SBOMs all live at the
scope level. The Scopes page is the default landing page after login.

![Scopes overview page showing three scopes with severity chips and
last-scan times](:::asset:scopes-overview:::)

## The scopes list (/scopes)

Each row in the table:

- **Repo / Path** — the parent repo's name, then the scan path. A repo
  with one scope (typically `/`) shows just the repo name.
- **Severity chips** — high-level summary of active SCA + SAST issues
  grouped by severity (critical, high, medium, low). Click a chip to
  jump to the matching tab with the matching filter.
- **Components** — total active components in this scope (from
  `scope_components` with `lifecycle='active'`).
- **Last scan** — when the scope was last *successfully and
  trustworthily* scanned. Hover for the failed-scan history. While a
  scan is in flight, this column shows the current phase + a
  progress chip.
- **Actions** — run scan, open scope, open SBOM viewer.

The page polls `/api/scopes` every 3 seconds whenever any scope has an
active scan, so phase progress updates live without a manual refresh.

## Running a scan

The play button at the right end of each row enqueues a scan run. The
button is disabled while a scan for the same scope is already running
or queued. The job is fire-and-forget — the API returns the new
`scan_run_id` immediately and the UI starts polling for progress.

Multiple scopes can scan in parallel; the worker concurrency is fixed
at one scope at a time per worker process, so adding more workers
horizontally is the way to speed things up.

## Scope detail (/scopes/:id)

Click a scope name to open the detail page. The layout is a header
with metadata (repo, path, last-scan summary, source-url-template,
download buttons) and three tabs:

- **SCA** — CVE findings for this scope (default landing tab).
- **SAST** — first-party CWE findings.
- **Components** — every library/dependency present.

The URL is the source of truth for which tab + which row is open:

- `/scopes/:id`                         — SCA tab, no row expanded
- `/scopes/:id/sca/:issueId`            — SCA tab with `:issueId` expanded
- `/scopes/:id/sast`                    — SAST tab
- `/scopes/:id/sast/:issueId`           — SAST tab with `:issueId` expanded
- `/scopes/:id/components`              — Components tab
- `/scopes/:id/components/:componentId` — Components tab with row expanded
- `/scopes/:id/sbom`                    — scope-level SBOM viewer

This means deep-linking works: paste a row URL into Slack and the
recipient lands on the same expanded row. Bookmarks survive page reload.

## Live scan banner

When a scope has a scan in flight, the detail page header shows an
amber banner with the current phase + the progress fraction (e.g.
"llm_detection · 12450 / 60000 tokens"). The banner disappears once the
scan reaches a terminal state.

When the most recent completed scan was *untrustworthy* (see
[Overview](overview#trustworthiness-gate)), the banner stays in place
as an amber warning: "Most recent scan failed trustworthiness check —
findings not advanced. Re-run when the LLM endpoint is healthy."

## Filters and search

Each tab has its own filter strip. Common patterns:

- **Severity** chips toggle which severities are shown.
- **Triage status** — for SAST: `pending`, `confirmed`, `false_positive`,
  `wont_fix`, `planned`, `done`. For SCA: `active`, `suppressed`,
  `not_found`, `dev_tree_policy`, etc.
- **Show dev-tool packages** / **Show dev CVEs** — npm-only toggles
  that surface components / SCA issues marked dev-only by cdxgen.
  Default tracks the repo-level `include_dev_deps` setting (hidden
  when it's off, the default).
- **Free-text search** — matches across package name, CVE, summary,
  file path, CWE ID, depending on the tab.

Filter state is local (URL-fragment-free for now). Refreshing the page
resets filters; row state is preserved via the URL.

## Triage actions

Each issue row can be expanded to access triage actions. The available
actions vary by issue type and current state — see
[SCA findings](sca-issues) and [SAST findings](sast-issues) for the
state machines.

The status badge in the row header always shows the **true** triage
status. There are no implicit overrides based on Jira linkage or
anything else — transitions are explicit, either through the link
action (which auto-transitions `pending` / `confirmed` → `planned`)
or through the next-status buttons in the expanded panel.

## Download artifacts

The scope header has two download buttons:

- **Download SBOM** — CycloneDX 1.7 JSON of all active scope_components,
  reflecting any operator edits (renames, custom evidence, hard-deletes).
  This is the primary CRA-evidence artifact.
- **Open SARIF viewer** — opens the most recent successful scan's SARIF
  v2.1.0 report in an inline viewer with a Download button.

## Behind the scenes

The scope row's "last scan" badge reads `scope.lastScanRunId` — a
denormalised pointer that's advanced *only* by trustworthy scans (see
[Overview](overview#trustworthiness-gate)). `scope.lastScanCompletedAt`
is updated on *every* terminal scan, trustworthy or not, so the
operator can tell when SASTBot last *tried*.
