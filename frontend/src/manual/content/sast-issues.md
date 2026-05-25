# SAST (CWE) findings

SAST = "static application security testing" — issues in your
first-party code. SASTBot's SAST is LLM-driven: a claude-p agent walks
the source tree, identifies issues, and emits CWE-mapped records with
file/line ranges. A second LLM pass *rechecks* each record against the
live source code before any of them touches the database.

## Where the data comes from

1. The `llm_detection` phase runs claude-p with the
   `sast_detection.md` prompt over the cloned scope. It emits records
   of three kinds:
   - `sast` — a concrete finding at a `file_path` + `start_line` +
     `end_line`.
   - `sast_absence` — a place the LLM *looked* and found nothing
     concerning (used to scope re-checks).
   - `reachability` — verdicts on SCA issues (covered in
     [SCA findings](sca-issues)).
2. The `sarif_emit` phase writes the SAST records to a SARIF v2.1.0
   artifact on disk.
3. The `sast_ingest` phase reads the SARIF back and persists
   de-duplicated `sast_issues` rows (one row per logical fingerprint).
4. The `llm_recheck` phase verifies each non-detected issue is still
   absent and each detected issue still appears at the reported
   location. Recheck verdicts can demote a finding back to
   `pending` if the recheck couldn't confirm it.

## Row anatomy

Each SAST row has:

- **Severity badge** — `critical` / `high` / `medium` / `low`, derived
  from the CVSS v3.1 vector the LLM emitted (or the vector implied by
  the CWE class for vectorless records).
- **CWE** — the primary CWE id, e.g. `CWE-79`. Multiple CWE ids in
  `latest_cwe_ids` show as comma-separated.
- **Summary** — one-line title.
- **File and line** — `latest_file_path:latest_start_line-latest_end_line`.
  With a `source_url_template` on the repo, this is a clickable link to
  your code host (Bitbucket, GitHub, etc.).
- **Triage chip** — `pending`, `confirmed`, `false_positive`,
  `wont_fix`, `planned`, `done`.
- **Confidence** — the LLM's self-reported `0.0–1.0`.

## Expanded row

Click any SAST row to expand. The panel shows:

- **CVSS vector** + scalar score.
- **LLM reasoning** — the LLM's explanation.
- **LLM summary** — written by the `sca_summaries` pass (yes, the same
  prompt covers SAST and SCA summaries — name is historical).
- **Source snippet** — a canonical 7-line window: 3 lines before, the
  problem range (which may be 1+ lines), 3 lines after. The window is
  pre-rendered server-side from disk at scan time; the LLM's
  `snippet` field is accepted but never trusted.
- **Triage actions** — see state machine below.
- **Notes** — free-text per issue.
- **Jira link** — see [Jira integration](jira).

## Triage state machine

The default state is `pending`. The next-state buttons in the expanded
panel guide the operator through canonical workflows:

| From | Available next states | Notes |
|---|---|---|
| `pending` | `confirmed`, `false_positive`, `wont_fix` | First triage decision. |
| `confirmed` | `planned`, `false_positive`, `wont_fix` | Operator acknowledges the issue. |
| `planned` | `done`, `confirmed` | Work scheduled. Auto-set when a Jira ticket is linked. |
| `done` | `confirmed` | Fix shipped. Reopens to confirmed if the next scan still sees it. |
| `false_positive` | `pending`, `confirmed` | Won't be re-suppressed automatically. |
| `wont_fix` | `pending`, `confirmed` | Indefinite suppression. |

A `done` issue is **re-opened to `confirmed`** automatically when the
next trustworthy scan still sees its fingerprint. That's the safety net
against premature "done" claims.

## How the fingerprint works

Each SAST issue has a deterministic `fingerprint` built from
`(cwe, file_path_normalised, start_line, end_line, summary_token)`. The
fingerprint is what de-duplicates across scans: a second scan that
emits the same row updates `last_seen_scan_run_id` and `latest_*`
fields rather than creating a new row.

The fingerprint formula intentionally INCLUDES `start_line` and
`end_line`. A finding that moves up or down by a single line on the
next scan WILL produce a new fingerprint — that's a known limitation
and the right tradeoff for now. (Line-number-insensitive fingerprints
risk merging unrelated findings.)

## The "fixed" sweep

The SAST auto-fix sweep runs at the end of every *trustworthy* scan:

1. Take every `pending` or `confirmed` SAST issue on the scope.
2. If the issue's fingerprint was NOT seen in the current scan AND was
   covered by an `sast_absence` record (i.e. the LLM verified that
   location is clean), transition to `done`.
3. If a previously-`done` issue reappears (fingerprint matched), demote
   to `confirmed`.

The gate on `hasErrorWarnings` applies here too. A degraded scan
cannot close a SAST issue.

## Filters

- **Severity** chips — critical / high / medium / low.
- **Status** — combined filter; default shows `pending` + `confirmed`
  + `planned`.
- **Confidence** — minimum LLM confidence threshold.
- **Search** — matches CWE id, file path, summary.

## SARIF viewer

The most recent scan's SARIF report is one click away from the scope
page (Download / Open SARIF). Same data, machine-consumable:

![Inline SARIF viewer for a scan, showing the JSON document with download
button](:::asset:sast-sarif-viewer:::)

- `runs[0].tool.driver.name = "SASTBot"`, `.version = APP_VERSION`.
- `runs[0].results[]` — one entry per ingested SAST issue.
- `runs[0].taxonomies[0]` — the CWE taxonomy; results dereference
  through `ruleId`.
- `region` — `startLine` / `endLine` for the problem range.
- `contextRegion` — snippet text + `startLine` / `endLine` of the
  surrounding 7-line window.

The SARIF is **producer-shape**: no `fingerprints`, no triage or
lifecycle fields. Those are operator-side concerns and live in
SASTBot's own DB, not in the SARIF (per the SARIF §3.27.23
recommendation).
