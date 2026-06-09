# Scans

A scan is one execution of the pipeline against one scope. Every
trigger — operator click on the Scopes page, future scheduled cron — is
recorded as a `scan_runs` row from the moment it's enqueued.

## Triggering a scan

The canonical entry points:

- **Scopes page** — the run icon at the right end of each row.
- **Scope detail page** — the run button in the header.
- **REST API** — `POST /api/admin/repos/:id/scan` (where `:id` is the
  repo ID). Triggers a scan for all active scopes of that repo and
  returns one `scan_runs` row per scope. See the
  [API reference](api-reference) for the exact shape.

The endpoint returns immediately with the new `scan_run_id` and a
`status: "queued"`. The worker picks the job up from BullMQ on Redis and
starts processing.

## Watching progress

While a scan is `running`, the worker updates
`scan_runs.current_phase` and `scan_runs.phase_progress` at every phase
boundary. The frontend polls `/api/scopes` every 3s for in-flight
scopes; the Scopes page row and the scope detail header refresh in
near-real-time.

Phases, in order, with typical wall-clock cost on a medium repo:

| Phase | Cost | What happens |
|---|---|---|
| `cloning` | seconds–minutes | Clone or refresh the retained clone. |
| `cdxgen` | seconds–minutes | Anchore cdxgen → raw SBOM. |
| `llm_sbom` | 30s–5min | LLM augmentation (keep / drop / add). |
| `sbom_persist` | sub-second | Write sbom_components rows from in-memory finalComponents. |
| `llm_sbom_recheck` | seconds–minutes | Verify ambiguous-component dispositions. |
| `osv` | seconds | Batched OSV.dev queries with cache. |
| `nvd` | seconds | NVD enrichment for C/C++ components. |
| `eol` | seconds | EOL lookup for runtime / framework packages. |
| `sbom_emit` | sub-second | Write comprehensive CycloneDX SBOM artifact (components + vulnerabilities + lifecycle) to disk. |
| `llm_detection` | 10–30 min | LLM agent walks source for SAST + reachability. |
| `sarif_emit` | sub-second | Write SARIF v2.1.0 to disk. |
| `sast_ingest` | seconds | Persist SAST issues with fingerprints. |
| `llm_recheck` | 2–10 min | Verify each non-detected issue is still fixed. |
| `sca_summaries` | seconds–minute | Short LLM-written summaries per SCA issue. |
| `finalizing` | sub-second | Update denorms; advance scope pointers if trustworthy. |

A typical FSS-class repo runs in 15–25 minutes; a large monorepo with
the `xhigh` SAST effort can take 45+ minutes. Token spend dominates the
LLM phases — see [Settings page](admin-settings) for per-repo token
budget controls.

## Scans page

The **Scans** page (left sidebar) is a flat, chronological audit list
of all scan runs across all scopes:

- Status badge (queued, running, success, failed, cancelled).
- Scope + repo.
- Started, finished, duration.
- Trigger (user, schedule, api).
- Trustworthiness chip — green if no error warnings, amber if degraded.

Pagination is 50 per page. Filters: status, repo, date range.

The page is intentionally an **audit view** — it's not where you do
day-to-day triage (that's the scope page). It's the page you open when
you need to understand *what ran when*, e.g. for a CRA audit or to
investigate a regression.

## Scan detail page (/scans/:id)

Drilling into a scan run gives you:

- **Header** — scope link, repo, branch, status, duration, trigger,
  trustworthiness chip.
- **Phase timeline** — every phase with its start/end timestamps.
- **Warnings panel** — every `scan_warnings` row in chronological
  order, with severity chip. The full warning body is shown inline.
- **Token usage** — per-pass input/output tokens, cache read/write
  tokens, and request count. (No cost estimate — token counts don't
  predict cost on a gateway; consult your LLM gateway for actual spend.)
- **Tabs**: Components (per-scan SBOM), Findings (combined SCA + SAST
  list as seen by this scan), SAST view, and SBOM / SARIF viewers.

The scan detail page is intentionally light on triage — it shows what
*this scan* observed. Issues are de-duped at the scope level, so
running triage from here is risky (you might dismiss a row that the
next scan re-creates with a different fingerprint).

## Scan failure

A scan that emits any `error`-severity warning is marked
**`status = failed`** at finalize. Failed scans do not affect the
scope: `lastScanRunId` does not advance, `lastScanCompletedAt` does
not advance, the SCA auto-fix sweep is skipped, and the SAST recheck
cleanup branches no-op.

The per-scan rows the worker wrote *before* the failure (SBOM
components, OSV/NVD findings, any SAST records that made it past
detection) are kept in the database for audit. They're visible on
the failed scan's detail page (`/scans/:id`) but not on the scope
page — the scope's default issue filters pivot off `lastScanRunId`,
which still points at the last successful scan.

The Scopes list "Last scan" column reflects the last *successful*
scan only. Failed attempts are visible on the **Scans**
page.

To recover after a failure: fix the underlying cause (LLM endpoint
health, network, credentials, etc.) and re-run the scan. A
successful re-run advances the pointer and the new scan's findings
become visible.

See [Troubleshooting](troubleshooting) for the common warning codes
and how to resolve them.

## Scan warnings

Common warning codes you'll see in the wild:

- `info` severity:
  - `llm_sast_detection_retry` — first detection attempt failed; auto-retry succeeded.
  - `llm_*_parse_errors` (drop ratio < 50%) — some LLM records were unparseable.
  - `recheck_capped` — SBOM recheck hit the per-scan hard cap.
- `error` severity:
  - `cdxgen_failed` — Anchore cdxgen exited non-zero.
  - `llm_sast_detection_failed` — claude-p exited non-zero or was killed.
  - `llm_sbom_augmentation_failed` — SBOM augmentation pass crashed.
  - `llm_*_parse_errors` with drop ratio ≥ 50% — the LLM lost half its records.
  - `clone_failed`, `auth_failed`, `branch_not_found`, `remote_unreachable`.
  - `scope_path_missing` — configured scan path doesn't exist in the clone.

## Cancelling and re-running

A scan can be cancelled while it's queued or running via the scope-page
action or `POST /api/scans/:id/cancel`. The worker checks for the
cancel flag at phase boundaries; expect the scan to terminate within
the current phase, not instantly.

There's no "rerun this scan" action by design — every run is a fresh
unit. To rerun, click the run button on the scope.

## Deleting a scan

The audit page supports per-row delete (admin only). Deleting a scan:

- Removes the `scan_runs` row.
- Removes the per-scan artifact files (`sbom/`, `sarif/`) from disk.
- Removes the `sbom_components` rows for that scan (cascaded by FK).
- Does **not** remove `sca_issues` / `sast_issues` rows — those are
  scope-level. If the deleted scan was the `last_seen_scan_run_id` of
  any issue, the next scan that touches the issue advances the pointer
  again.

Deleting a scan is the right answer when an experimental run produced
garbage and you want it out of the audit trail. It's not the right
answer for normal cleanup — old scans don't cost much and they're your
history.
