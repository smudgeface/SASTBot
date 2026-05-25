# SCA (CVE) findings

SCA = "software composition analysis" — vulnerabilities in your
third-party dependencies. A row on the **SCA** tab represents one
*logical* issue: a CVE against a package on this scope. It is
de-duplicated across scan runs by the `(scope_id, package_name, osv_id)`
unique constraint.

![Scope detail page, SCA tab, showing severity-grouped CVE findings with
package, location, reachability badges, and triage status](:::asset:scope-detail-sca:::)

## Where the data comes from

1. The scan's `cdxgen` + `llm_sbom` phases produce a curated CycloneDX
   SBOM of components.
2. The `osv` phase queries OSV.dev in batches for every component's
   PURL.
3. The `nvd` phase fills in C/C++ components that OSV.dev missed.
4. The `llm_detection` phase asks the LLM to assess
   **reachability** — whether each high-severity CVE in a third-party
   component is actually exploitable from the first-party code in this
   scope.
5. The `sca_summaries` phase writes a short LLM-authored summary for
   each issue.

## Row anatomy

Each SCA row has:

- **Severity badge** — `critical` / `high` / `medium` / `low`, sourced
  primarily from OSV's CVSS v3.1 or v4.0 vector; fallback to NVD if OSV
  has no severity.
- **Package and version** — `package_name@latest_package_version`.
- **CVE link** — `latest_cve_id` clickable to NIST NVD.
- **OSV ID** — the upstream advisory id (e.g. `GHSA-…`, `OSV-…`).
- **Reachable badge** — present when the LLM committed to a verdict.
  - `Reachable` (red) — LLM identified concrete call sites in your code.
  - `Not reachable` (green) — LLM looked and found nothing.
  - *(no badge)* — reachability disabled on this repo, or the CVE is
    below the configured minimum severity for reachability assessment.
- **Dev** chip — npm-only. Tag the component as a dev dependency
  (cdxgen 12.2+ `dev: true` lockfile marker). Hidden by default unless
  the **Show dev CVEs** toggle is on, or the repo has
  `reachability_include_dev_deps=true`.
- **Status chip** — `active`, `suppressed`, `removed`,
  `dev_tree_policy`, `manual_override`. See states below.

## Reachability

The reachability badge is the most operator-visible LLM output. The
assessment is:

- Triggered for CVEs at or above the configured **Reachability minimum
  severity** (`Settings → LLM-assisted analysis`).
- Per-issue, deterministic on input — same SBOM + same code yields the
  same verdict.
- Documented in the expanded row with:
  - `Reachable reasoning` — the LLM's explanation
  - `Call sites` — clickable `path:line` references with snippets
    pre-rendered server-side from the canonical 7-line context window
  - `Reachable model` — the model that produced the verdict
  - `Reachable confidence` — `0.0–1.0`

The LLM is fallible. Treat reachability as a *prioritisation hint*, not
ground truth. The verdict, confidence, model, and reasoning are all
visible so you can decide whether to trust it.

## Triage state machine

| State | Meaning | Set by |
|---|---|---|
| `active` | Default. Live finding. | Initial insertion. |
| `suppressed` | Operator dismissed (with a reason). | Manual via expanded row. |
| `removed` | Component is no longer present. | Auto, when a trustworthy scan no longer sees the package. |
| `dev_tree_policy` | npm dev dependency, auto-hidden. | Auto, on backfill / per-scan. |

The flow inside the expanded row:

- **Suppress** — opens a dialog with a reason picker (false positive,
  not exploitable in our use, mitigated externally, won't fix, other +
  free text). Suppressed issues are hidden from the default view.
- **Unsuppress** — restores to `active`.
- **Link Jira ticket** — see [Jira integration](jira).
- **Notes** — free-text per issue. Persisted; never sent to the LLM.

## How "removed" works

The SCA auto-fix sweep runs at the end of every *trustworthy* scan:

1. Take every active SCA issue on the scope.
2. If the issue's `(package_name, osv_id)` was NOT seen in the current
   scan's SBOM + OSV results, mark the issue `removed` with
   `dismissed_at = scan.finished_at`.
3. If a previously-`removed` issue reappears, it's reactivated to
   `active`.

The sweep is gated on `hasErrorWarnings(scanRunId) === false`. If the
scan was degraded (LLM dropped half its records, cdxgen failed, etc.),
the sweep is skipped — a degraded scan can't decide whether real
findings have been fixed.

## How the dev-tree policy works

When a repo has `reachability_include_dev_deps=false` (the default),
issues whose component is marked `is_dev_only=true` by cdxgen are
auto-set to `dismissed_status='suppressed'` with
`dismissed_reason='dev_tree_policy'`. They're hidden from the default
view but visible when **Show dev CVEs** is toggled on. Toggling the
repo setting to `true` reactivates them.

Note: this is npm-only. Non-npm components have `is_dev_only=false`
regardless and are unaffected.

## Filters

- **Severity** chips — toggle critical / high / medium / low.
- **Status** — active (default), suppressed, removed, dev_tree_policy.
- **Reachable** — only / hide reachable.
- **Search** — matches package name, CVE id, OSV id, summary text.

The default view shows `active` only.

## SCA on the scan-detail page

The scan-detail page also has an SCA view, but it's per-scan and
**audit-only**. It shows what *that scan* observed. Don't triage from
here — fingerprint dedup works at the scope level, so a per-scan
suppression would point at the wrong rows for future scans.
