# How SASTBot works

SASTBot is built around five primitives. Once you have them in your head,
the rest of the UI is just a different view on the same data.

## The five primitives

| Concept | What it is | Lifetime |
|---|---|---|
| **Repository** | A source-of-truth: name, URL, branch, credential. | Operator-managed. Deleted on demand. |
| **Scope** | A scan path within a repo (e.g. `/`, `/services/api`). Findings live here. | Lives as long as the repo lists the path in its scan-paths. |
| **Scan run** | One execution of the pipeline against one scope at a point in time. Immutable audit record. | Forever (or until you delete the repo / scope). |
| **Issue** (SCA / SAST) | A *logical* finding on a scope — a CVE-on-component (SCA) or a CWE-at-location (SAST). De-duped across scans. | Persists across scans; transitions through triage states. |
| **Component** | A library or vendored dependency present in the scope. | Two tables: per-scan audit and per-scope operator-edited state. |

The UX runs top-down through that list. You manage repositories,
SASTBot derives scopes, you run scans on scopes, and findings/components
accrue on the scope across scan runs.

## What a scan does, end-to-end

A scan is a worker job. The backend hands it off to BullMQ on Redis and
returns immediately; the worker reports progress through `current_phase`
which the UI polls every three seconds. The phases, in order:

1. **`cloning`** — clones (or refreshes a retained clone of) the repo
   into a per-scan working directory.
2. **`cdxgen`** — runs Anchore's `cdxgen` to produce a CycloneDX SBOM
   from manifest files. This is the "machine truth" about declared
   dependencies.
3. **`llm_sbom`** — an LLM pass over the cdxgen output that drops
   first-party noise, surfaces vendored libraries cdxgen missed
   (`extern/`, `third-party/`, `vendor/`), and keeps a rationale field
   for any change it makes.
4. **`sbom_emit`** — writes the curated CycloneDX SBOM to disk as the
   canonical per-scan artifact.
5. **`sbom_ingest`** — re-reads that artifact into the `sbom_components`
   table so the rest of the pipeline sees only what's in the file.
6. **`osv`** — batched OSV.dev queries for every component (with caching
   of recently-queried PURLs).
7. **`nvd`** — NVD enrichment for C/C++ components without an OSV hit
   (optional, but recommended; raises rate limit with an NVD API key).
8. **`eol`** — end-of-life lookup for runtime / framework components.
9. **`llm_detection`** — an LLM agent (claude-p) walks the source tree
   and emits SAST records, SAST-absence records (where it looked but
   found nothing concerning), and reachability verdicts for every SCA
   issue at the configured minimum severity.
10. **`sarif_emit`** — writes SARIF v2.1.0 from the in-memory detection
    buffer.
11. **`sast_ingest`** — re-reads the SARIF and persists SAST issues with
    de-duped fingerprints.
12. **`llm_recheck`** — a narrower LLM pass that verifies every
    non-detected issue is *still* fixed, and that detected ones still
    appear at the reported location. Recheck failures are the safety
    net against the LLM giving spurious "all clear" verdicts.
13. **`sca_summaries`** — short LLM-written summaries for each SCA
    issue.
14. **`finalizing`** — updates `scan_runs` denorms, advances scope
    pointers if (and only if) the scan was trustworthy.

Most of the wall-clock budget on a typical scan is spent in
`llm_detection` and `llm_recheck`. The other phases are seconds.

## Trustworthiness gate

A scan that survived to "finalizing" still has to pass a trustworthiness
check before its findings re-anchor the scope's truth set. A scan is
**untrustworthy** if any `error`-severity warning was emitted:

- `cdxgen_failed`
- `llm_sast_detection_failed`
- `llm_sbom_augmentation_failed`
- `llm_*_parse_errors` when the LLM dropped ≥50% of its records
- `clone_failed`, `auth_failed`, `branch_not_found`, `remote_unreachable`,
  `scope_path_missing`

Untrustworthy scans complete in the audit trail (their findings are
written, the SBOM is emitted, etc.) but do **not** advance the scope's
`lastScanRunId`. That means the next time you open the scope page, the
SCA auto-fix sweep that prunes "fixed" findings is gated off until a
trustworthy scan replaces the degraded one.

The scope page warns you with an amber banner when the most recent scan
was untrustworthy.

## Two-table component model

The Components tab on the scope page shows operator-edited durable state
(scope_components). The Components tab on the scan-detail page shows the
per-scan audit snapshot (sbom_components). They serve different purposes:

- **`sbom_components`** — per-scan, immutable, cascades on scan delete.
  Read by the scan detail page.
- **`scope_components`** — per-scope, durable across scans, includes
  manual overrides (rename, custom evidence, hard-delete). Read by the
  scope page.

Data flows scan → scope, never the reverse. The scan flow uses a
seven-tier identity matcher (component root → CPE → PURL → normalized
name + version → manifest + name) to decide whether an emitted component
matches an existing scope component or is a new one.

See [Components & SBOM](components-sbom) for the operator-facing detail.

## Where the LLM is, where it isn't

SASTBot uses an LLM for four passes inside a scan:

| Pass | Purpose | Effort default | Per-repo override |
|---|---|---|---|
| `llm_sbom` (augmentation) | Drop first-party noise; surface vendored libs | `medium` | `repos.llmSbomEffort` |
| `llm_sbom_recheck` | Verify ambiguous-component dispositions | `medium` | `repos.llmSbomRecheckEffort` |
| `llm_detection` (SAST + reachability) | Find SAST issues; reachability verdicts | `xhigh` | `repos.llmSastEffort` |
| `llm_recheck` | Verify SAST non-detection is genuine | `medium` | `repos.llmRecheckEffort` |

It does **not** use the LLM for:

- Cloning, dependency parsing, OSV/NVD lookup, EOL data, SARIF
  generation, ticket linking, backup/restore.
- Anything outside a scan boundary. The UI is deterministic; there are
  no "ask the LLM about this finding" surfaces.

## Data flow on disk

- **`/app/clones/<repoId>`** — retained clone cache (only when the repo
  has `retain_clone=true`).
- **`/var/lib/sastbot/artifacts/sbom/<scanRunId>.json`** — canonical
  curated SBOM, written once at `sbom_emit`, served by
  `GET /scans/:id/sbom`.
- **`/var/lib/sastbot/artifacts/sarif/<scanRunId>.sarif.json`** —
  SARIF v2.1.0, written at `sarif_emit`, served by
  `GET /scans/:id/sast-sarif`.
- **PostgreSQL** — repositories, scopes, scan runs, issues,
  components, credentials (AES-256-GCM, keyed by `MASTER_KEY`).
- **Redis** — BullMQ queue and worker state.

## The audit trail

Every scan that touches a scope leaves a `scan_runs` row, regardless of
trustworthiness. That row holds the phase progress, warnings, LLM token
usage, and pointers to the SBOM/SARIF artifact files on disk. Old scan
rows aren't garbage-collected automatically — they're your history, and
the disk pressure is bounded by `component_count` × small numbers.

Deleting a scope or repo cascades the scan rows AND their on-disk
artifact files (see [Backup & restore](admin-backup-restore) for what
gets preserved across a backup/restore cycle).
