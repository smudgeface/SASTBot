# Components & SBOM

A **component** is one library or vendored dependency present in a
scope. The Components tab on the scope page is the operator-editable
truth set; downstream SBOM exports reflect what you see there.

## Two tables, two purposes

SASTBot keeps two distinct component tables that should not be
confused:

| Table | Lifetime | Mutability | Read by |
|---|---|---|---|
| `sbom_components` | Per scan run (cascades on scan delete) | Immutable audit | Scan-detail page |
| `scope_components` | Per scope, persists across scans | Mutable (operator edits) | Scope page |

Data flows scan → scope, never the reverse. Each scan emits
`sbom_components` rows; the persist step then lifts those rows into
`scope_components` through a seven-tier identity matcher (component
root → CPE → PURL → normalized name + version → manifest + name). The
matcher decides whether to UPDATE an existing scope_component or
INSERT a new one.

## The Components tab

`/scopes/:id/components` lists every active scope_component. Columns:

- **Name** — canonical name including any group prefix. npm scoped
  packages keep their `@scope/` (e.g. `@types/node`); maven keeps
  `groupId:artifactId`.
- **Version** — `null` shows as `—`; the LLM is instructed to coerce
  `"unknown"`, `"*"`, `""` to `null` at parse time so they don't create
  twin rows that bypass the unique constraint.
- **Ecosystem** — `npm`, `maven`, `pypi`, `generic`, etc.
- **Discovery method** — `manifest` (cdxgen found it in a lockfile),
  `filename` (LLM found it by directory inspection), or
  `llm_augmentation` (LLM added it).
- **Component root** — for vendored libs, the shallowest repo-relative
  directory exclusively owned by the library (e.g. `extern/Xenomai`).
  Used as the dedup primary key.
- **Dev chip** — npm-only, true when cdxgen sees `dev: true` in the
  lockfile (cdxgen 12.2+). Hidden by default; toggleable.
- **LLM evidence** — info icon when the LLM kept-or-added the
  component with a rationale. Hover for the path, excerpt, and reason.
- **Source** chip — `scan` (default) or `manual_override` (operator
  has edited at least one field).

Click a row to expand. The expanded panel shows:

- All discovered evidence (path-and-line list).
- CPE, PURL, manifest file, manifest line.
- A pencil icon next to **Evidence** to inline-edit
  (name, component_root, evidence list).
- A trashcan icon (in the detail pane, next to the pencil) for hard delete.

## Component actions

Three operator actions are available per scope_component:

- **Ignore** (Ban icon, row-level) — soft-suppresses the component and
  all its pending/confirmed SCA issues. Sticky across scans: future CVEs
  on the same package also land as suppressed automatically. Reversible
  via the Restore action in the Ignored view (see Filter chips below).
  An optional free-text reason can be recorded when ignoring.
- **Edit** (pencil icon, in the detail pane) — opens
  `PATCH /api/scopes/:id/components/:componentId`. Accepts `name`,
  `component_root`, `evidence` (array of `{path, line?}`). Marks the
  row `source='manual_override'`. The persist-flow UPDATE uses COALESCE
  / array-empty checks so operator-set values aren't overwritten by
  future scans.
- **Delete** (trashcan, in the detail pane next to the pencil) —
  `DELETE /api/scopes/:id/components/:componentId`. Hard delete. Safe to
  use freely: the next scan will re-emit any legitimate component, and
  the matcher will collapse the new row against any operator override
  that survives. Use this for duplicate or garbage rows the matcher
  didn't catch. Use **Ignore** instead if the component is real but you
  don't want to see it or its CVEs.

## Filter chips (status views)

The Components tab has two filter chips:

- **Not found** — components where the worker could not find evidence
  (the evidence path file no longer exists on disk, or the LLM SBOM
  recheck concluded the component is absent). This is a worker-side
  decision, not an operator action.
- **Ignored** — components the operator has explicitly ignored via the
  Ban icon. Shows the Restore (Undo) action in place of the Ignore
  button.

When no chip is selected (the default), only active components are
shown. Selecting one or both chips replaces the default and shows
components with the selected `dismissed_status` values instead.

In the **Ignored** view, the row-level action icon becomes a Restore
icon (Undo2). Clicking it restores the component to active and
un-suppresses the SCA issues that were cascaded by the ignore action.
The trashcan in the detail pane is always available regardless of
which filter view is active.

Evidence accepts `path:N` shorthand on each line in the textarea —
parsed into `{path, line: N}` objects.

### Edge cases

- **Rename collisions** — if you rename a component to a name that
  already exists on the scope, the PATCH returns HTTP 400 with a
  guidance message. Delete the existing duplicate first, then rename.
- **Marking a component dev-only** — there's no operator action for
  this. The dev flag is sourced from cdxgen's `dev: true` lockfile
  marker; if cdxgen got it wrong, fix the manifest in your source
  repo, not in SASTBot.

## CycloneDX SBOM endpoints

Two distinct endpoints, both serving CycloneDX 1.7:

- `GET /api/scans/:id/sbom` — per-scan, immutable.
  - Built once at scan time by the `sbom_emit` phase (which runs AFTER
    osv/nvd/eol) and written to `${ARTIFACT_DIR}/sbom/${scanRunId}.json`.
  - Embeds `vulnerabilities[]` (every sca_issue detected in this scan,
    with disposition) and per-component lifecycle/EOL properties — a
    complete, self-contained CRA evidence document.
  - Reflects what *that scan* observed. Doesn't reflect operator edits
    made after the scan.
  - Legacy scans (run before M11) have no `vulnerabilities[]` in their
    file — re-scan the scope to produce a comprehensive artifact.
- `GET /api/scopes/:id/sbom-json` — per-scope, on-demand.
  - Built fresh on every request from the current `scope_components`
    rows.
  - Reflects any operator edits (renames, evidence changes, deletes).
  - **Ignored and not-found components are excluded**, along with all
    their SCA vulnerabilities. Only `dismissed_status='active'`
    components and their issues appear in this artifact.
  - The primary **CRA-evidence** artifact.

The two endpoints serve the same content shape but different scopes —
the per-run snapshot vs the per-scope operator-edited state. They are
intentionally different; don't unify them.

## SBOM viewer

Either endpoint opens in the in-app SBOM viewer (`/scans/:id/sbom` or
`/scopes/:id/sbom`). The viewer is a Monaco-backed read-only JSON
display with a Download button. The displayed bytes are exactly the
endpoint response — no client-side reformatting.

## What's in the SBOM

Top-level structure (CycloneDX 1.7):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:<scanRunId or scopeId>",
  "version": 1,
  "metadata": {
    "timestamp": "2026-05-24T…Z",
    "tools": {
      "components": [
        { "type": "application", "name": "SASTBot", "version": "0.10.0" },
        { "type": "application", "name": "cdxgen", "version": "12.2" }
      ]
    },
    "component": { "type": "application", "name": "<repo>", "version": "<branch>" }
  },
  "components": [
    {
      "type": "library",
      "name": "lodash",
      "version": "4.17.20",
      "purl": "pkg:npm/lodash@4.17.20",
      "bom-ref": "pkg:npm/lodash@4.17.20",
      "properties": [
        { "name": "sastbot:discovery_method", "value": "manifest" },
        { "name": "sastbot:eol_date", "value": "2023-09-30" },
        { "name": "sastbot:lifecycle_state", "value": "eol" }
      ]
    }
    // …
  ],
  "vulnerabilities": [
    {
      "bom-ref": "CVE-2021-23337",
      "id": "CVE-2021-23337",
      "source": { "name": "OSV.dev", "url": "https://osv.dev/vulnerability/CVE-2021-23337" },
      "ratings": [
        { "source": { "name": "OSV.dev" }, "score": 7.2, "severity": "high",
          "method": "CVSSv31", "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" }
      ],
      "advisories": [{ "url": "https://osv.dev/vulnerability/CVE-2021-23337" }],
      "affects": [{ "ref": "pkg:npm/lodash@4.17.20" }],
      "analysis": {
        "state": "in_triage",
        "firstIssued": "2024-08-12T09:31:00Z",
        "lastUpdated": "2024-08-12T09:31:00Z"
      }
    }
  ]
}
```

A few non-obvious things about the comprehensive SBOM shape:

- **`analysis.state`** surfaces the operator's disposition
  (`in_triage`, `resolved`, `not_affected`, `false_positive`).
  Dismissed findings stay in the artifact for CRA evidence completeness
  — they are not silently hidden.
- The per-scan SBOM (`/scans/:id/sbom`) includes only findings this
  scan detected. The scope-level SBOM (`/api/scopes/:id/sbom-json`)
  includes every active sca_issue for the scope, including those from
  previous scans that haven't been marked removed.
- **Reachability verdicts and LLM summaries are NOT in the SBOM.** Both
  are added to sca_issues after `sbom_emit` runs (by `llm_detection`
  and `sca_summaries` respectively). They remain visible on the scope
  detail page. If reachability-in-SBOM is needed in a future milestone,
  the phase can be moved to immediately before `finalizing`.
- The output is **deterministic** byte-for-byte: keys sorted, arrays
  sorted (vulnerabilities by `id`, affects[] by `ref`), no
  clock-dependent fields. Two reads of the same SBOM produce identical
  bytes (Stream D6 invariant). This matters for ETag stability and for
  CRA-evidence equivalence.
- `sastbot:llm_evidence_path`, `sastbot:llm_rationale`, and
  `sastbot:llm_excerpt` are emitted on LLM-augmented components to
  carry the rationale for downstream auditors.
- `is_dev_only` components are included in the SBOM regardless of UI
  filter — the SBOM is the truth set; UI filtering is presentation.
