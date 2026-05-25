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
- A trashcan icon for hard delete.

## Editing a component

Two operator actions on each scope_component:

- **Edit** (pencil icon) — opens `PATCH /api/scopes/:id/components/:componentId`.
  Accepts `name`, `component_root`, `evidence` (array of
  `{path, line?}`). Marks the row `source='manual_override'`. The
  persist-flow UPDATE uses COALESCE / array-empty checks so
  operator-set values aren't overwritten by future scans.
- **Delete** (trashcan) — `DELETE /api/scopes/:id/components/:componentId`.
  Hard delete. Safe to use freely: the next scan will re-emit any
  legitimate component, and the matcher will collapse the new row
  against any operator override that survives.

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
  - Built once at scan time by the `sbom_emit` phase and written to
    `${ARTIFACT_DIR}/sbom/${scanRunId}.json`.
  - Reflects what *that scan* observed. Doesn't reflect operator edits
    made after the scan.
  - Legacy scans (run before M9 Stream B) have no artifact file and
    the endpoint returns 404 with a re-run hint.
- `GET /api/scopes/:id/sbom-json` — per-scope, on-demand.
  - Built fresh on every request from the current `scope_components`
    rows.
  - Reflects any operator edits (renames, evidence changes, deletes).
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
      "name": "axios",
      "version": "1.6.0",
      "purl": "pkg:npm/axios@1.6.0",
      "bom-ref": "pkg:npm/axios@1.6.0",
      "licenses": [{ "license": { "id": "MIT" } }],
      "evidence": {
        "occurrences": [{ "location": "src/api.ts#12" }]
      },
      "properties": [
        { "name": "sastbot:discovery_method", "value": "manifest" }
      ]
    }
    // …
  ]
}
```

A few non-obvious things:

- The output is **deterministic** byte-for-byte: keys sorted, arrays
  sorted, no clock-dependent fields. Two reads of the same SBOM
  produce identical bytes (Stream D6 invariant). This matters for
  ETag stability and for CRA-evidence equivalence.
- `sastbot:llm_evidence_path`, `sastbot:llm_rationale`, and
  `sastbot:llm_excerpt` are emitted on LLM-augmented components to
  carry the rationale for downstream auditors.
- `is_dev_only` components are included in the SBOM regardless of UI
  filter — the SBOM is the truth set; UI filtering is presentation.
