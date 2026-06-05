# M11 — Comprehensive SBOM (vulnerabilities + lifecycle) + phase reorder

> **Status:** queued (2026-05-25). Spun out of an M10 manual-review
> observation: the SBOM artifact file is emitted *before* osv/nvd/eol
> run, so it can't include CVE data or component lifecycle/EOL info —
> both of which CycloneDX 1.7 supports as first-class fields. CRA-grade
> SBOM evidence should be self-contained.
>
> **Trigger:** user remark on 2026-05-25 after reading
> `/manual/overview`. Quote: "We should move the emit and ingest to
> after osv+nvd+eol."

## Goal

Make the SBOM artifact served by `GET /scans/:id/sbom` a comprehensive
CycloneDX 1.7 document including:

- The component list (as today).
- A top-level `vulnerabilities[]` array with CVE/OSV records, severity,
  CVSS vector + score, CWEs, aliases, description, and `affects` refs
  back to the component `bom-ref`s.
- Per-component lifecycle / EOL data — preferably mapped to a
  CycloneDX-native field where one exists, otherwise via `properties`
  with `sastbot:eol_date` / `sastbot:lifecycle_state` keys.

## Why this is non-trivial

The current pipeline puts `sbom_emit` + `sbom_ingest` BEFORE
osv/nvd/eol, because those three phases query `sbom_components` rows.
That ordering means the file is written before any vuln data exists.

Two viable architectures:

1. **Move both phases after osv+nvd+eol.** Requires refactoring
   `osvService.queryAndPersistFindings`,
   `nvdService.queryAndPersistNvdFindings`, and
   `checkAndPersistEolFindings` to take an in-memory component list
   instead of `SbomComponent[]` DB rows. Each function uses
   `component.id` (the sbom_components PK) for internal dedup keys —
   a temporary identity (array index, purl, or synthesised UUID) can
   replace it. Manifest-snippet lookup uses `component.manifestFile`,
   which is on the in-memory `CdxComponent` already. The chain
   `persistScanComponentsToScopeState → llm_sbom_recheck` still
   depends on `sbom_components` being populated — so sbom_ingest stays
   before that pair OR persistScope/recheck also move later.

2. **Split persist from emit (recommended).**
   - New phase `sbom_persist`: writes `sbom_components` from in-memory
     `finalComponents` (no file involved). Happens right after
     `llm_sbom`.
   - `persistScanComponentsToScopeState` + `llm_sbom_recheck` run as
     today (they read `sbom_components`).
   - osv / nvd / eol run as today (they read `sbom_components`).
   - `sbom_emit` moves to AFTER `eol`. Builds the comprehensive
     CycloneDX from `sbom_components` + `sca_issues` + EOL data,
     writes one file.
   - `sbom_ingest` is retired — the file is the OUTPUT, never the
     input again in this flow.

   This preserves the "file is the operator-facing truth, written
   once with everything" property while avoiding the deep refactor of
   osv/nvd/eol signatures.

Recommended path: architecture #2. Cleaner end state, smaller
diff, easier to test.

## Audit findings (Step 0 — 2026-05-25)

The plan above was a quick first draft. Re-reviewed against the
current code; the following decisions were locked in before
implementation began.

### A1. Vulnerability scoping — include ALL sca_issues, surface disposition

Locked: the comprehensive SBOM emits every sca_issue for the scope
*regardless of `dismissedStatus`*. CRA evidence asks "what did the
scan find, and what was the operator's response" — hiding suppressed /
false_positive findings would cook the books.

CycloneDX 1.7 has `vulnerabilities[].analysis.state` for exactly this.
Map `sca_issues.dismissedStatus` → CycloneDX:

| `dismissedStatus`   | `analysis.state`           |
|---------------------|----------------------------|
| `pending`           | `in_triage`                |
| `confirmed`         | `in_triage`                |
| `planned`           | `in_triage`                |
| `fixed`             | `resolved`                 |
| `suppressed`        | `not_affected`             |
| `false_positive`    | `false_positive`           |

Also emit `analysis.detail` populated from the operator's `notes` or
`dismissedReason` when present, and `analysis.response: ["update"]`
for `planned`. `analysis.firstIssued = firstSeenAt`,
`analysis.lastUpdated = updatedAt`.

### A2. Determinism — every new array gets a sort key

The existing builder is byte-deterministic (Stream D6). Extending it
keeps that invariant. Sort keys:

- `vulnerabilities[]` — by `id` (the CVE / OSV ID), ascending.
- `vulnerabilities[].ratings[]` — by `(source.name, method, score)`.
- `vulnerabilities[].cwes[]` — numeric ascending.
- `vulnerabilities[].aliases[]` — lexicographic ascending.
- `vulnerabilities[].advisories[]` — by `url` ascending.
- `vulnerabilities[].affects[]` — by `ref` ascending.
- Per-component `properties[]` — already sorted by D4 (`(name, value)`).
  Just append the new EOL properties before D4 runs.

Add an assertion to `sbomCurated.deterministic.test.ts`: build twice
on the same scan with a fully-populated vuln + EOL set, assert
byte-identical output.

### A3. Vulnerability → component linkage (`affects[].ref`)

`sca_issues` has no FK to `sbom_components`. We have to match by
`(packageName, latestPackageVersion)`. The builders already iterate
the component list — build a side-map first:

```ts
const componentRefByKey = new Map<string, string>(); // "name@version" → purl
for (const c of components) {
  componentRefByKey.set(`${c.name}@${c.version ?? ""}`, c.purl);
}
```

For each sca_issue, look up `${issue.packageName}@${issue.latestPackageVersion ?? ""}`.

- Match → `affects: [{ ref: purl }]`.
- No match → emit the vulnerability with `affects: []` (CycloneDX
  permits an empty array). Log a debug warning; this should be rare,
  but a missing component shouldn't drop a vuln from the evidence
  artifact.

For the scope-level builder, the source map is `scope_components`
keyed by `(name, version)`. For the scan-level builder, the source
map is `sbom_components` keyed the same way.

### A4. Builder choice — extend DB readers, not in-memory builder

The plan said "extend `buildAugmentationSbom` or new
`buildComprehensiveSbom`". Picking: **extend the DB-reading builders**
(`buildCuratedSbomJson(scanRunId)` and
`buildCuratedSbomJsonForScope(scopeId)`).

Reasons:
- Both already pull sbom_components / scope_components from the DB.
  Adding a `prisma.scaIssue.findMany(...)` call alongside is a
  one-line change.
- The in-memory `buildAugmentationSbom` exists to support the file-
  first round-trip with `sastbot:*` properties readable by
  `ingestSbomFromArtifact`. After M11 the worker scan flow stops
  calling either; only the (currently dormant) operator-upload path
  would use them.
- Worker `sbom_emit` collapses to `await emitSbomArtifact(scanRunId)`
  — the existing one-liner used by `GET /scans/:id/sbom`.
- `buildAugmentationSbom` and `ingestSbomFromArtifact` stay in tree,
  unchanged. Future Stream B7 (operator-uploaded SBOM) caller path
  is preserved. Don't delete what we don't have to.

### A5. EOL / lifecycle data — pull from `sca_issues.latestEolDate`

`eolService.checkAndPersistEolFindings` writes ScanFinding rows AND
upserts ScaIssue rows. Each ScaIssue carries `latestEolDate` (when
parseable from the endoflife.date / npm-deprecation data) and
`latestSeverity` ("critical" for past-EOL, "high" within 90 days, etc).

For the per-component property emission:

```ts
// In components[].properties, for each component matched to an EOL issue:
{ name: "sastbot:eol_date", value: issue.latestEolDate.toISOString().slice(0, 10) }
{ name: "sastbot:lifecycle_state",
  value: issue.latestEolDate < now ? "eol" : "active" }
```

For npm deprecation (no `eolDate`, just a deprecation message stored
in `latestSummary`), emit:

```ts
{ name: "sastbot:lifecycle_state", value: "deprecated" }
```

Match the EOL issue back to the component via the same `(name,
version)` map from A3.

### A6. Legacy SBOM artifacts — leave alone

Pre-M11 files on disk lack `vulnerabilities[]` and the new EOL
properties. They're served as-is by the endpoint. `vulnerabilities[]`
is optional in CycloneDX 1.7 so downstream consumers won't choke. No
backfill — operators who want comprehensive evidence on a historical
scope can re-run that scope's most recent scan.

### A7. Manual touchpoints — add sca-issues.md and quick-start.md

Plan listed three sections. After a fresh pass:

- `overview.md` — phase list (covered).
- `scans.md` — phase table (covered).
- `components-sbom.md` — endpoint detail + "What's in the SBOM"
  example (covered; plan called this out).
- `sca-issues.md` — add a one-line note after step 5 of the pipeline
  walkthrough: "The per-scope SBOM endpoint (`/api/scopes/:id/sbom-json`)
  embeds these vulnerabilities inline alongside the components, so a
  single download is a complete CRA evidence artifact."
- `quick-start.md` — no edit needed; the phase reference there is
  generic ("cloning, cdxgen, …") and doesn't enumerate the post-eol
  steps.

### A8. Phase placement — `sbom_emit` after `eol`, before `llm_detection`

Locked. The auto-fix sweep (step 7) only PRUNES issues not detected
this scan; the issues that WERE detected stay unchanged. So emitting
right after `eol` captures the full vuln set for THIS scan. Tradeoff:
the SBOM won't include reachability verdicts (added by `llm_detection`)
or `latestLlmSummary` (added by `sca_summaries`). Acceptable for an
0.11 milestone — those are operator-UX helpers, not CRA-required
fields. Document in `components-sbom.md`. If a future caller needs
reachability-in-SBOM, move the phase to immediately before `finalizing`.

## Implementation plan (architecture #2)

### Backend changes

| File | Change |
|---|---|
| `backend/src/schemas.ts` | `current_phase` enum: remove `sbom_ingest`, add `sbom_persist`. |
| `backend/src/worker.ts` | ScanPhase type follows. Reorder: `llm_sbom` → `sbom_persist` → `persistScope` (inline) → `llm_sbom_recheck` → `osv` → `nvd` → `eol` → `sbom_emit` → `llm_detection`. **`sbom_emit` collapses to one line:** `await emitSbomArtifact(scanRunId)` (per A4). Remove the worker's direct `buildAugmentationSbom + writeArtifact` call; remove the `buildAugmentationSbom` and `stableStringify` imports from worker.ts. |
| `backend/src/services/sbomIngest.ts` | New function `persistComponentsFromMemory(scanRunId, finalComponents, evidenceMap, cpeMap, identityMap)` writes `sbom_components` rows directly (no file read). Reuses the row-building logic that today lives downstream of the file parse. Keep `ingestSbomFromArtifact` for the operator-uploaded-SBOM path (Stream B7 future work). |
| `backend/src/services/sbomCurated.ts` | Extend the **DB-reading** builders `buildCuratedSbomJson(scanRunId)` AND `buildCuratedSbomJsonForScope(scopeId)` to pull `sca_issues` (filtered to the matching scan or scope) and emit CycloneDX 1.7 `vulnerabilities[]` + per-component EOL `properties`. Both already read components from the DB; add a sibling `prisma.scaIssue.findMany(...)`. Update `CuratedSbomDoc` interface. `buildAugmentationSbom` stays untouched (operator-upload path preserved per A4). |
| `backend/src/services/scopeComponentService.ts` | No change — still reads sbom_components which is populated by sbom_persist. |
| Tests: `sbomEmit.test.ts`, `sbomIngest.test.ts`, `sbomCurated.deterministic.test.ts`, `mappersPhase.test.ts` | Adjust for new ordering + comprehensive shape. Add cases for vulnerabilities[] emission + EOL property emission. |

### Frontend changes

| File | Change |
|---|---|
| `frontend/src/api/types.ts` (or wherever `ScanPhase` lives) | Auto-derives from regenerated `schema.d.ts` after `npm run gen:types`. |
| `frontend/src/components/SCAN_PHASE_LABELS` or similar | Add `sbom_persist` label ("Persisting components"); drop `sbom_ingest`. |

### Manual updates

- `frontend/src/manual/content/overview.md` — replace the phases table
  with the new order. Spell out that `sbom_persist` is the internal
  DB write and `sbom_emit` is the operator-facing file write.
- `frontend/src/manual/content/scans.md` — same phases table needs
  the same edit. Plus update the wall-clock-cost column.
- `frontend/src/manual/content/components-sbom.md` — add a section on
  what the SBOM file now includes (vulnerabilities + lifecycle); update
  the "What's in the SBOM" example JSON to show a populated
  `vulnerabilities` array and per-component lifecycle properties.
- `frontend/src/manual/content/sca-issues.md` — append a one-line note
  after step 5 of the pipeline walkthrough: the per-scope SBOM now
  embeds these vulnerabilities inline (per A7).

### CycloneDX shape additions

CycloneDX 1.7 `vulnerabilities[]` schema:

```json
{
  "vulnerabilities": [
    {
      "bom-ref": "stable-uuid-or-cve-id",
      "id": "CVE-2021-44228",
      "source": { "name": "OSV.dev", "url": "https://osv.dev/vulnerability/CVE-2021-44228" },
      "ratings": [
        {
          "source": { "name": "NVD" },
          "score": 10.0,
          "severity": "critical",
          "method": "CVSSv31",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        }
      ],
      "cwes": [502],
      "description": "Log4j2 JNDI lookup arbitrary code execution.",
      "advisories": [{ "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228" }],
      "affects": [{ "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" }]
    }
  ]
}
```

For component lifecycle:

- CycloneDX 1.6+ added `metadata.lifecycles[]` for the **document
  scope** (e.g., `{"phase": "build"}`). Not what we want for
  per-component EOL.
- Per-component EOL has no first-class field yet (CLE — Common
  Lifecycle Enumeration — is still in draft). Use
  `components[].properties` with namespaced keys:
  - `sastbot:eol_date` — ISO 8601 date string (e.g., `2024-12-31`).
  - `sastbot:lifecycle_state` — `active`, `eol`, `deprecated`,
    `unsupported`.
- When CLE lands in a CycloneDX release, swap the property keys for
  the standard field.

## Version bump

`0.10.0 → 0.11.0` (MINOR — new operator-visible behavior in a
CRA-evidence artifact format).

## Exit criteria

- [ ] `sbom_persist` runs between `llm_sbom` and `persistScope`.
  `sbom_components` rows visible in DB before osv runs.
- [ ] `sbom_emit` runs between `eol` and `llm_detection`. The
  artifact file at `${ARTIFACT_DIR}/sbom/<scanRunId>.json` includes
  populated `vulnerabilities[]` and per-component EOL properties.
- [ ] `GET /scans/:id/sbom` returns the comprehensive document.
- [ ] `GET /api/scopes/:id/sbom-json` (built on demand from
  scope_components) also returns the comprehensive shape — the
  scope-level builder pulls sca_issues for the SAME scope.
- [ ] Determinism test still passes: two consecutive reads produce
  byte-identical bytes (vulnerabilities sorted by id, affects[] sorted
  by ref).
- [ ] Manual sections updated. New phase table renders correctly in
  `/manual/overview` and `/manual/scans`.
- [ ] All backend + frontend tests green.
- [ ] One real FSS scan run + endpoint curl confirms the file content
  is comprehensive on a post-change scan.

## Out of scope

- Operator-uploaded SBOM ingest (Stream B7 future work). Keep
  `ingestSbomFromArtifact` in tree for that future caller — just
  don't invoke it from the worker scan flow.
- Cross-scope SBOM rollup (CRA evidence at the *repo* or
  *organisation* level).
- CycloneDX 1.8 / CLE adoption.
