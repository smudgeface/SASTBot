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

## Implementation plan (architecture #2)

### Backend changes

| File | Change |
|---|---|
| `backend/src/schemas.ts` | `current_phase` enum: remove `sbom_ingest`, add `sbom_persist`. |
| `backend/src/worker.ts` | ScanPhase type follows. Reorder: `llm_sbom` → `sbom_persist` → `persistScope` (inline) → `llm_sbom_recheck` → `osv` → `nvd` → `eol` → `sbom_emit` → `llm_detection`. |
| `backend/src/services/sbomIngest.ts` | New function `persistComponentsFromMemory(scanRunId, finalComponents, evidenceMap, cpeMap, identityMap)` writes `sbom_components` rows directly (no file read). Reuses the row-building logic that today lives downstream of the file parse. Keep `ingestSbomFromArtifact` for the operator-uploaded-SBOM path (Stream B7 future work). |
| `backend/src/services/sbomCurated.ts` | Extend `buildAugmentationSbom` (or a new `buildComprehensiveSbom`) to take `vulnerabilities` (from sca_issues) and an EOL/lifecycle map. Emit CycloneDX 1.7 `vulnerabilities[]` and component `properties` for EOL. Update `CuratedSbomDoc` interface. |
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
