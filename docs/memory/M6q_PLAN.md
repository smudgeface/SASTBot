# M6q — Components tab UX & data richness

## Goal

Make the Components tab as actionable as the SAST and SCA tabs: show
licenses, surface every file where a component is used (with line
numbers + git links), cross-link to the SCA/SAST issues a component
contributes to, and let the operator download the SBOM from the scope
view. Along the way, fix two pieces of misleading data — the
clone-prefixed paths that leak cdxgen's internal workspace, and the
"generic" ecosystem label that practically means "vendored" but doesn't
read that way.

## Investigation findings

### The SBOM has 3–4 overlapping "where is this used" sources

cdxgen output for a CycloneDX component contains up to four
representations of "where is this thing?":

| Source | Shape | Path style | Has line numbers? | Notes |
|---|---|---|---|---|
| `evidence.identity[].methods[].value` | string per inference method | `../clones/<repo-id>/<repo-path>` (cdxgen workspace-relative) | No | Used for manifest inferences. |
| `evidence.identity[].concludedValue` | single string per identity | same as `methods[].value` | No | The final identity conclusion. |
| `evidence.occurrences[].location` | array of locations | **repo-relative** with `#<line>` suffix | **Yes** | Set when cdxgen finds `require()`/`import` references. |
| `properties[].name === "SrcFile"` | name/value pairs | same as `methods[].value` | No | Effectively duplicates evidence.identity. |

Empirical sample — `jquery` from the recent Gocator Classic `/` run:
- `evidence.identity[].methods[].value`: `../clones/<repo-id>/GoEmulate/.../jquery-1.11.2.min.js`
- `evidence.occurrences[]`: 28 entries like `GoWeb/kJs/javascript/src/kjs/Record.js#3` (repo-relative, line-numbered) — the good data
- `properties[].SrcFile`: `../clones/<repo-id>/GoEmulate/.../jquery-1.11.2.min.js` ×2 (duplicates of evidence.identity)

`cef.redist.x64` (manifest-discovered) only has the noisier shape:
- `evidence.identity[].methods[].value`: `../clones/<repo-id>/GoEmulate/GoEmulateApp/packages.config` — no line numbers
- `properties[].SrcFile`: same — redundant

The takeaway: **`evidence.occurrences[]` is the gold source when present,
and `evidence.identity[].methods[].value` (or `concludedValue`) is the
fallback. `properties[].SrcFile` is always redundant — drop it.** All
non-occurrence paths need the `../clones/<repo-id>/` prefix stripped
to be repo-relative.

### `sbom_components` currently flattens this down to one path

The `sbom_components` schema today stores only:
- `manifest_file` (single string — chosen from `evidence.identity` per `extractManifestFile`)
- `evidence_line` (single integer — only ever populated by the now-removed `vendored_lib` SAST path)
- `llm_evidence` (JSONB `{path, excerpt, llmReason}` — single path, no line)

To show "every file where this component is used," the row needs to
carry the full occurrence list, not a single chosen path.

### `ecosystem='generic'` is the "vendored" tell in practice

cdxgen emits `pkg:generic/...` purls for components without an
identifiable package ecosystem. In SASTBot's M6p Stage 2 pipeline,
**every LLM-augmented vendored library is synthesised with a
`pkg:generic/` purl** in `applySbomAugmentation` — so 100% of
`generic`-ecosystem rows in our DB are LLM-augmentation finds (verified:
`SELECT COUNT(*) WHERE ecosystem='generic' AND discovery_method !=
'llm_augmentation'` returns 0 on all four verification scans).

This is a stable correlation but not a guarantee — a future change
that adds non-LLM `pkg:generic/` components would break a direct
rename. The safer UI rule is "show the discovery method when it's
`llm_augmentation`; otherwise show the ecosystem."

### Existing cross-tab references are weak

Scan-detail Components tab shows finding chips per row, but the chip is
a static `cve_id`/`osv_id` label — clicking it does nothing. There's
no equivalent on the scope page (it doesn't show findings on the
Components tab at all). Both tabs would benefit from the same
clickable "this component contributes to these issues" surface, with
SCA issues linking to the SCA tab and SAST issues linking to the SAST
tab (only relevant on the scope page — SAST has no per-component link
on the scan page since SAST findings aren't tied to components).

### Per-scope SBOM download is missing

`useSbomJson(id)` on the scan page hits `GET /scans/:id/sbom-json`.
There's no scope-level equivalent. The scope page is the
operator-facing "current state" view; downloading the SBOM should live
there, not (only) on the historical scan-detail page.

## Plan

### Phase 1 — Fix the SBOM at source, then persist the occurrence list

The user push-back here is right: the clone-prefix and the redundant
`properties[].SrcFile` aren't intrinsic to CycloneDX — they're
consequences of how we invoke cdxgen. Fix what we can at source first;
the post-processing layer then has less to do and won't have to lie
about provenance.

#### 1.1 cdxgen invocation changes

| Change | Today | Proposed | Why |
|---|---|---|---|
| **Process CWD** | inherits backend CWD (`/app/backend`) | `cwd: workingDir` (the scope dir) | cdxgen prints paths relative to its CWD. From `/app/backend` the clone is `../clones/<id>/...`. Setting CWD to the scope dir makes both `evidence.identity.methods[].value` and `properties.SrcFile` come out repo-relative — no post-hoc regex stripping needed. |
| **Path arg** | absolute `workingDir` | `.` (since CWD is now the scope dir) | Same intent — keeps cdxgen anchored to a single root. |
| **`--evidence`** | omitted (defaults to false in `--help`, but empirically present anyway) | pass explicitly | Make the evidence section a guaranteed contract, not an accident of project-type defaults. The `occurrences[]` array we depend on lives inside `evidence`. |
| **`--profile generic`** | default | keep default | Considered `license-compliance` — it adds license-only metadata but skips some component types. Sticks with `generic` for full coverage; revisit if license fidelity becomes a CRA-report bottleneck. |
| **`--min-confidence`** | not set (0) | not set (0) — see note | Considered `0.5` to suppress the noisy `0.25` filename inferences (e.g., the jquery `concludedValue` that points at one of many copies). But on `/`, the 0.25-confidence filename method is sometimes the *only* identity cdxgen has for a real vendored lib. Tradeoff isn't worth it; the LLM augmentation pass cleans this up better than a blunt threshold would. |

**What stays a downstream problem.** `properties[].name === "SrcFile"`
will *still* duplicate `evidence.identity[].methods[].value` even with
CWD fixed (cdxgen has no flag to suppress it). Phase 1.3 ignores it
during extraction.

A small `runCdxgen` change covers all this:

```ts
await execFileAsync(
  cdxgenBin,
  ["-o", outputPath, "--evidence", ...excludeArgs, "."],
  {
    cwd: workingDir,                 // ← NEW
    timeout: 5 * 60 * 1000,
    env: { ...process.env, CDXGEN_DEBUG_MODE: "false", FETCH_LICENSE: "true" },
  },
);
```

Verification: run a `/` scan, grep `../clones/` in the resulting
`scan_runs.sbom_json` — expect zero matches.

#### 1.2 Migration

Add `sbom_components.occurrences` JSONB column, default `[]`. Each
entry is `{path: string, line: number | null}`. Keep
`manifest_file`/`evidence_line` as the "representative" first-occurrence
shortcut (used by `<FileLink>` today and as a cheap query/sort key);
the new column augments rather than replaces.

#### 1.3 Extraction

In `persistAugmentedComponents` (and the legacy `persistComponents`
fallback), walk each component:

1. If `evidence.occurrences[]` is non-empty, parse each
   `location: "path#line"` into `{path, line: parseInt(line) || null}`.
2. Else, collect `evidence.identity[].methods[].value` (or
   `concludedValue` if methods is empty) as `{path, line: null}`.
3. Skip `properties[].name === "SrcFile"` outright — always redundant
   with step 2 per Phase 1 investigation and Phase 1.1 confirms there's
   no flag to suppress cdxgen emitting it.
4. With CWD fixed in 1.1, no path-prefix stripping is needed. Belt-and-
   braces: keep a defensive `path.startsWith("../clones/")` check that
   logs a warning if the prefix ever returns — surfaces a regression in
   the invocation rather than silently re-introducing the bug.
5. Dedupe by `(path, line)`.
6. For LLM-augmented components, also include `llm_evidence.path` as
   an occurrence with `line: null` so the panel always has at least
   one entry.

#### 1.4 Backfill

Worker boot hook `backfillSbomOccurrences` mirrors the existing
pattern — for any `sbom_components` row with `occurrences = []` AND a
non-null `scan_runs.sbom_json`, re-extract from the raw SBOM JSON.
Filters on `occurrences = []` so it's a one-time pass per row. Existing
historical rows pre-date the CWD fix so they'll have clone-prefixed
identity paths; backfill strips the prefix as a one-time data migration
(same regex as the defensive check in 1.3, but actually applied here).

#### 1.5 Tests

`tests/sbomOccurrences.test.ts` covers:
- Occurrence shape with `#line` parsing
- Identity-only fallback (manifest-discovered components)
- Defensive clone-prefix stripping (for backfill of pre-CWD-fix rows)
- LLM-augmentation single-entry case
- SrcFile-property skip
- Verification of the cdxgen invocation change via a tiny integration
  test that runs cdxgen against a fixture dir and asserts no
  `../` in any output path.

### Phase 2 — Backend endpoints

**Linked issues are a scope-page concept only.** "Issue" is the
de-duped, persistent entity living across scans (rows in `sca_issues` /
`sast_issues`); "finding" is the per-scan raw detection (rows in
`scan_findings`). A scope view is a view across the issue layer; a scan
view is a view across the finding layer. Mixing them on a single
endpoint forces every caller to disambiguate. So:

- **`GET /scans/:id/components`** — keep the existing `findings` chip
  surface (raw per-scan detections, already shown). Add `licenses[]`
  and `occurrences[]`. No `linked_issue_ids`.
- **`GET /scopes/:id/components`** — add `licenses[]`, `occurrences[]`,
  AND `linked_issue_ids: { sca: string[]; sast: string[] }`. Derived
  server-side from the scope's `sca_issues` / `sast_issues` rows scoped
  to the **latest scan run** (matches scope-tab semantics).

`linked_issue_ids` join rules:
- **SCA**: `sca_issues.scopeId = scope` AND `package = component.name`
  AND `version = component.version` AND `lastSeenScanRunId =
  scope.lastScanRunId` (same join the OSV phase uses).
- **SAST**: `sast_issues` rows whose `reachable_call_sites` JSON array
  references the component's package — narrow set, only populated for
  reachable SCA-driven findings. May be empty for most components.

This keeps the scan-page Components tab a faithful "what did this scan
detect" view (matching its purpose as an audit surface), while the
scope-page tab becomes the actionable "what should I do about it"
view that cross-references current issues.

**Per-scope SBOM download.** New route `GET /scopes/:id/sbom-json`
returns `scan_runs.sbom_json` for the scope's `lastScanRunId`, with
`Content-Disposition: attachment; filename=sbom-<repo-name>-<scope-slug>.cdx.json`.
Mirrors the existing `/scans/:id/sbom-json` shape. 404 when no
successful scan exists.

### Phase 3 — Frontend ecosystem display

**New helper.** `frontend/src/lib/componentLabels.ts`:

```ts
export function prettyEcosystem(
  ecosystem: string | null,
  discoveryMethod: string,
): { label: string; variant: "ecosystem" | "vendored" } {
  if (discoveryMethod === "llm_augmentation") {
    return { label: "Vendored", variant: "vendored" };
  }
  return {
    label: (ecosystem ?? "—").toUpperCase(),
    variant: "ecosystem",
  };
}
```

Use it in both Components tabs. Vendored variant gets a distinct
muted color (similar to existing Dev badge) so it reads as "category"
rather than "ecosystem name."

### Phase 4 — Frontend Components tab — expandable rows

Apply the same expandable-row pattern as the SAST and SCA tabs (the
existing `<details>`-driven expansion in ScopeDetailPage). Update
both `ScopeDetailPage` and `ScanDetailPage` `ComponentsTab` components.

**New columns** (left to right):
1. **Package** (existing — name + Dev badge + LLM info icon → move
   the LLM tooltip's contents into the expand panel and drop the
   tooltip)
2. **Version** (existing)
3. **Ecosystem** (existing — switch to `prettyEcosystem` helper)
4. **License** (new — first license from `licenses[]`, with "+N more"
   suffix when multiple)
5. **Issues** (new on scope; merge with existing "Findings" on scan) —
   compact severity-coloured chip strip; each chip is a button that
   triggers the cross-tab navigation in Phase 5
6. **Expand chevron** (new)

**Expand panel** shows:
- **License details.** Each license entry from `licenses[]` with its
  full name and SPDX URL (where available). Today these are stored as
  strings — phase 1 doesn't change that, but if the raw SBOM has
  richer license URLs in `licenses[].license.url`, surface them on
  detail-row click (read from `scan_runs.sbom_json` lazily? Or
  persist a richer license shape too — TBD; lean toward "string today,
  rich object in Phase 6 polish if useful").
- **Description.** From `scan_runs.sbom_json` per-row read OR a new
  `description` column on `sbom_components`. Decision: skip for M6q
  scope — `name + version` is enough; revisit if operators ask.
- **Found in.** Render `occurrences[]` as a numbered list. Each entry
  is a `<FileLink template={scope.source_url_template} file=… line=…>`
  matching the existing SAST/SCA pattern. Truncate to first 15 with
  a "show all (N)" disclosure for long lists like jquery.
- **LLM augmentation evidence** (existing — move out of tooltip).
  Renders `llm_evidence.llmReason`, the `FileLink` to
  `llm_evidence.path`, and the excerpt block (`<pre>`) when present.
- **Linked issues.** Renders the same chip strip as the column, but
  expanded with severity + issue title. Click on each navigates per
  Phase 5.

### Phase 5 — Routable detail rows

Deep-link every detail row to its own URL so cross-tab references are
just `<Link>`s and operators can paste a URL into Slack/email/Jira and
land on the exact issue. Replaces the search-param approach in the
first draft of this plan with proper route segments.

#### 5.1 New route shape

Scope page (`ScopeDetailPage`):

| Route | Behaviour |
|---|---|
| `/scopes/:scopeId` | Tabs default to SCA; no row expanded. |
| `/scopes/:scopeId/sca` | SCA tab active; no row expanded. |
| `/scopes/:scopeId/sca/:issueId` | SCA tab active; row `issueId` expanded and scrolled into view. |
| `/scopes/:scopeId/sast` | SAST tab active. |
| `/scopes/:scopeId/sast/:issueId` | SAST tab active; row expanded. |
| `/scopes/:scopeId/components` | Components tab active. |
| `/scopes/:scopeId/components/:componentId` | Components tab active; row expanded. |

Scan page (`ScanDetailPage`) gets parallel routes against findings
(per-scan IDs) rather than issues:

| Route | Behaviour |
|---|---|
| `/scans/:scanId` | Tabs default to findings (current behaviour). |
| `/scans/:scanId/findings` | SCA-findings tab active. |
| `/scans/:scanId/findings/:findingId` | Row expanded. |
| `/scans/:scanId/sast` | SAST tab active. |
| `/scans/:scanId/sast/:findingId` | Row expanded. |
| `/scans/:scanId/components` | Components tab active. |
| `/scans/:scanId/components/:componentId` | Row expanded. |

#### 5.2 Router wiring

`frontend/src/routes/index.tsx` (or wherever the router config lives —
to be confirmed) adds nested routes under the existing scope and scan
pages. The detail page renders the same component for all sub-routes;
inside, `useParams()` reads `issueId` / `componentId` / `findingId` and
`useMatch()` (or `useLocation`'s pathname) determines the active tab.

**Single hook covers all four detail row types.** SCA issues, SAST
issues, components (scope page) and findings (scan page) all use the
same expand-state mechanism — the URL param key just differs by route
segment:

```ts
function useExpandedRowId(): string | undefined {
  // Only one of these will be defined at a time — whichever sub-route
  // matched. `issueId` is shared between SCA and SAST routes (the tab
  // is implied by the path segment, not the param name).
  const { issueId, componentId, findingId } = useParams<{
    issueId?: string; componentId?: string; findingId?: string;
  }>();
  return issueId ?? componentId ?? findingId;
}
```

A row is expanded iff its id matches the URL param. Toggling expand
on a row by clicking its header navigates to the row-scoped route (or
back to the tab-only route if already expanded). React Router's
relative `<Link>` keeps the URL stitched correctly. Every detail row
on the scope page (SCA issue, SAST issue, component) and every detail
row on the scan page (SCA finding, SAST finding, component) becomes
addressable by URL — there is no scope-related row that can be
expanded but not shared.

#### 5.3 Cross-tab linking

Clicking a linked-issue chip on a component:

```tsx
<Link to={`../sca/${issue.id}`}>...</Link>   // relative — sibling tab
```

Browser back returns to the components row with its row-scoped URL
still active (so it stays expanded). No additional state to track.

#### 5.4 Out-of-tree linking

All four row-detail URLs are stable, shareable, and self-contained. A
user can paste any of these into Slack / email / Jira and the
recipient lands on the exact expanded row:

| URL pattern | What the recipient sees |
|---|---|
| `/scopes/<scopeId>/sca/<issueId>` | SCA tab active, that SCA issue expanded and scrolled into view. |
| `/scopes/<scopeId>/sast/<issueId>` | SAST tab active, that SAST issue expanded and scrolled into view. |
| `/scopes/<scopeId>/components/<componentId>` | Components tab active, that component's expand panel open (licenses, occurrences, linked issues). |
| `/scans/<scanId>/findings/<findingId>` | SCA-findings tab active on scan page, that finding expanded. |
| `/scans/<scanId>/sast/<findingId>` | SAST tab active on scan page, that SAST finding expanded. |
| `/scans/<scanId>/components/<componentId>` | Components tab active on scan page, expand panel open. |

The scope and scan pages each fetch their full row set on mount, so
the link works even on a cold page load — the row data is present by
the time the URL resolves and the expand state applies.

#### 5.5 Migration / compatibility

- Existing in-app links to `/scopes/:scopeId` and `/scans/:scanId`
  continue to work; the new routes are additive nested children.
- The Radix `<Tabs>` `value` becomes URL-driven via a small adapter
  that converts the active route segment back into a tab key. No tab
  state in component-local React state.
- No persistence concerns — the route is the state.

### Phase 6 — SBOM download on Scope page

Add a `Download SBOM` button next to the existing scan-trigger / scan
controls on `ScopeDetailPage`. Disabled when `scope.lastScanRunId` is
null. Hits `GET /scopes/:id/sbom-json` per Phase 2.

**Do not** add SARIF download here — SARIF is scan-specific and the
operator can already get it from the scan-detail page.

## Out of scope

- Per-component VEX assertions (a CRA-relevant followup but
  separate concern; would live in its own milestone).
- Persisting richer license shape (URL, name, SPDX expression).
  Phase 4 keeps strings; revisit when an operator asks.
- Editing/annotating occurrence lists from the UI — read-only for now.
- SBOM diff between scans — interesting but unrelated.

## Verification

### Functional

1. **cdxgen invocation at source.** Trigger a fresh scan. Inspect
   `scan_runs.sbom_json` directly: `jq '.components[].evidence.identity[].methods[].value'`
   should show repo-relative paths (e.g. `GoEmulate/GoEmulateApp/packages.config`)
   with zero `../clones/` prefixes. Verifies Phase 1.1 took effect.

2. **Occurrence persistence.** `cef.redist.x64` row's "Found in"
   list shows the single manifest path; `jquery` row shows the
   ~28 source files with line numbers, each rendered as a clickable
   `<FileLink>` to the git remote.

3. **Backfill.** Restart the worker, watch boot logs for
   `backfillSbomOccurrences`. Existing pre-M6q rows get
   `occurrences` populated (with one-time clone-prefix strip applied)
   without a re-scan.

4. **License column.** A row with multiple licenses shows
   `MIT +1 more`; expand panel lists all licenses.

5. **Vendored label.** Every `discovery_method='llm_augmentation'`
   row shows "Vendored" in the Ecosystem column instead of "generic".
   Verified against: `SELECT discovery_method, ecosystem FROM
   sbom_components WHERE discovery_method='llm_augmentation' GROUP BY 1,2`
   — pre-M6q the result is `('llm_augmentation', 'generic')` for all
   rows; post-M6q the UI displays "Vendored" for all such rows
   regardless of the underlying ecosystem value (which stays unchanged
   for compatibility).

6. **Routable detail URLs.** Pasting
   `/scopes/<scopeId>/sca/<issueId>` directly into a fresh tab lands
   on the SCA tab with the exact issue expanded and scrolled into
   view. Same for `/components/<componentId>` and `/sast/<issueId>`.

7. **Cross-tab linking (scope only).** On the scope page Components
   tab, clicking a linked-CVE chip on a vulnerable component navigates
   to `/scopes/<scopeId>/sca/<issueId>` (URL changes); the SCA tab
   activates and the target row expands. Browser back returns to
   `/scopes/<scopeId>/components/<componentId>` with the source row
   still expanded.

8. **Scan-page Components tab unchanged structurally.** Still shows
   the per-scan `findings` chip strip (chips are non-clickable static
   labels — same as today). Adds license + occurrence list in the
   new expand panel. Confirms Phase 2's scope-only split: no
   `linked_issue_ids` on the scan endpoint.

9. **Scope SBOM download.** Button on scope page downloads
   `sbom-<repo-name>-<scope-slug>.cdx.json` (CycloneDX JSON).
   Returns 404 cleanly when no successful scan exists for the scope.

### Non-functional

- TypeScript / vitest both clean.
- `npm run gen:types` regenerated and committed (schema added
  `occurrences` + `linked_issue_ids`).
- No new N+1 queries in the components endpoint — `linked_issue_ids`
  derived in a single grouped query per request.

## Sequencing

Phases 1 → 2 → 3 → 4 → 5 → 6 in order. Phases 1 and 2 are backend
plumbing that must land before any frontend work. Phase 3 is a tiny
isolated helper that can be PR'd standalone. Phases 4 and 5 are the
visible UX changes and can land together. Phase 6 is independent of
Phases 4–5 and can land in any order after Phase 2.

Estimated effort: backend ~½ day, frontend ~1 day, tests + polish ~½
day. Whole milestone fits comfortably in a single Sonnet
implementation session if the plan is followed.
