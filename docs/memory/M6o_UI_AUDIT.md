# M6o — UI consistency audit

A read-through audit of four pages and the components they share. Two scopes:

1. **Original M6i carry-over** — SAST issue UI (list row + expanded panel) vs SCA
   issue UI on `ScopeDetailPage`. Plus the audit-mode versions of both on
   `ScanDetailPage`.
2. **Cross-page consistency** — `/scopes` vs `/scans` (list pages) and
   `/scopes/:id` vs `/scans/:id` (detail pages). Table row content wrapping,
   font weight, badge/lozenge style + color, spacing, time formatting.

The audit catalogues findings; the fix work happens in M6o-impl.

## TL;DR — the headline issues

1. **Four different SeverityBadge implementations** across the app, with two
   completely different color palettes (vivid `bg-red-500/20` vs pastel
   `bg-red-100`). Same severity word renders four different ways depending
   on which page you're on.
2. **Three different time formats** for "when did this happen": relative
   ("9h ago"), Intl-formatted ("May 9, 2026, 02:10"), and locale ISO
   ("5/9/2026, 2:10:54 AM"). All on adjacent pages.
3. **`ScanDetailPage` SAST view uses raw `<pre>` for snippets** instead of the
   `ContextSnippet` component that everything else uses. Visible regression
   from ScopeDetailPage's panel.
4. **List pages disagree on Card structure** — `/scopes` wraps the table in a
   Card with a header ("4 scopes" + icon), `/scans` puts the table straight
   into a Card with no header.
5. **Detail pages disagree on the summary panel shape** — `ScopeDetailPage`
   uses a stacked-bar `SeveritySummary` card, `ScanDetailPage` uses a 5-cell
   `SummaryCard` grid. Same data, different shapes.
6. **Helpers duplicated verbatim** between the two detail pages: `vulnUrl`,
   `VulnLink`, `buildSourceUrl`, `FileLink`, `basename`/`truncateFilePath`,
   `SeverityBadge`. ~80 LOC each.

---

## Section 1 — Cross-page consistency

### 1.1 SeverityBadge — four implementations

| Where | Render | Palette | Shape |
|---|---|---|---|
| `ScopesPage.tsx:19` `SeverityChip` | `<span>` filled | hard-coded `bg-destructive/15 text-destructive` (single red, all severities) | rounded square, `text-xs font-medium` |
| `ScansPage.tsx:60` (inline chip in `FindingsSummary`) | `<span>` filled | `severityChipClass()` from `lib/format.ts` — pastel (`bg-red-100 text-red-800` for critical) | rounded square, `text-xs font-semibold`, label `C:42` |
| `ScopeDetailPage.tsx:75` `SeverityBadge` | `<Badge variant="outline">` | local `SEVERITY_COLORS` map — vivid (`bg-red-500/20 text-red-600 border-red-400`) | rounded-full pill, `text-[10px] uppercase` |
| `ScanDetailPage.tsx:81` `SeverityBadge` | raw `<span>` | `severityChipClass()` — pastel | rounded square, `text-xs font-semibold uppercase` |

Two complete palettes coexist. The shared `lib/format.ts` palette uses Tailwind
`-100`/`-800` shades plus dark-mode variants, and uses `amber` for medium and
`sky` for low. The local `SEVERITY_COLORS` in ScopeDetailPage uses
`-500/20`/`-600` shades (translucent fill) and uses `yellow` for medium and
`blue` for low. So a "medium" severity badge is **amber** on `/scans/:id` and
**yellow** on `/scopes/:id`.

**Recommendation.** Promote `SeverityBadge` to `components/SeverityBadge.tsx`
with one canonical implementation. Pick a palette — proposal: **the vivid
`SEVERITY_COLORS` from ScopeDetailPage** (better contrast, matches the
stacked-bar `SEVERITY_BAR_COLOR` palette already used in the scope summary
card). Delete `lib/format.ts:SEVERITY_CLASSES` after migrating the four
remaining call sites. Keep `severityChipClass` as a thin wrapper around the
new map for the few non-Badge uses.

### 1.2 Time / date formatting

| Caller | Format used | Example output |
|---|---|---|
| `ScopesPage.tsx:115` Last scan column | `formatRelative` | `9h ago` |
| `ScopeDetailPage.tsx:1613` header subtitle | `formatRelative` | `9h ago` |
| `ScopeDetailPage.tsx:631` SAST/SCA "Last seen" | `formatRelative` | `9h ago` |
| `ScansPage.tsx:83` `formatTimestamp` (local helper) | `new Date(iso).toLocaleString()` | `5/9/2026, 2:10:54 AM` |
| `ScanDetailPage.tsx:586` started_at | `formatDate` from `lib/format.ts` (Intl) | `May 9, 2026, 02:10` |

Three formats for "when". `formatTimestamp` in ScansPage doesn't even live in
the shared lib — it's a local copy.

**Recommendation.** Standardize on two:
- **`formatRelative`** for "freshness at a glance" (list pages, "Last seen"
  columns, header subtitles).
- **`formatDate`** for "exact moment" (detail-page header timestamps, hover
  tooltips on relative times).

Delete `formatTimestamp` from `ScansPage`; replace with `formatDate`.

### 1.3 Scan status badge

| Where | Style |
|---|---|
| `ScansPage.tsx:38` `StatusBadge` | local `STATUS_STYLE` map, `<Badge variant="secondary">` — pill with full-color fill (`bg-emerald-100 text-emerald-800` etc), uppercase |
| `ScanDetailPage.tsx:565-570` header status | inline `<p>` with conditional text-color classes, uppercase, no background — very different visual weight |

The list-page badge looks like a pill. The detail-page header status is a
naked colored line of text. Same status, completely different visual style.

**Recommendation.** Promote `StatusBadge` (from ScansPage) to a shared
component. Use it on the detail page next to the title — the colored line of
text reads like body copy and gets lost.

### 1.4 List page Card structure

`ScopesPage.tsx:77-152`:
```jsx
<Card>
  <CardHeader className="pb-0">
    <CardTitle><Layers /> N scopes</CardTitle>
  </CardHeader>
  <CardContent className="pt-4">
    <Table>...</Table>
  </CardContent>
</Card>
```

`ScansPage.tsx:144-216`:
```jsx
<Card>
  <Table>...</Table>
</Card>
```

The Scans page has no row count, no icon, no title — just a bare table inside
a card. The Scopes page has the count and icon at the top of the card.

**Recommendation.** Add a matching CardHeader to ScansPage: `<FileSearch />
N scans`. Use the existing `FileSearch` icon already imported for the empty
state.

### 1.5 List page severity rendering

`ScopesPage.tsx:122-128` (Critical / High column):
- Hard-coded to two severities (C + H).
- Single red color for both: `bg-destructive/15 text-destructive`.
- Format: `5 C`, `12 H`.
- Falls back to a faded checkmark when both are zero.

`ScansPage.tsx:46-81` (Findings column):
- All four severities (C/H/M/L).
- Per-severity color from `severityChipClass`.
- Format: `C:5`, `H:12`, `M:3`, `L:0`.
- Falls back to em-dash.

These pages tell different stories: Scopes implies "only the urgent stuff
matters in the list view", Scans implies "show me everything". Either could
be right for either page.

**Recommendation.** Pick one. Suggest:
- Keep the **Scans** approach (all four, per-color, `C:N` format) — it's more
  informative and the Scans page is clearly the more detailed view.
- Update Scopes to match: `C:6 H:36 M:13 L:1` instead of `6 C 36 H`. Drop the
  custom red-only rendering. Use shared SeverityBadge for the chips.

### 1.6 Pending-triage badge (Scopes only)

`ScopesPage.tsx:138-141`: `<Badge variant="outline" className="gap-1
text-amber-600 border-amber-400"><Clock /> 56</Badge>`. Uses border-only
amber styling.

This is the only place the Pending count is surfaced as a badge. The SCA/SAST
columns next to it are plain numbers. So one number gets a colored pill, two
adjacent ones don't.

**Recommendation.** Either drop the pill-style on Pending (make it a plain
number with `text-amber-600` if non-zero), or wrap SCA/SAST counts in similar
neutral-toned outline badges so all three columns visually match.

### 1.7 Detail page header structure

Both pages use the pattern:
```
← All <list>
<h1>Repo · Path</h1>
<status / meta lines>
```

Fine in skeleton. Differences:

- **`ScopeDetailPage.tsx:1604-1615`**: title puts `· /GoWeb` inline in the
  same `<h1>`, in `text-muted-foreground font-normal`. Subtitle is one line:
  `Branch: master · Last scan: 9h ago`.
- **`ScanDetailPage.tsx:558-590`**: title puts `/GoWeb` in a separate
  `<span className="text-base font-normal text-muted-foreground font-mono">`
  with `font-mono` (no `· ` separator visible — uses `ml-2` whitespace). Then
  4–5 stacked meta lines: status (uppercase colored `<p>`), LLM token usage,
  duration, then a small italic `text-xs text-muted-foreground/80` line with
  the date and a "scope page" backlink.

Two visible differences worth aligning:
1. **Path styling**: `font-mono` on Scan but plain on Scope. Pick one
   (recommend `font-mono` for paths everywhere).
2. **Path separator**: Scope uses `· /GoWeb`, Scan uses just `/GoWeb` (no dot).

The status / meta block on ScanDetailPage is denser because a scan is a
moment-in-time event with operational metadata (duration, token cost). The
scope is an ongoing concept. That's fine — but the **status word styling**
should match, and currently doesn't (see §1.3).

### 1.8 Detail page summary panel

- **`ScopeDetailPage.tsx:130-193`** `SeveritySummary`: one card. Stacked
  horizontal bar (red/orange/yellow/blue segments by count), `<2xl>` total
  number, color-dot legend below, footer with SCA/SAST/Pending counts.
- **`ScanDetailPage.tsx:138-148`** `SummaryCard` × 5: grid of 5 individual
  cards (Components, Critical, High, Medium, Low). Each card has a small
  uppercase label and a `text-2xl font-bold` value. Severity cards pull the
  text-color from `severityChipClass(severity)`'s text class.

The Scope card is a far more attractive summary — it shows proportions, not
just counts. The Scan grid feels like an early-stage "show me the data"
layout that never got upgraded.

**Recommendation.** Reuse `SeveritySummary` on `ScanDetailPage`. It already
takes the same shape inputs (critical/high/medium/low + sca/sast/pending) —
the scan response has all of these (though "pending" doesn't quite apply
mid-scan; pass 0). Add Components count alongside as a small companion. Drop
`SummaryCard`.

### 1.9 Tab counter pill

- `ScopeDetailPage.tsx:1657-1666`:
  `<span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">42</span>`
  (rounded-full, smaller text)
- `ScanDetailPage.tsx:660-668`:
  `<span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs">42</span>`
  (rounded square, larger text)

**Recommendation.** Pick one. Suggest the ScopeDetailPage variant
(rounded-full, `text-[10px]`) — pill counters are the more common pattern in
shadcn/ui-like UIs.

### 1.10 Filter bars

Both detail pages use the shared `FilterGroup`/`Pipe`/`ToggleGroup` from
`components/filters.tsx`. **This is the one area where consistency is good.**
Both pass `colorFn` to `FilterGroup` for severity coloring — but `ScopeDetailPage`
passes the local `SEVERITY_COLORS` map (vivid) while `ScanDetailPage` passes
`severityChipClass` (pastel). So even within the shared filter component,
the active-state colors differ between pages. Falls out automatically once
§1.1 is fixed.

### 1.10b Tab triggers — icons present on Scan, missing on Scope

- `ScanDetailPage.tsx:577-588`: each tab trigger has a leading icon
  (`<ShieldAlert>` for Raw SCA Findings, `<ScanSearch>` for Raw SAST
  Detections, `<Package>` for Components) plus the count pill.
- `ScopeDetailPage.tsx:1654-1670`: tab triggers are plain text — no icons.

The icons are a strong wayfinding cue and the Scope page has all three of
the same concepts (SCA / SAST / Components). Trivial alignment.

**Recommendation.** Add the same three icons to ScopeDetailPage's tab
triggers, with the same `gap-1.5` and `h-3.5 w-3.5` sizing.

### 1.10c Components tab counter — missing on Scope

- `ScanDetailPage.tsx:587`: Components tab shows `{s.component_count}` in
  the canonical pill counter.
- `ScopeDetailPage.tsx:1670`: Components tab is bare — no count, even
  though the scope summary endpoint exposes the same data.

Operators flipping between tabs lose visibility into "how many components
were on the most recent scan" — the answer is one click away (open the
tab, look at the table footer pager) but a header-level count is faster.

**Recommendation.** Add a count pill to ScopeDetailPage's Components tab,
matching the SCA/SAST tabs above it. The latest-scan total is
`scope.last_component_count` (already on the response) — falls back to
nothing while no scan has finished.

### 1.10d Table layout — `table-fixed` + truncation on Scan tables

Visible symptom: long Summary text on `/scans/:id` "Raw SAST Detections"
overflows its column and pushes Severity / Location wider than they
should be. The same SAST issue on `/scopes/:id` doesn't overflow — its
table is `<Table className="table-fixed">` with `<TableCell>` width hints
and `truncate` / `line-clamp-1` on the summary cell.

- `ScopeDetailPage.tsx:773` (SAST) + `:1264` (SCA): `<Table className="table-fixed">`.
- `ScanDetailPage.tsx:686` + `:743`: plain `<Table>` (no `table-fixed`).

Without `table-fixed`, the browser auto-sizes columns based on content.
A long single-line summary string blows past the implicit 24/64-px column
hints we set on Severity / Location, ending in horizontal overflow.

**Recommendation.** Apply `<Table className="table-fixed">` to both Scan
tables (SCA findings + SAST detections). Add `w-6 / w-24 / w-64` cell
widths matching ScopeDetailPage. Wrap the summary cell content in
`truncate` (single-line) — the audit view doesn't need full text in the
row; the expanded panel shows it complete.

### 1.10e Summary cell foreground color — SAST inconsistency

- `ScopeDetailPage.tsx:867` (SAST row) and `:1037` (SCA row): summary
  rendered in a `<span className="text-sm truncate">` — defaults to the
  full foreground color (dark text in light mode).
- `ScanDetailPage.tsx:108` (SCA row): `<div className="line-clamp-1">` —
  also full foreground. ✓ matches.
- `ScanDetailPage.tsx:260` (SAST row): `<TableCell className="text-sm
  text-muted-foreground line-clamp-1">{summary}` — uses **muted**
  foreground. Visibly grayer than every other Summary cell in the app.

So three out of four summary renderings agree on full foreground; the
SAST row on ScanDetailPage is the outlier.

**Recommendation.** Drop `text-muted-foreground` from
`ScanDetailPage.tsx:260`. Optional follow-up: extract a tiny
`<RowSummary>` helper so future drift can't reappear, but a one-class
delete is fine for now.

### 1.11 Duplicated helpers

`ScopeDetailPage.tsx:253-320` and `ScanDetailPage.tsx:71-136` contain
near-identical copies of:

- `vulnUrl` (3 lines)
- `VulnLink` (10 lines)
- `buildSourceUrl` (10 lines)
- `FileLink` (20 lines)
- `basename` / `truncateFilePath` (basically identical, 4 lines)

Plus the two `SeverityBadge` impls (§1.1).

**Recommendation.** Extract to `components/`:
- `components/VulnLink.tsx` (exports `VulnLink`, `vulnUrl`)
- `components/FileLink.tsx` (exports `FileLink`, `buildSourceUrl`,
  `basename`)
- `components/SeverityBadge.tsx`

Delete from both detail pages, import from shared.

---

## Section 2 — SAST issue panel parity (within ScopeDetailPage)

The "M6i carry-over" — when triaging a SAST issue feels different than
triaging an SCA issue, where do they diverge?

### 2.1 Skeleton — already aligned

Both `SastIssueRow` and `ScaIssueRow` (`ScopeDetailPage.tsx:522` / `:898`) use
the same column structure: chevron, severity, summary + copy-link button,
location, status + Jira-attention indicator, last-seen. Same widths
(`w-6/w-24/.../w-64/w-28/w-24`). Same `cursor-pointer hover:bg-muted/40`.
Same JiraCard, same StatusBadge, same Pager. **Don't break this — start from
the SCA row when adjusting SAST.**

### 2.2 Location cell texture mismatch

**SCA** (`:970-1027`): two-line file/package + a chip strip below
(`CVE`/`EOL`/`Has fix`/`Reachable`/`Dev`).

**SAST** (`:599-617`): two-line file/rule-id slug. **No chip strip.** Even
though SAST issues have meaningful flags (CWE list, triage_confidence, LLM
vs Opengrep origin) that could go in a strip if useful.

This makes SCA rows visually richer than SAST rows. Walk down the page and
SCA rows have orange/red/blue lozenges everywhere; SAST rows are just text.

**Recommendation.** Add a small chip strip to SAST rows. Candidates:
- `CWE-N` chip (or `+N more` truncation if `latest_cwe_ids.length > 1`).
- A subtle `LLM`/`Opengrep` chip differentiating rule provenance — but
  consider whether this is operator-relevant. Probably not worth surfacing.
- The `triage_confidence` if present (e.g. "Conf: 80%").

A single CWE chip is probably the highest-value add. Stop short of cluttering
the cell.

### 2.3 Expanded-panel ordering

Both panels use a similar order: optional banner → summary → file link →
snippet → metadata row → reachability → aliases → Jira → action buttons.

Differences:

- **SCA has an `actively_exploited` banner** at the top of the panel
  (`:1048-1056`), styled `border-destructive/40 bg-destructive/10` with a
  ShieldAlert icon. SAST has nothing equivalent — although SAST issues *could*
  be tagged with KEV-style info via CWE-to-CVE-to-KEV chaining (out of scope
  here, but the banner slot is empty).
- **SAST has a "Rule description" paragraph and "LLM reasoning" paragraph**
  (`:640-672`) that SCA doesn't have analogues for.
- **SCA has metadata as a single flex-wrap row** of `OSV / CVE / CVSS /
  Ecosystem / Scope` (`:1080-1111`). SAST has a similar row at `:678-691`
  (`Rule / CWE / Confidence`) — same pattern, ✓.

**Recommendation.** Keep the asymmetry where it reflects real domain
differences (SCA has CVE metadata, SAST has rule reasoning). Two specific
fixes:
- (a) Promote SCA's `actively_exploited` banner to a generic
  `<HighSeverityCallout>` component slot at the top of both panels. Wire it
  into SAST when there's a future signal worth surfacing (e.g. high-confidence
  + critical-severity LLM finding, or a KEV-mapped CWE). Don't render it
  empty for SAST today, just reserve the slot.
- (b) Make sure both panels open with a one-line headline summary (LLM
  summary if present, else first sentence of rule message / OSV summary).
  This is already the case; verify no row hits the "neither set" fallthrough.

### 2.4 Triage action buttons — already aligned ✓

Both `SastIssueRow` and `ScaIssueRow` have identical action-button branches
keyed off the same six statuses. The button labels and variants match
verbatim. Only difference: the SCA `act` mutation calls `useDismissScaIssue`,
SAST calls `useTriageSastIssue`. Don't touch.

### 2.5 Snippet rendering — aligned within ScopeDetailPage

Both use `<ContextSnippet>` (`:656-661` for SAST, `:1072-1077` for SCA).
That's a regression risk to be mindful of in the next section.

### 2.6 Components tab — bug + UX issues

Caught during Batch B browser review. Five sub-issues, one of them a real
backend bug that's been silently broken since M6n.

**(a) Backend bug: `exclude_dev_only` filter never goes off.**
`backend/src/routes/scopes.ts:107` and `:552` declare the param as
`z.coerce.boolean()`. Zod's `coerce.boolean()` is `Boolean(value)` under
the hood, and `Boolean("false") === true` in JS — any non-empty string
coerces to true. So when the frontend sends `?exclude_dev_only=false` the
backend sees `true` and applies the filter regardless of the toggle state.
Verified by curl: both `=true` and `=false` return identical 276-row
results (with 2,174 dev components hidden in both).

This affects the same toggle on the SCA tab as well — it's been a no-op
since M6n shipped. Other `z.coerce.boolean()` filters in the same file
happen to work because the frontend only sends them when `true`
(omitting the param when false), so they never hit the bug path.

**Fix.** Replace `z.coerce.boolean()` with a parser that handles
`"true"` / `"false"` strings correctly. Zod doesn't ship one, but the
common pattern is a `z.preprocess` wrapper. Apply to both `exclude_dev_only`
declarations. Optionally apply to the rest of the `coerce.boolean()`
filters in the file as defense in depth.

**(b) Toggle's visual active-state is too subtle.**
The "Show dev-tool packages" / "Show dev-tool CVEs" toggle uses
`bg-accent text-accent-foreground border-border` for active, which is a
very subtle gray shift — combined with bug (a), clicking the button
appears to do nothing.

Fix once (a) is fixed: convert the bare `<button>` to use the existing
`ToggleGroup` (`components/filters.tsx`) like the "Include resolved"
toggle next to it. ToggleGroup's active state is the same classes but
the user is already trained to read them as a filter on this page.

**(c) Count badge looks like a filter button.**
`{totalRuntime} runtime / {totalDev} dev` sits inline with the toggles,
in `text-blue-600` for the dev count. Blue is the link color
(`VulnLink`, file links) so it reads as interactive. The whole text
reads as a "Runtime / Dev" segmented filter at a glance.

Fix: drop the blue, move the count text to its own subtitle line below
the filter row, rephrase as a static label
("276 of 2,450 components shown · 2,174 dev-tool packages hidden").

**(d) "Scope" column is misleading.**
Shows the raw CycloneDX `scope` value: `required` → relabeled to
`runtime`; `optional` → shown as-is. The column was added before M6n
introduced the truthful `is_dev_only` classifier. cdxgen lumps both
real devDeps and transitive runtime-deps into `optional`, so the column
mixes apples and oranges. The `Dev` badge already conveys the dev/runtime
distinction in the Package cell.

Fix: drop the Scope column. The Dev badge stays.

**(e) "Type" column is noise.**
Shows the cdxgen `component_type` (`library` / `framework` / etc).
Same package can appear with different types when it shows up in
multiple manifests (e.g. jQuery once as a library from package-lock.json
and once as a framework from a vendored .min.js). The values aren't
operator-relevant — cdxgen's classification is heuristic and frequently
flaky.

Fix: drop the Type column. If component-type ever becomes load-bearing,
re-add as a tooltip on the package name.

---

## Section 3 — ScanDetailPage SAST/SCA panels

This is the audit/debug view. Lower priority for triage UX, but currently
diverges from ScopeDetailPage in ways that make the audit view feel
half-finished.

### 3.1 SAST snippet uses raw `<pre>` — regression vs ScopeDetailPage

`ScanDetailPage.tsx:359`:
```jsx
<pre className="rounded bg-background border p-3 text-xs overflow-x-auto font-mono whitespace-pre-wrap">{issue.latest_snippet}</pre>
```

vs ScopeDetailPage's `<ContextSnippet snippet={...} matchLine={...}
matchEndLine={...} />` — which paints the matched line range with a yellow
highlight band and shows real file line numbers in a gutter.

The audit view loses both features. Operators dropping into the audit view
get a worse view of the same data.

**Recommendation.** Use `ContextSnippet` here too. Trivial swap:

```jsx
{issue.latest_snippet && !issue.latest_snippet.startsWith("__absence__:") && (
  <ContextSnippet
    snippet={issue.latest_snippet}
    matchLine={issue.latest_start_line}
    matchEndLine={issue.latest_end_line}
  />
)}
```

(Plus the absence-string handling that's in ScopeDetailPage.)

### 3.2 SCA expanded panel — already mostly aligned

`ScanDetailPage.tsx:216-307` `FindingRow` expanded body is structurally
similar to `ScopeDetailPage.tsx:1045-1216` `ScaIssueRow` body — same
actively_exploited banner, same metadata row, same `ReachabilityVerdict`,
same aliases. The Scan version omits Jira (correct for an audit view) and
the action buttons (correct).

One small drift: the audit view's metadata row uses `font-medium` for the
field labels (`<span className="font-medium">OSV: </span>`) — same as
ScopeDetailPage. ✓ 

### 3.3 SAST expanded panel — sparse vs ScopeDetailPage

`ScanDetailPage.tsx:345-372` SAST expansion is a stripped-down version of
ScopeDetailPage's. Misses:
- CWE badge styling (uses plain `<Badge variant="outline">` not styled chips)
  — currently OK, just outline pills with the CWE id. Acceptable.
- Triage reasoning text — but the audit view doesn't have a triage_reasoning
  field on raw detections, so this is correct.

The big issue is §3.1. Otherwise the SAST audit view is fine.

### 3.4 Components tab on ScanDetailPage

`ScanDetailPage.tsx:381-444` `ComponentsTab` is a different component from
`ScopeDetailPage.tsx:1389-1482` `ComponentsTab` (same name, different
module). They share no code.

Differences:
- **Filter UX**: Scan uses a checkbox `<input type="checkbox">` for "Only
  show components with findings (N)"; Scope uses a custom toggle button
  styled like the rest of the Scope filter bar.
- **Scope column**: Scan doesn't show a Scope column; Scope shows it.
- **Dev badge**: Scan doesn't render the `Dev` badge; Scope does.
- **Findings column**: Scan has a "Findings" column with severity-colored
  CVE/EOL chips per component; Scope has no equivalent (because at the
  scope level, findings are tracked separately via SCA issues, not per
  component).

The Scan-side "Findings" column is genuinely useful in audit mode — given a
component, see which CVEs OSV matched. Don't unify; keep both views. But:

**Recommendation.** Make the toggle UX match (use the styled toggle button
from Scope, drop the bare checkbox). Add the `Dev` badge to the package name
on Scan for consistency.

---

## Section 4 — Recommended remediation order

Three batches, increasing scope. Each is self-contained and can ship as its
own PR.

### Batch A — "Make the same thing look the same" (~half day)

The sky-is-different/grass-is-different problems. Pure visual unification,
no behavior change.

1. Extract `SeverityBadge`, `VulnLink`, `FileLink`, `basename` to shared
   components (§1.11). Pick the SCOPE palette (vivid). Update both detail
   pages and `ScansPage.tsx`. Delete `lib/format.ts:SEVERITY_CLASSES`,
   replace `severityChipClass` with a wrapper around the new map.
2. Standardize time formatting (§1.2). Delete `formatTimestamp` from
   ScansPage. Add `title` tooltips on relative times to show the exact
   timestamp on hover.
3. Promote `StatusBadge` from `ScansPage` to a shared component, use on
   `ScanDetailPage` header (§1.3).
4. Fix tab counter pill (§1.9) — change `ScanDetailPage` to `rounded-full
   text-[10px]`.

### Batch B — "Tighten cross-page parity" (~half day, slightly larger now)

Where the pages tell different stories of the same data — make them tell the
same story.

5. Add CardHeader to `ScansPage` table card (§1.4).
6. Switch `ScansPage` severity chips to all four severities, per-color,
   `C:N` format using the shared SeverityBadge (§1.5). Or pick the other
   direction; decide as a one-line bikeshed before the work.
7. Replace `SummaryCard` grid on `ScanDetailPage` with `SeveritySummary`
   reused from ScopeDetailPage (§1.8). Move `SeveritySummary` to a shared
   component file in the process.
8. Align detail-page header path styling (`font-mono` everywhere) (§1.7).
9. Add the three tab-trigger icons (ShieldAlert / ScanSearch / Package) to
   `ScopeDetailPage`'s tabs, matching `ScanDetailPage` (§1.10b).
10. Add a count pill to `ScopeDetailPage`'s Components tab using the latest
    scan's component count (§1.10c).
11. Apply `<Table className="table-fixed">` and matching `w-6 / w-24 / w-64`
    cell hints + `truncate` on the summary cell to both `ScanDetailPage`
    tables (Raw SCA Findings + Raw SAST Detections), to fix the SAST
    overflow visible on `/scans/:id` (§1.10d).
12. Drop the lone `text-muted-foreground` on `ScanDetailPage.tsx:260` so
    SAST summaries match every other Summary cell in the app (§1.10e).

### Batch C — "Polish the SAST/SCA detail panels" (~half day, slightly larger)

The original M6i carry-over plus the Components-tab bug + cleanup caught
during Batch B review.

13. Replace raw `<pre>` snippet with `ContextSnippet` on `ScanDetailPage`
    SAST view (§3.1).
14. Add a CWE chip to SAST issue rows on `ScopeDetailPage` (§2.2).
15. Promote SCA's `actively_exploited` banner into a generic
    `HighSeverityCallout` slot at the top of both expanded panels (§2.3a).
    Don't add SAST signals yet — just reserve the slot.
16. On `ScanDetailPage` Components tab: swap checkbox for styled toggle,
    add `Dev` badge (§3.4).
17. Fix the `z.coerce.boolean()` bug on `exclude_dev_only` (§2.6a). Replace
    with a `z.preprocess`-based string-aware boolean parser. Apply to both
    `exclude_dev_only` declarations in `routes/scopes.ts`. Optional: also
    swap the other `coerce.boolean()` filters as defense in depth.
18. Components tab (Scope) UX: convert the dev-tool toggle to the existing
    `ToggleGroup` for clear active-state feedback; drop the blue color on
    the count text; move counts to a subtitle line beneath the filter row
    (§2.6b–c).
19. Drop the "Type" and "Scope" columns from the Scope Components tab — the
    Dev badge already conveys the runtime/dev distinction, and cdxgen's
    type/scope values mislead more than they inform (§2.6d–e).

### Out of scope

- **`SbomViewerPage`** and **`SastSarifViewerPage`** — viewer pages over
  large JSON blobs, separate concern. Glance only.
- **Admin pages** (`/admin/repos`, `/admin/credentials`, `/admin/settings`)
  — different visual lineage (form-heavy), not touched here.
- **Login page** — single-purpose, not relevant.
- **Dashboard** — already on the queue to get merged into `/scopes`
  (separate pending feature in MEMORY).
- **A complete shadcn/ui design-system audit.** Stay focused on the four
  pages in scope.

## Verification plan for the impl session

After Batch A: the four list/detail pages should screenshot-diff cleanly
against equivalents — same severity colors, same time formatting, same status
pill style. Browser walk-through:
- `/scopes` → one severity row should match `/scans` row of the same scan.
- `/scopes/:id` SAST badge color should match `/scans/:id` SAST badge color.
- `formatRelative` titles should show the exact `formatDate` timestamp on hover.

After Batch B: `/scans` should have a row count header, `/scans/:id` should
have the same summary panel shape as `/scopes/:id`, severity-chip stories
match across list pages.

After Batch C: open a SAST issue on the audit view (`/scans/:id`) and
confirm the snippet has line numbers and a yellow highlight band, matching
the scope page. Confirm a SAST row on `/scopes/:id` shows a CWE chip if the
issue has CWE ids.
