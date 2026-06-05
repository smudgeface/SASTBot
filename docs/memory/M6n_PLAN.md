# M6n — SBOM / SCA dev-tree filtering

## Goal

For an npm-heavy repo, ~89% of cdxgen's component output is the developer's
build-tool dependency tree (webpack / babel / jest / @types / their
transitives). None of it ships in the product, so none of it is CRA-relevant.
Today SASTBot persists all of it AND queries OSV against all of it AND surfaces
the resulting CVE noise on the SCA tab AND lets it eat hint-set slots in the
LLM detection pass.

Validate the bloat (done — see "Investigation findings" below), then ship a
single per-repo flag that, when off, hides dev-only components and their CVE
noise from every consumer (OSV queries, SCA tab, Components tab, LLM hints).
Default the flag off so new repos get the clean view.

## Investigation findings

Reference SBOM (hand-curated by Claude Code in a prior experiment, in
`docs/Claude CRA Analysis Reference/SBOM_CycloneDX.json`): **41 components**
across three Gocator Classic repos.

SASTBot today on the same product (one repo, `gocator.git`):

| scope | total components |
|---|---|
| `/` | 45 |
| `/GoWeb` | 2,436 |

GoWeb npm breakdown (cdxgen 12.2's `cdx:npm:package:development=true` marker
mirrored onto `SbomComponent.isDevOnly`):

| `is_dev_only` | cdxgen `scope` | count | what these are |
|---|---|---|---|
| **true** | optional | 2,119 | transitive devDeps (webpack/babel/jest/lint trees and fanout) |
| false | optional | 219 | transitive **runtime** deps (antd's children, mobx-react's deps, …) |
| true | required | 55 | direct devDeps declared in package.json (webpack 4, gulp 3, node-sass) |
| false | required | 42 | direct **runtime** deps — antd, mobx, react, three, kendo-react, jquery, … |
| (none ecosystem) | required | 14 | LLM `vendored_lib` hits — jQuery 1.11.0, jQuery UI 1.8, RequireJS, Closure Library, CodeMirror, Underscore, … |

So **2,174 of 2,436 GoWeb components (89%) are flagged dev-only**. The
remaining 262 (42 + 219 + 14 vendored + 1 maven) is the same order of magnitude
as the reference's 41, with the same headline packages.

SCA noise impact (Gocator Classic):

```
scope    sca_total  sca_dev_only  sca_runtime
/             22         0            22
/GoWeb       322       284            38      ← 88% of findings are dev-tree CVEs
```

LLM cost impact: hint set is capped at `LLM_SCA_HINT_CAP = 200` in
`backend/src/worker.ts:133`. With dev components included, dev-tree
critical/high CVEs compete for those slots ahead of legitimate runtime CVEs,
and the LLM's Goal 2 reachability analysis spends tokens on packages that
don't ship.

The flag `Repo.reachabilityIncludeDevDeps` already exists and gates the LLM
hint set correctly at `backend/src/worker.ts:160`. Default is `true`. M6n
extends it to gate three more consumers and flips its default.

Considered alternatives (rejected):
- **cdxgen `--required-only`** drops `scope=optional` at SBOM-generation time.
  Too blunt — the 219 transitive runtime deps are `scope=optional` too, and
  that's where most real npm CVEs live. Loses CVE coverage permanently.
- **Per-repo "skip transitives entirely" flag.** Same problem: drops legit
  transitive runtime deps. CRA cares about what runs, including transitives.
  The legitimate ask ("show me only what's in package.json") is a UI-only
  view — ship as a `Direct only` toggle later if anyone asks.

## Decision

**Option C, narrowly scoped**: keep cdxgen's full output in `sbom_components`
(no data loss), and gate four downstream consumers on `is_dev_only` per a
single per-repo flag.

- **Reuse** `Repo.reachabilityIncludeDevDeps`. Don't rename — the current name
  was accurate when it gated only the LLM hint set, and a rename costs a
  prisma migration without changing behavior. CLAUDE.md gets a one-line note
  explaining its broader role.
- **Flip default** from `true` to `false`. New repos and existing repos both
  pick up the new default unless explicitly overridden.
- **Four consumers** all read it and apply the same filter (`isDevOnly = false`).

## Implementation steps

### 1. Schema migration (`backend/prisma/schema.prisma`)

Flip the default on `Repo.reachabilityIncludeDevDeps` from `true` to `false`.

```
prisma migrate dev --name m6n_default_exclude_dev_deps
```

This changes the column default for new repo rows. **Existing rows keep their
current value** (Postgres `ALTER COLUMN ... SET DEFAULT` doesn't touch existing
rows). The one-shot worker backfill (step 5) handles rows already in the
unwanted state by suppressing their dev-only SCA issues.

Also: do NOT ship a server-side migration that flips existing repos' values.
Operators may have explicitly set the flag and we shouldn't override.

### 2. Repo edit form default (`backend/src/services/repoService.ts:97`, `:164`)

`createRepo` currently does `input.reachability_include_dev_deps ?? true`.
Change the fallback to `false`. The Zod default in
`backend/src/schemas.ts:210` (`z.boolean().default(true)`) also flips to
`false` for the create-input shape.

### 3. OSV-query gate (`backend/src/services/osvService.ts`)

In `queryAndPersistFindings` (the OSV batch query that drives SCA persistence),
read the repo's flag from the scope/repo lookup and skip components with
`isDevOnly = true` when the flag is false.

Two ways to implement:
- **(a)** Filter the component list before it hits the OSV batch endpoint.
  Saves the OSV API calls. **Preferred.**
- **(b)** Query OSV for everything but skip `upsertScaIssueFromDetection` for
  dev-only components. Simpler diff, costs OSV calls. Skip — pointless
  network traffic.

The function signature already takes the components list; the caller in
`worker.ts` knows the repo. Pass `includeDevDeps: boolean` explicitly so the
service stays pure (no Prisma read for the repo flag inside osvService).

Also add a no-op log line when filtering kicks in:
`logger.info({ filtered: <n> }, "[osvService] excluded dev-only components from OSV query")`.

### 4. UI default filters

- **Components tab** (`frontend/src/routes/ScopeDetailPage.tsx:1369` —
  `ComponentsTab`). Default the existing `has_findings` UI to also include a
  new `dev` toggle. Default state: hide `is_dev_only=true`. Toggle label:
  `Show build-tool packages`. Surface counts in the tab header:
  `262 runtime / 2,174 build` (compute from the API response or add `total_dev`
  / `total_runtime` to the route response).

  Backend route to update: `backend/src/routes/scopes.ts:531` — add
  `is_dev_only?: boolean` to `querystring`, apply to the `where` clause if set.

- **SCA Issues tab** (same page). Default the SCA filter to
  `latestIsDevOnly = false` with a toggle. Mirror the count badge pattern.
  The route is in the same file (`/api/scopes/:id/issues`) — extend its
  querystring and `where` similarly.

Frontend query hook updates: `frontend/src/api/queries/scopes.ts:109` (and the
SCA-issues hook nearby). Add the new query-string parameter; default to
`is_dev_only: false` in the call site.

Re-run `npm run gen:types` once the route schemas are updated.

### 5. One-shot worker backfill (`backend/src/worker.ts`)

New function `backfillDevOnlyScaIssues`, registered alongside the existing
`backfillLlmSummaries`, `backfillManifestPathPrefixes`, etc. (see
`worker.ts:659` for the registration pattern).

```ts
async function backfillDevOnlyScaIssues(): Promise<void> {
  // For every repo with reachabilityIncludeDevDeps = false, find active
  // (non-terminal) ScaIssue rows where latestIsDevOnly = true and mark them
  // as fixed-by-dev-tree-policy so they drop off the default SCA tab without
  // forcing a re-scan.
  //
  // Idempotent: filtered on `latestIsDevOnly = true AND status NOT IN
  // ('fixed','suppressed','false_positive')`. Re-running a no-op.
  const repos = await prisma.repo.findMany({
    where: { reachabilityIncludeDevDeps: false },
    select: { id: true },
  });
  if (repos.length === 0) return;
  // ... bulk update via prisma.scaIssue.updateMany on scopeId in (scopes of these repos)
  //     with status='suppressed' and a new resolution_reason='dev_tree_policy'
  //     (or use status='fixed' if we want the auto-fix sweep semantics —
  //     bikeshed at impl time)
}
```

Bikeshed call to make in the impl session:
- **status='fixed'** — same lane as the auto-fix sweep; row hides from default
  tab; surfaces in "Fixed" filter. Less honest about *why* it's hidden.
- **status='suppressed' with reason** — needs a new reason enum value
  (or reuse an existing one). More honest. Probably the right call.

Either way, log a one-line summary on completion: rows updated per repo.

### 6. CLAUDE.md note

Add a bullet under the "Worker-startup backfills" section (or alongside the
existing dev-marker note) explaining that `Repo.reachabilityIncludeDevDeps`
gates four consumers (OSV, UI Components tab, UI SCA tab, LLM hint set), not
just reachability — keep the column name for migration cost reasons.

### 7. PROGRESS.md entry

Standard format: dated header, "what shipped", "what we learned". Highlight
the 89%-bloat finding and the cross-consumer flag pattern.

## Out of scope

- **Renaming the flag.** Not worth a prisma migration just to make the name
  read better. Document the broader role and move on.
- **`Direct only` UI toggle.** The "show me only direct deps" view is a
  legitimate ask but cosmetic; defer until someone hits it.
- **Non-npm dev filtering.** No equivalent of `dev: true` exists for nuget /
  generic / maven. The 11 generic CMake-noise rows on `/` (Boost, gtest,
  Threads, Sanitizers, PythonInterp) are a separate cleanup item — file as
  M6o or similar.
- **Touching cdxgen flags.** `--required-only` is too blunt; revisit only if
  the dev-marker filter proves insufficient in practice.
- **Cross-scope component dedup.** jquery@1.11.0 appears in both `/` and
  `/GoWeb` scopes today (vendored hits in different paths). That's correct —
  scopes are independent — leave alone.

## "Done" looks like

- Components tab on `/GoWeb` defaults to ~262 entries with a clear `2,174 build
  packages hidden` indicator and a working toggle.
- SCA Issues tab on `/GoWeb` defaults to ~38 findings with the same indicator.
- LLM hint set on a fresh `/GoWeb` scan no longer contains dev-tree CVEs (log
  line in `worker.ts` reflects the smaller count when the flag is false).
- Worker boot log shows one-shot backfill ran once and updated N rows; second
  boot shows it ran and updated 0 (idempotent).
- Repo edit dialog reflects the new default for newly created repos.
- New PROGRESS entry; CLAUDE.md note updated.
