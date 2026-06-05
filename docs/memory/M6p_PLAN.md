# M6p — SBOM accuracy: post-processing + LLM augmentation

## Goal

The SBOM produced for a CRA report should match what a thoughtful human auditor
would assemble. Today's cdxgen-only pipeline is structurally noisy (CMake
internals, .NET BCL assemblies, version dupes) and structurally blind to
vendored C/C++ code without manifests (the bulk of an embedded device's
attack surface). The hand-curated reference SBOM at
`docs/Claude CRA Analysis Reference/SBOM_CycloneDX.json` shows what a good
result looks like — but it too has blind spots.

Build a two-stage pipeline that takes cdxgen's output as a seed, removes
mechanical noise (Stage 1), and asks an LLM to confirm/reject/augment by
reading the actual source tree (Stage 2). Aim for the next Gocator Classic
scan's `/` and `/GoWeb` component lists to read like the reference.

## Investigation findings

(Full analysis lives in the conversation log; key facts duplicated here for
the impl session.)

### What's wrong with cdxgen-only today

Per the recent `/` scan (60 stored components) vs the reference's 39
gocator-attributed entries:

| Category | Examples from `/` scan | Action |
|---|---|---|
| **Mechanical dupes** | `CLI11` ×3 (lowercase, `${VERSION_STRING}` literal, real 1.8.0); `GoSdkNet` ×4 (versionless + 3 versions); `kApiNet` ×4; `gtest`/`gmock`/`GoogleTest`/`googletest-distribution` for one library; `Hardcodet.Wpf.TaskbarNotification` vs `Hardcodet WPF NotifyIcon`; `Xceed.Wpf.Toolkit` vs `Xceed Extended WPF Toolkit` | Stage 1 — dedupe |
| **CMake build outputs** | `Threads`, `PythonInterp`, `Sanitizers`, `PackageTest` | Stage 1 — drop |
| **Test framework metadata** | `Microsoft.VisualStudio.QualityTools.UnitTestFramework`, googletest variants | Stage 1 — drop |
| **.NET BCL / runtime** | `System.Xml`, `System.Core`, `PresentationCore`, `PresentationFramework`, `WindowsBase`, `Microsoft.CSharp` | Stage 1 — drop (with allowlist for legit `System.Net.Http`-style external packages on older .NET targets — see §1.2) |
| **First-party LMI packages** | `GoSdkNet`, `kApiNet`, `GoAcceleratorEngine` | Stage 2 — LLM identifies & flags as first-party |
| **Suspicious low-confidence singletons** | `Boost @ 1.61` (only Boost reference cdxgen surfaces), `ZedGraph 5.1.5`, `Python @ —` | Stage 2 — LLM confirms or rejects from source |
| **Bad version strings** | `CLI11 @ ${VERSION_STRING}` (unresolved CMake variable) | Stage 1 — drop |

### What the LLM-curated reference got right

Compared to cdxgen, the reference:
- Correctly classified components by repo (gocator/, ve/, fss/) and only enumerated CRA-relevant third-party deps
- Found 3 components cdxgen missed entirely on `/` (MSVC Runtime 2013, GNU gettext 0.19.6, IpToCountry)
- Excluded all the mechanical noise listed above

### What the LLM-curated reference got wrong

The reference DOES have blind spots — **cdxgen caught at least one real
third-party dependency the LLM missed:**

- **CefSharp / Chromium Embedded Framework.** Verified by `grep CefSharp` in
  the clone: `GoEmulate/GoEmulateApp/Program.cs`, `MainCef.cs`, plus a full
  `CefBrowser/` directory with 6 lifecycle handlers. `GoEmulate` is a
  Windows desktop emulator that embeds Chromium. The reference doesn't
  mention CEF at all — likely because the LLM treated `GoEmulate/` as
  out-of-scope tooling vs the firmware/UI proper. cdxgen found it from the
  `packages.config` / `.csproj` files.

Lesson: **neither tool alone is sufficient.** cdxgen's noise floor is too
high; LLM's coverage of "what's actually in this tree" depends on what it
chose to look at. The two-stage pipeline below uses cdxgen as a safety net
the LLM has to actively reject from, rather than asking the LLM to write
the SBOM from scratch.

## Stage 1 — Mechanical post-processing

A pure function over the cdxgen output, runs in
`sbomService.persistComponents` between parsing the CycloneDX JSON and
writing the SBOM components to the DB. No backend dependencies, no LLM
calls, fully deterministic.

### 1.1 Rules

In order. Each rule has a single responsibility; each is testable in isolation.

**(a) Drop entries with placeholder version strings.**
- Pattern: `version` matches `^\$\{[^}]+\}$` or `^@\{[^}]+\}$` (CMake `${X}`
  / MSBuild `@{X}` placeholders that weren't substituted).
- Examples killed: `CLI11 @ ${VERSION_STRING}`.

**(b) Drop CMake-internal package-config targets.**
- Hardcoded blocklist of known `find_package()` results that aren't real
  components: `Threads`, `PythonInterp`, `Python` (the bare standalone, not
  `python3-*` packages), `Sanitizers`, `PackageTest`, `googletest-distribution`.
- Match on `name` exactly (case-insensitive), `ecosystem=generic` or
  `ecosystem=null`.
- Document the list in the source with the M6p marker so it's easy to find
  and extend.

**(c) Drop .NET BCL / runtime assemblies.**
- Hardcoded blocklist of known runtime-bundled assemblies: `System`,
  `System.Core`, `System.Xml`, `System.Xml.Linq`, `System.Data`,
  `System.Data.DataSetExtensions`, `System.Deployment`, `System.Drawing`,
  `System.Windows.Forms`, `System.Xaml`, `System.Configuration`,
  `PresentationCore`, `PresentationFramework`, `WindowsBase`,
  `Microsoft.CSharp`.
- **Allowlist exceptions** (keep these — they are nuget-distributed even
  though they look like BCL): `System.Net.Http` (was a separate nuget pre-.NET
  4.5; some Gocator projects target .NET 4.0), `System.Data.SqlClient`,
  `System.Memory`, anything with an explicit version that includes a
  `-preview` suffix.
- The right way to make this robust is to drop based on PURL prefix
  `pkg:nuget/System.*` when the version is a 4.x assembly version (e.g.
  `4.0.0.0`, `4.6.0`) AND the component has no resolved hashes — but the
  simple namelist gets us 90% there.

**(d) Drop test-only frameworks.**
- Blocklist: `Microsoft.VisualStudio.QualityTools.UnitTestFramework`,
  `xunit*`, `NUnit*`, `MSTest*`, `gtest`, `gmock`, `GoogleTest`.

**(e) Coalesce versionless + versioned pairs.**
- Group by canonical key: lowercase `name`, ecosystem.
- If any row in the group has a `version` set AND at least one row has
  version `null`/empty, drop the versionless row(s).
- Keep multiple versioned rows of the same package as distinct (real:
  different Visual Studio projects can pin different versions; we want to
  see all of them).

**(f) Normalize name capitalization within a canonical-key group.**
- Once duplicates by `lowercase(name)` are detected, pick the version of the
  name that's most "package-like" (preference: matches `purl` if present
  → matches an upstream-conventional casing in a small allowlist → first
  occurrence). Drop the alphabetic-only-different copies.
- This kills `cli11` vs `CLI11`, `Hardcodet WPF NotifyIcon` vs
  `Hardcodet.Wpf.TaskbarNotification` (these read as a naming-style choice;
  prefer the dotted-form which matches the nuget package id).

**(g) Coalesce naming variants of the same package.**
- Special-case: when the cdxgen output contains both a "friendly name" and
  a "package id" variant (e.g. `Hardcodet WPF NotifyIcon` + `Hardcodet.Wpf.TaskbarNotification`, `Xceed Extended WPF Toolkit` + `Xceed.Wpf.Toolkit`), prefer the package id and drop the friendly name.
- Implementation: a small alias map maintained alongside the blocklist.
  Manageable size; if it grows past ~20 entries the right answer is to ask
  the LLM in Stage 2.

### 1.2 Implementation

- Single function `postProcessComponents(components: SbomComponent[]): SbomComponent[]` in `sbomService.ts`.
- Called from `persistComponents` before the existing `canonicalPackageName` step (so dedupe runs on raw cdxgen output, not the canonicalized form).
- Each rule is a separate small function; the top-level function chains
  them in the order above.
- Constants (`CMAKE_INTERNAL_BLOCKLIST`, `BCL_BLOCKLIST`,
  `BCL_ALLOWLIST_EXCEPTIONS`, `TEST_FRAMEWORK_BLOCKLIST`,
  `NAMING_ALIAS_MAP`) live at the top of the file, each with a one-line
  comment justifying the entry so future maintainers don't yank an item
  that looks innocuous but is load-bearing.

### 1.3 Unit tests

Critical to land tests here because the rules will accumulate and we need
regression coverage. One test per rule:

- `(a) drops ${VERSION_STRING} placeholders`
- `(b) drops Threads/PythonInterp/Sanitizers/PackageTest`
- `(c) drops System.Xml but keeps System.Net.Http on .NET 4.0`
- `(d) drops gtest/gmock`
- `(e) collapses GoSdkNet versionless when versioned rows exist`
- `(f) collapses cli11 + CLI11 to canonical case`
- `(g) collapses Hardcodet WPF NotifyIcon → Hardcodet.Wpf.TaskbarNotification`

Plus an integration test that takes a saved cdxgen output (the current
Gocator Classic `/` scan, 60 components) and asserts the post-processed
result has the expected ~40 components, with a snapshot of the canonical
list checked in.

### 1.4 Expected outcome

The `/` scope `sbom_components` count drops from 60 → ~40 after this
stage. Stage 1 alone won't get us to the reference because the missing
items (MSVC Runtime, gettext, IpToCountry) need source-level inspection
that's Stage 2's job.

### 1.5 Risk

The blocklists are inherently arbitrary. The mitigation is:
- Every blocklist entry has a comment explaining why.
- The first time a blocklist false-positive bites us (someone genuinely
  ships a package called `Threads`), we add an explicit allowlist alongside.
- Stage 2 sees the post-Stage-1 output, so if the LLM disagrees with a
  blocklist decision it can re-add the component.

## Stage 2 — LLM augmentation pass

A new worker phase, `llm_sbom`, that runs after `cdxgen` + Stage 1 but
before `osv`. It's the SBOM analogue of the existing `llm_detection`
phase: invoke claude-p with the source tree mounted, hand it the
Stage-1-cleaned cdxgen SBOM as input, ask it to produce a final SBOM by
confirming/rejecting/augmenting.

### 2.1 Architecture

Mirror `llmSastService` as closely as possible — same orchestrator pattern
(`spawnClaudeAndStream`), same prompt-file layout (`backend/prompts/`),
same JSON-line output contract.

- New service: `backend/src/services/llmSbomService.ts` with
  `runSbomAugmentation(input): Promise<SbomAugmentationResult>`.
- New prompt files: `backend/prompts/sbom_system.md` and
  `backend/prompts/sbom_augmentation.md`.
- New worker phase wired into `worker.ts` between Step 3 (cdxgen) and Step 4
  (OSV).
- Repo-level effort field: `repos.llmSbomEffort` (default `medium`;
  mirroring `llmSastEffort`/`llmRecheckEffort` from M6m).

### 2.2 Inputs handed to the LLM

The prompt's input block contains:
- **The Stage-1-cleaned cdxgen SBOM** as a single JSON file the LLM can
  re-read via its `Read` tool. **Don't inline it in the prompt** — it's
  hundreds of components on big repos. Write it to a tmp file inside the
  clone directory and tell the prompt where to find it.
- **The scope path** (`/` or `/GoWeb`) so the LLM knows which subtree to
  inspect.
- **The clone working dir** (set as cwd for claude-p; the prompt tells it
  to use `Glob` / `Grep` / `Read` to inspect files).
- **Known first-party namespaces from the repo** — pulled from a new
  optional repo field `repos.firstPartyNamespaces` (string[]; e.g.
  `["LMI.", "Go", "kApi"]`). When the LLM sees a component matching one
  of these prefixes, it classifies it first-party and excludes. Default
  empty; operator sets it per repo. (This addresses §2 in the audit's
  Stage-1 caveats — first-party detection is a per-repo policy, not a
  hardcoded rule.)
- **Known vendored-code directories from the repo** — `repos.vendoredDirs`
  (string[]; default `["extern/", "third-party/", "vendor/"]`). The LLM
  scans these specifically for libraries that cdxgen missed.

### 2.3 What the LLM outputs

A JSON-line stream where each line is one of three record types
(claude-p's typical structured-output protocol):

```jsonc
{"type": "keep", "component_id": "..."}     // confirm a cdxgen component
{"type": "drop", "component_id": "...", "reason": "first-party LMI package"}
{"type": "add", "name": "MSVC Runtime", "version": "2013 (v12.0)",
                "ecosystem": "generic", "evidence_path": "GoEmulate/GoEmulateApp/GoEmulateApp.csproj",
                "evidence_excerpt": "<PlatformToolset>v120</PlatformToolset>"}
```

`evidence_path` is required for every `add` and recommended for every
`drop`. Stored in a new column `sbom_components.llm_evidence` (jsonb,
nullable) so the operator can audit why a component is or isn't there.

### 2.4 Prompt design (sketch)

Two prompts, paralleling `sast_system.md` / `sast_detection.md`:

**`sbom_system.md`** — role + ground rules:
- "You are auditing the third-party software inventory of a product
  preparing a CRA Article 13 SBOM."
- "Your goal is to produce the list of *third-party* code shipped in this
  product, suitable for CVE monitoring."
- Definition: exclude first-party (own org), build-time-only tooling, and
  .NET BCL/runtime assemblies. Include vendored third-party C/C++ libraries
  even when there's no manifest, by reading source headers and CMakeLists.
- Output format spec for keep/drop/add records.

**`sbom_augmentation.md`** — task block:
- "Read $SBOM_FILE (the cdxgen-generated SBOM, already cleaned of
  mechanical noise)."
- "For each component, emit either a `keep` or `drop` record. Use `drop`
  for first-party packages (FIRST_PARTY_NAMESPACES), test-only tooling, or
  duplicates."
- "Then, inspect VENDORED_DIRS in the source tree. For each subdirectory
  that's a vendored third-party library, emit an `add` record. Read
  `<library>/CHANGELOG`, version headers, or `package.json`-like files for
  the version. If the version is unknowable, emit version `null` and
  include a `version_unknown: true` flag."
- "Also inspect `.csproj`, `packages.config`, `.sln` files for explicit
  references to runtime/SDK versions (e.g. `<PlatformToolset>v120</...>`
  → MSVC Runtime 2013) that cdxgen doesn't surface as components."
- Ground the model with the reference's gocator section as an example of
  what a good final SBOM looks like (truncated; show 5-7 entries).

### 2.5 Worker integration

`worker.ts` Step 3.5 (between cdxgen and OSV):

```ts
const augmented = await runSbomAugmentation({
  scanRunId,
  scopeDir,
  scopePath,
  cdxgenOutput: cleanedComponents,        // post-Stage-1
  firstPartyNamespaces: repo.firstPartyNamespaces ?? [],
  vendoredDirs: repo.vendoredDirs ?? ["extern/", "third-party/", "vendor/"],
  tokenBudget: 200_000,
  effort: repo.llmSbomEffort,
  log,
});

// apply augmented to components: drop, keep, add
const finalComponents = applySbomAugmentation(cleanedComponents, augmented);
```

Then `persistComponents(finalComponents, ...)` writes the final list.

OSV / EOL / SCA hint set / LLM detection all flow from the augmented list.

### 2.6 Cost + duration estimate

Detection phase on the `/` scan today: ~15 min, ~$13 LLM. Augmentation is
strictly cheaper because it doesn't have to find vulnerabilities — just
classify components and add a few vendored libs. Estimate ~5–8 min and
~$3–5 per scope. The Stage 1 work is essentially free.

### 2.7 Verification

After Stage 2 lands, run a scan on Gocator Classic and check:

1. `/` scope produces ~18–22 components matching the reference's
   section 1.2 (vendored gocator C/C++).
2. The 3 cdxgen-missed items (MSVC Runtime, gettext, IpToCountry) are
   present as `add` records with sensible `evidence_path` values.
3. CefSharp is present as a `keep` record with a one-line LLM rationale
   confirming it's used by `GoEmulate/`.
4. `/GoWeb` scope produces ~30–40 components: the NPM runtime deps from
   section 1.6 + vendored JS from section 1.5. The 2,174 npm dev-only
   components stay excluded by the existing M6n dev filter.
5. Spot-check 5 LMI internal packages (GoSdkNet, kApiNet, …) are dropped
   with the reason `first-party`.

## Out of scope

- **A pure LLM-from-scratch SBOM pipeline.** The CefSharp finding shows
  why cdxgen's seed is load-bearing — the LLM didn't know to look at
  `GoEmulate/`. Hybrid is the right model.
- **License-detection augmentation.** cdxgen does some license detection
  but it's noisy; out of scope for this iteration. The reference reports
  licenses but they're not used downstream in SASTBot today.
- **Cross-repo SBOM merging.** The reference is across 3 repos
  (gocator/ve/fss). SASTBot scans one repo per scope. A "consolidated SBOM
  across repos" view is a separate UX feature.
- **Existing-scan backfill.** Stage 2 needs the source tree to inspect,
  which we may not have for old scans (clones get cleaned up). New scans
  get the augmentation; old data stays as-is. (Mention the cdxgen output
  in `scan_runs.sbom_cdxgen_raw` is available for re-processing if a user
  insists on backfilling — but it's not a default.)

## "Done" looks like

- A fresh `Scan now` on Gocator Classic `/` produces a `sbom_components` row
  count between 17 and 22, with the reference's section 1.2 components
  present.
- Each `add` record has `llm_evidence` populated so the Components tab can
  show a tooltip explaining why the component is there.
- `/GoWeb` produces 30–40 runtime components, dev-only count stays at
  ~2,174 (M6n filter unchanged), and vendored jQuery 1.11/CodeMirror/etc.
  are present.
- No regression in scan duration: total wall-clock for `/` stays under
  20 min on Opus.
- Stage 1's tests are green and cover the seven rules.

## Order of operations

1. Stage 1 (~half day): post-processing function + tests + re-scan to
   confirm cleanup math.
2. Stage 2 (~1–2 days): service + prompts + worker integration + repo
   fields + UI affordance for the LLM evidence tooltip + re-scan to
   confirm reference parity.
3. Document the new pipeline in CLAUDE.md alongside the existing M6
   notes — there are operator-visible knobs (FIRST_PARTY_NAMESPACES,
   VENDORED_DIRS) that need write-up.
