# Next-session handoff — Component (SBOM) accuracy

(Disposable. Delete this file when the work it describes ships, or stash
it under a milestone name in `docs/` if it grows into a real plan.)

---

## Goal

The SASTBot Components tab is showing **2,481 components** across the two
Gocator Classic scopes (`/` = 45, `/GoWeb` = 2,436). At first glance this
is an order of magnitude too many for what would be a useful CRA-compliance
SBOM. We have a hand-curated reference for comparison and want to figure
out what's wrong, what's right, and what to do about it.

## Reference materials (already on disk)

A previous experiment had Claude Code produce a CRA-compliance analysis
over the full Gocator Classic codebase (multiple repos including the
`/GoWeb` frontend). All three artifacts live under
`docs/Claude CRA Analysis Reference/`:

| File | What it is |
|---|---|
| `CRA Analysis Prompt.md` | The prompt that drove the reference run — declares the CRA framing, asks for "third-party libraries" with exact versions, calls out vendored code as a hard requirement |
| `CRA_Compliance_Report.md` | The narrative compliance report (what the reference Claude found / recommends) |
| `SBOM_CycloneDX.json` | The CycloneDX 1.5 SBOM the reference produced — **41 components total** |

**Read these first.** They are the "what good looks like" anchor.

## The contrast in numbers

| Source | Scope | # components |
|---|---|---|
| Reference (Claude Code, manual) | full Gocator Classic incl. /GoWeb (+ ve, fss repos) | **41** |
| SASTBot (cdxgen) | Gocator Classic `/` scope alone | 45 |
| SASTBot (cdxgen) | Gocator Classic `/GoWeb` scope alone | **2,436** |
| SASTBot total across both scopes | 2,481 |

So SASTBot for `/GoWeb` is producing ~60× the reference's total. The
ecosystem breakdown for the full set:

| Ecosystem | Count |
|---|---|
| npm | 2,436 |
| nuget | 33 |
| (none) | 27 |
| generic | 11 |
| maven | 1 |

Almost all of the bloat is npm. Spot-check the reference's first three
components: `jQuery@1.11.0`, `jQuery UI@1.8.0`, `google-closure-library@20151015.0.0`
— these are the runtime libraries actually shipped with the firmware UI,
not the developer's build-tool tree.

## Hypothesis going in (validate before acting)

cdxgen reads `package-lock.json` and emits **every** entry as a component
— direct + transitive + devDependencies + transitive of devDependencies.
For a project like /GoWeb that's webpack + babel + jest + @types/* + all
of their dependency trees, that fans out to 2,000+ entries. None of the
build-tooling tree ships with the product, so none of it is CRA-relevant.

CLAUDE.md already has notes about cdxgen 12.2's npm `dev: true` marker
(M6h), and the existing `Repo.reachabilityIncludeDevDeps` flag uses it
to filter the LLM hint set. **But that flag does NOT filter the
`sbom_components` rows themselves** — every component gets persisted, and
the Components tab shows them all. So even with `reachabilityIncludeDevDeps
= false`, the user still sees the bloated list on the Components tab.

Things worth understanding before deciding on a fix:

1. **What does cdxgen consider "required" vs "optional" vs "excluded"?**
   CLAUDE.md says cdxgen lumps both true devDeps AND transitive runtime
   deps under `scope: optional` — that's not a clean dev/runtime signal
   on its own. The 12.2+ `dev: true` lockfile marker IS a clean signal
   for npm, but only npm.
2. **Does cdxgen have a "runtime only" mode?** Check `cdxgen --help`
   for flags like `--required-only`, `--no-include-formulation`, or
   similar. If yes, we might just need to set it.
3. **What's in the 27 "(none)" ecosystem rows?** Probably vendored
   libs the LLM detected (`vendored_lib` records) — those should be
   real and CRA-relevant.
4. **What's actually in the 2,436 npm components?** Pull a sample and
   see the dev/runtime split; cross-reference against the reference's
   JS/UI components to see which of the 41 reference items SASTBot
   covers and which ones it missed entirely. (A risk: even with all
   the bloat, SASTBot might MISS reference items that don't have a
   package-lock entry — vendored code, copied JS files, etc.)

## What "good" looks like

A reasonable end state has SASTBot producing a CRA-grade SBOM that:

- Lists everything that **ships in the product** (firmware + static
  assets + bundled JS).
- **Skips** the developer's build-tool dependency tree (webpack, babel,
  jest, @types/*, lint config, and all of their transitives).
- **Includes** vendored / checked-in copies of upstream code (LLM
  `vendored_lib` records already cover this).
- Probably ends up in the same order of magnitude as the reference (~40
  components for Gocator Classic), give or take real differences in
  what each pass found.

How to get there is the open question. Options to weigh:

A. **Filter at display time only** (cheap, reversible): keep cdxgen's
   full output in `sbom_components` but filter the Components tab to
   `is_dev_only = false`. Pro: no data loss, can iterate on the filter.
   Con: SCA queries against OSV are still hitting the full set, so the
   detection-pass cost is unchanged.
B. **Filter at SBOM-generation time** (deeper but cleaner): pass the
   right cdxgen flags so the SBOM only includes runtime components in
   the first place. Pro: SCA + LLM hints both shrink. Con: harder to
   recover from if cdxgen's filter is too aggressive — you can't show
   the user "here's what we excluded" without re-running.
C. **Hybrid**: emit everything, mark the dev/build subset, default the
   UI + SCA + LLM hints to "runtime only" with a toggle to show all.
   Most flexible, most code.

The hand-curated reference is also worth treating as a yardstick, not
gospel — it might miss things SASTBot legitimately catches. The point
is to understand WHY each side reports what it does, then make a
deliberate call.

## Where the relevant code lives

- `backend/src/services/sbomService.ts` — cdxgen invocation. Look for
  the args list and any flag candidates. Scope-relative paths and
  exclusions are also computed here.
- `backend/src/worker.ts` — calls `runCdxgen`, persists components
  via `persistComponents`. The `Repo.reachabilityIncludeDevDeps` flag
  affects only the LLM hint set built later, not what gets persisted.
- `backend/prisma/schema.prisma` — `SbomComponent` table; note
  `isDevOnly` (npm dev marker), `scope` (raw cdxgen scope), `manifestFile`
  (provenance).
- `frontend/src/components/ComponentsTab.tsx` (or wherever Components
  renders) — display filter would land here for option A.

## Starting queries

```bash
# Sample of the npm bloat — which packages are "everywhere"?
docker compose -f docker/compose/docker-compose.yml --env-file .env exec -T postgres psql -U sastbot -d sastbot -c "
  SELECT name, COUNT(*) AS rows, BOOL_OR(is_dev_only) AS any_dev, BOOL_AND(is_dev_only) AS all_dev
  FROM sbom_components
  WHERE scan_run_id = (SELECT last_scan_run_id FROM scan_scopes WHERE path = '/GoWeb' AND repo_id = (SELECT id FROM repos WHERE name = 'Gocator Classic'))
    AND ecosystem = 'npm'
  GROUP BY name
  ORDER BY rows DESC LIMIT 30;
"
```

```bash
# Dev / runtime / unknown split
docker compose -f docker/compose/docker-compose.yml --env-file .env exec -T postgres psql -U sastbot -d sastbot -c "
  SELECT
    is_dev_only,
    scope,
    COUNT(*) AS components
  FROM sbom_components
  WHERE scan_run_id IN (
    SELECT last_scan_run_id FROM scan_scopes
    WHERE repo_id = (SELECT id FROM repos WHERE name = 'Gocator Classic')
  )
  GROUP BY 1, 2
  ORDER BY 3 DESC;
"
```

```bash
# Check cdxgen flags currently in use
grep -n 'cdxgen' backend/src/services/sbomService.ts | head -20
```

## What good outcome looks like for this milestone

- A short, written-down explanation of why the SASTBot count is what it
  is (e.g. "cdxgen reads all of package-lock.json including devDeps;
  the dev marker only catches ~80% of them per cdxgen issue #3927").
- A decision on which of A/B/C above to ship, with the why captured.
- Either a config knob (per-repo: "include dev/build deps in SBOM:
  yes / no / show-but-mark") or a filter implementation, or — if the
  decision is to leave it — a written justification.
- An optional `Repo.maxScaHints` (top-N by CVSS) follow-up if hint
  volume becomes a separate concern.

## Existing context

Read `CLAUDE.md` for the conventions; especially the M6h note (cdxgen
12.2 dev marker), the M6m note (per-repo effort), and the canonical-
package-name note (group prefix handling). Read the most recent few
entries in `docs/PROGRESS.md` for the SAST/SCA architecture.

The local instance at `http://localhost:5173` (or
`http://<mac-ethernet-ip>:5173` from another LAN machine) has the
recent Opus-4.7 scan results loaded, login `admin@sastbot.local` /
`admin`. Gocator Classic root: `e5a77515-f7bc-4a6b-b355-b7fcac6610cc`.
GoWeb scope: `34035670-c766-4727-81f3-9290337abd76`. Repo cache on
disk: `/app/clones/796ea61d-e475-4d34-8b10-fd6fc5398266/`.
