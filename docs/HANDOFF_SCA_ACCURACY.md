# Next-session handoff — SCA accuracy investigation

(Disposable. Delete this file when the work it describes ships, or stash it
under a milestone name in `docs/` if it grows into a real plan.)

---

## Goal

Verify that SCA findings in SASTBot are accurate. Specifically:

1. **Is the version cdxgen reports the version actually in use?**
2. **Is the OSV match for that version actually a vulnerability?** (Or have
   we matched against a too-broad affected range that includes versions
   where the issue is already fixed?)

## Concrete starting case

Gocator Classic root scope (`scope_id =
e5a77515-f7bc-4a6b-b355-b7fcac6610cc`) shows two medium-severity issues
for `System.Net.Http@4.3.4`. Manual inspection of the `.csproj` doesn't
make it obvious why cdxgen settled on `4.3.4`. And the cited CVE on
`https://nvd.nist.gov/...` looks like it was fixed in `4.3.4` itself —
suggesting the OSV affected-range data may include versions where the
issue is no longer present, or our match is mishandling the range.

This is one example, but the underlying questions are general — the
answer applies to every SCA finding SASTBot produces.

## First-look queries

Pull the actual data for the System.Net.Http findings:

```bash
docker compose -f docker/compose/docker-compose.yml --env-file .env exec postgres psql -U sastbot -d sastbot -c "
  SELECT id, package_name, latest_package_version, osv_id, latest_cve_id, latest_severity,
         latest_summary, latest_manifest_file
  FROM sca_issues
  WHERE scope_id = 'e5a77515-f7bc-4a6b-b355-b7fcac6610cc'
    AND package_name = 'System.Net.Http'
    AND dismissed_status NOT IN ('fixed', 'suppressed', 'false_positive');
"
```

Then for each `osv_id` returned, pull the raw OSV advisory and look at
its `affected[].versions` / `affected[].ranges` data. Either query
osv.dev directly:

```
curl -s https://api.osv.dev/v1/vulns/<osv_id> | jq '.affected[] | {package: .package, ranges: .ranges, versions: .versions}'
```

…or look at what we persisted on `scan_findings.detail_json` for that
finding (we store the raw OSV record alongside the row).

Compare that to the actual `System.Net.Http` NuGet metadata at
https://www.nuget.org/packages/System.Net.Http/4.3.4 — does its release
notes / git log show the CVE was fixed in 4.3.4?

## Where the relevant code lives

- `backend/src/services/sbomService.ts` — cdxgen invocation + version
  extraction. `extractEcosystem` / `canonicalPackageName`. NuGet handling
  is light here; cdxgen does the heavy lifting.
- `backend/src/services/osvService.ts` — OSV query (`queryAndPersistFindings`),
  range matching, finding persistence. **The version-vs-range comparison
  logic is here.** This is the most likely place for a bug.
- `backend/src/services/cvss4.ts` — CVSS v4.0 score derivation; not relevant
  unless the medium severity itself looks wrong.
- `backend/prisma/schema.prisma` — `sca_issues` (deduplicated) and
  `scan_findings` (per-scan, includes `detail_json` with the raw OSV).

The cdxgen output for the scan is stored on `scan_runs.sbom_json` (CycloneDX
JSON). Pull it via `GET /scans/:id/sbom` to see exactly how cdxgen
described `System.Net.Http` — purl, version, evidence, and which manifest
it derived from. That will tell us what cdxgen *thinks* the version is and
why.

## What a good outcome looks like

- A clear answer to "where did 4.3.4 come from" for this specific case
  (which manifest, which resolution rule).
- A clear answer to "does CVE-X actually affect 4.3.4" (read OSV's
  `affected[].ranges` carefully — the introduced/fixed/last-affected
  semantics matter).
- If our match logic is the bug, a fix to `osvService.ts` with a regression
  test using a real OSV record.
- If the LLM-suggested manifest version is wrong on the .csproj side, a
  note about NuGet PackageReference vs `packages.config` resolution and
  whether cdxgen's version is the *resolved* version vs the *requested*
  version.

## Background you may need

- **NuGet version semantics on .csproj**: `<PackageReference Version="4.3.0">`
  is a *minimum*; the actual resolved version depends on the lockfile
  (packages.lock.json) or transitive constraints. Without a lockfile,
  the resolver picks the lowest version satisfying all constraints. cdxgen
  may report either depending on what it can see.
- **OSV affected ranges**: each `ranges[]` entry has `events` like
  `[{introduced: "4.3.0"}, {fixed: "4.3.4"}]`. A version `4.3.4` is NOT
  in the affected range — `fixed` is exclusive (i.e. 4.3.4 is the first
  unaffected version). If our matcher treats `fixed` as inclusive, that's
  the bug.
- **CVE vs OSV ID**: a single CVE can map to multiple OSV records (one per
  ecosystem). The CVE summary on NVD might say "fixed in 4.3.4" but the
  OSV record we ingested might be for a different ecosystem with different
  version semantics.

## Existing context

Read `CLAUDE.md` for the conventions; read the most recent few entries in
`docs/PROGRESS.md` (especially M6 onward) for the SAST/SCA architecture.
Memory has the pending-features list and a note about deployment targets.

The `BOOTSTRAP_ADMIN_PASSWORD` env var is set in `.env` to `admin`; you can
log in to the local instance at `http://localhost:5173` (or
`http://<mac-ethernet-ip>:5173` from another LAN machine) as
`admin@sastbot.local` / `admin`. The Gocator Classic root scope
(`e5a77515-f7bc-4a6b-b355-b7fcac6610cc`) has the example issues. Repo cache
on disk: `/app/clones/796ea61d-e475-4d34-8b10-fd6fc5398266/`.
