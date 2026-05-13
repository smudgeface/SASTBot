# Scan lifecycle

How a single SASTBot scan runs, what each phase does, and what it
typically costs. Use this to plan capacity, set per-repo budgets, and
extrapolate cost to your own repos.

A scan is one BullMQ job **per `ScanScope`** — a repo with two scan
paths (e.g. `/` and `/GoWeb`) produces two independent runs. Both run
serially on a single worker; the data below is per-scope.

## Phase sequence

The enum lives in `backend/src/schemas.ts` and is mirrored in the UI as
`SCAN_PHASE_LABELS`. The worker calls `setPhase(scanRunId, phase, progress?)`
at each boundary; the UI polls `scan_runs.current_phase` every 3s while
any scope has an active scan.

| # | Phase (`current_phase`) | What runs | Typical duration | LLM cost |
|---|---|---|---|---|
| 1 | `cloning` | Shallow `git clone` (or `git fetch` on cached clone). | 10–60s LAN, 1–10m cold WAN | – |
| 2 | `cdxgen` | `cdxgen` against the scope dir; emits CycloneDX 1.7. | 20s–2m | – |
| 3 | `llm_sbom` | **Stage 1** mechanical post-processing (`postProcessComponents`, 6 rules) cleans cdxgen noise (placeholder versions, cmake internals, .NET BCL assemblies, test frameworks, versionless duplicates, alias normalization). **Stage 2** `claude -p` augmentation reads the Stage-1-cleaned SBOM, drops first-party / build-only / .NET BCL entries, adds vendored libs cdxgen missed, attaches rationale evidence. | 1–10m | $0.50–$2.50 |
| 4 | `osv` | Batched OSV.dev queries per component. Dev-only npm components are skipped when `reachabilityIncludeDevDeps=false`. | 5–30s | – |
| 5 | `eol` | endoflife.date enrichment for runtimes (Node, Python, .NET). | <5s | – |
| 6 | `llm_detection` | `claude -p` SAST agent reads source, emits `sast` (per-location), `sast_absence` (cross-cutting), and `reachability` records for OSV findings. | 5–20m | $5–$16 |
| 7 | `llm_recheck` | `claude -p` re-verifies any issue that the detection pass didn't re-emit, to confirm it's fixed (vs. just dropped from the LLM's attention). | 1–3m | $0.50–$1.50 |
| 8 | `sca_summaries` | One short `claude -p` summary per high+critical SCA issue (cached after first generation). | seconds to minutes | small |
| 9 | `finalizing` | SARIF v2.1.0 generation, severity rollup, scope `lastScanRunId` advance (gated on no error-warnings), dev-tree policy suppression on dev-only SCA issues. | <2s | – |

A "trustworthy" scan has no `error`-severity warnings in
`scan_runs.warnings`. The SCA auto-fix sweep and the `lastScanRunId`
advance are both gated on trustworthiness — degraded scans never mark
issues as "fixed."

## Cost & performance — empirical baselines

The numbers below come from four full scans of the Gocator Classic
repo across the M6p shakedown (May 2026). Per scan there are two
scopes: a small C++/C# root (`/`) and a large npm-heavy frontend
(`/GoWeb`). Each row is one scan run; "Total" includes only the three
LLM phases (other phases are sub-cent).

### Scope `/` — small C++/C# scope

Sizing context: cdxgen produces ~45 raw components; Stage 1 reduces to
~19. Mostly nuget references plus `extern/` vendored libraries. Native
C++ source weighted heavily.

| Run | SBOM augmentation | SAST detection | SAST recheck | Total LLM |
|---|---|---|---|---|
| 1 (baseline) | 195s / $1.17 / 25 req | 17.7m / $15.80 / 226 req | 76s / $0.79 / 22 req | **$17.76** |
| 2 (no `vendored_lib` in SAST) | 116s / $0.92 / 21 req | 9.0m / $5.52 / 126 req | 86s / $0.99 / 30 req | **$7.43** |
| 3 (silence-means-keep + heuristic dirs) | 192s / $1.25 / 33 req | 13.7m / $11.19 / 208 req | 114s / $1.05 / 37 req | **$13.49** |
| 4 (manifest guardrail + bundle files) | 151s / $0.98 / 21 req | 14.0m / $11.10 / 191 req | 114s / $1.08 / 39 req | **$13.16** |

Issues found (C/H/M/L): 10/42/16/4 → 10/45/22/5 → 13/47/24/4 → 13/51/24/6.
All four runs marked `untrustworthy=false`.

### Scope `/GoWeb` — large npm-heavy scope

Sizing context: cdxgen produces 2,435 raw components; after the
`reachabilityIncludeDevDeps=false` filter, ~258 ship at runtime. Most
of the manifest tree is well-typed React / build tooling.

| Run | SBOM augmentation | SAST detection | SAST recheck | Total LLM |
|---|---|---|---|---|
| 1 (baseline) | 4.1m / $1.71 / 62 req | 11.3m / $7.18 / 151 req | 52s / $0.54 / 18 req | **$9.43** |
| 2 (no `vendored_lib` in SAST) | 9.8m / $2.21 / 33 req | 10.9m / $7.34 / 156 req | 61s / $0.63 / 25 req | **$10.18** |
| 3 (silence-means-keep + heuristic dirs) | 2.2m / $0.91 / 31 req | 9.5m / $6.76 / 135 req | 76s / $0.66 / 27 req | **$8.33** |
| 4 (manifest guardrail + bundle files) | 83s / $0.58 / 28 req | 10.7m / $7.59 / 164 req | 96s / $0.83 / 32 req | **$9.00** |

Issues found (C/H/M/L): 2/27/141/10 → 2/31/141/11 → 2/32/147/14 → 3/31/139/14.

### Headline observations

- **Detection is the dominant cost** (60–95% of total LLM spend) and is
  also the most variable run-to-run. Detection cost is driven by the
  agent's search depth, which scales with code surface area more than
  raw line count — repos with many small source files cost more than
  equivalent-sized repos with a few large files.
- **SBOM augmentation cost is small and bounded** (typically <$2.50/scope)
  even for large npm trees, because the input is structured data the
  LLM can read once rather than searching through arbitrary source.
- **Recheck is cheap and consistent** (~$0.50–$1.50/scope) because it
  only re-verifies a small carry-over set.
- **The large npm scope is *cheaper* than the small C++ scope** for
  detection. Counter-intuitive but consistent across all 4 runs — npm
  code is short, well-typed, and the agent recognizes it quickly. The
  small C++ scope has fewer but more involved files and the agent reads
  more of each one.

## Sizing your own repos

Rough budget guidance for planning. All figures assume `xhigh`
detection effort (the default on Opus 4.7) and `medium` recheck +
SBOM-augmentation effort.

| Repo profile | SBOM components (post-augmentation) | Per-scan LLM cost | Wall clock |
|---|---|---|---|
| Small native (C/C++/C#, ~10–100 KLOC) | 20–40 | $10–$20 | 25–35m |
| Large managed (npm, Maven, .NET) | 200–500 runtime / 1k–5k raw | $8–$15 | 12–20m |
| Mixed monorepo with 3+ scopes | (per-scope, additive) | sum of above | sum of above |

### Cost levers

- **`Repo.llmSastEffort`** — `low | medium | high | xhigh | max`. Default
  `xhigh`. Dropping to `high` saves ~30%; `medium` saves ~50–60%. Lower
  effort → fewer detection records → lower recall.
- **`Repo.llmRecheckEffort`** — default `medium`. Recheck is bounded and
  narrow; rarely worth tuning.
- **`Repo.llmSbomEffort`** — default `medium`. Same logic: SBOM
  augmentation is bounded and `medium` is sufficient.
- **`xhigh` is Opus-only.** Sonnet silently degrades it to its own
  default, which is `high` on Sonnet 4.6. Changing models without
  reviewing per-repo effort settings silently lowers fidelity. The
  `claude -p --effort` flag is passed explicitly by `spawnClaudeAndStream`
  so the product default never silently changes the scan profile.
- **`reachabilityEnabled`** (per repo, default true) gates the reachability
  half of the detection prompt. Disabling drops detection cost ~10–20%
  for large dependency trees with many CVEs.
- **`reachabilityIncludeDevDeps`** (default false) excludes npm `dev: true`
  components from OSV queries, the UI, and the LLM hint set. Keeping it
  false saves API calls (no OSV query against the dev tree) and avoids
  noise on dev-only CVEs.

## Where results land

| Output | Storage | Consumer |
|---|---|---|
| Raw cdxgen SBOM (CycloneDX 1.7) | `scan_runs.sbom_json` (JSONB) | Auditable raw source; LLM SBOM augmentation reads this; served at `GET /scans/:id/sbom` as the per-scan audit trail |
| Curated CycloneDX 1.7 SBOM | Built on demand from `sbom_components` by `sbomCurated.ts` | Served at `GET /api/scopes/:id/sbom-json` as the operator-facing artifact (matches the Components tab; CRA-ready) |
| Post-augmentation component list | `sbom_components` rows (one per scan run) | Components tab + OSV queries + curated-SBOM builder |
| LLM augmentation evidence | `sbom_components.llm_evidence` (JSONB `{path, excerpt, llmReason}`) | Tooltip rationale on Components tab |
| Discovery method tag | `sbom_components.discovery_method` (`manifest \| llm_augmentation`) | Filtering + provenance audit |
| `is_dev_only` flag | `sbom_components.is_dev_only` (npm `dev: true` marker from cdxgen 12.2+) | Dev-tool filter on Components & SCA tabs |
| SAST findings | `sast_issues` rows (deduped via fingerprint hash of the match line) | SAST tab |
| SAST recheck verdicts | `sast_issues.dismissed_status` + `dismissed_reason` columns | SAST tab |
| OSV / CVE findings | `sca_issues` rows | SCA tab |
| Reachability assessment | `sca_issues.reachable_*` columns | SCA tab + auto-fix gating |
| SARIF v2.1.0 | `scan_runs.sast_sarif` (JSONB) | `GET /scans/:id/sast-sarif` |
| Phase progress | `scan_runs.current_phase` + `phase_progress` (JSONB) | Live status banner, scopes-list "Last Scan" cell |
| Warnings | `scan_runs.warnings` (JSONB array of `{code, severity, message}`) | Trustworthiness gate (`hasErrorWarnings`); drives the "this scan may be incomplete" UI |
| Per-LLM-pass cost & token usage | Worker stdout logs (Pino JSON) | Operational dashboards; not yet persisted |

## Failure modes & recovery

| Code | Severity | What happens | Recovery |
|---|---|---|---|
| `cdxgen_failed` | error | Worker emits warning; downstream phases skip; scan marked untrustworthy. | Inspect cdxgen output in worker logs; re-run after fixing the manifest. |
| `cdxgen_zero_components` | info | Scan completes but with zero components; flagged if a previous run had > 0. | Verify the scope directory has a manifest at the expected path. |
| `llm_sbom_augmentation_failed` | error | Worker falls back to Stage-1-cleaned components; scan still completes; marked untrustworthy. | Inspect `claude -p` exit and stderr in logs; re-run scan. |
| `llm_sbom_parse_errors` | info | Some augmentation records were unparseable; partial results applied. | Usually self-clears; if persistent, inspect tmp record stream. |
| `llm_sast_detection_failed` | error | No SAST findings persisted; scan marked untrustworthy. | Inspect `claude -p` exit; re-run scan. |
| `scope_path_missing` | error | Pre-flight detected the configured scope path doesn't exist in the clone. Scan aborts before cdxgen. | Edit the repo in Admin → Repos; set Scan paths to a directory that actually exists at the repo root. |
| `remote_unreachable` | error | `git ls-remote` / `git clone` couldn't reach the remote (VPN drop, DNS, firewall). | Reconnect network, re-trigger. |
| `branch_not_found` | error | Default branch on the repo doesn't exist on the remote. | Edit the repo's Default branch (common LMI case: change `main` → `master`). |
| `auth_failed` | error | Git auth rejected by the remote. | Verify the credential in Admin → Credentials. |
| `clone_failed` | error | Any other `git clone` failure. | Inspect the error message; usually network or filesystem related. |

Worker boot also runs idempotent backfills for any new column added in
recent milestones — `backfillLlmSummaries`, `backfillCvssScores`,
`backfillReachability`, `backfillManifestOrigin`,
`backfillDevOnlyScaIssues`, `backfillSastSarif`, `backfillSastSnippets`.
Adding a new column that must be populated for pre-existing rows? Mirror
this pattern instead of forcing operators to re-scan.
