# SBOM Component Recheck — plan

> **Status:** Plan only. Not implemented.
> **Date:** 2026-05-13
> **Motivating incident:** FSS demo-prep scan (2026-05-13) — same repo,
> same cached clone, three consecutive runs produced 21 → 8 → 22
> components. The LLM SBOM augmentation pass is non-deterministic
> enough that "did we miss it?" vs "is it actually gone?" can't be
> resolved from a single scan.

This doc plans the SBOM component recheck feature. It's structurally
analogous to the existing SAST recheck phase but operates on
**scope-level component state** rather than per-scan output.

## Why this isn't just a new phase

The user observation that triggered this plan: *the previous scan
isn't the right reference point — the database is*. Issues
(`sast_issues`, `sca_issues`) are scope-level: every scan contributes
evidence to a cumulative, durable record. Components today are
**not** — `sbom_components.scan_run_id` makes each row a snapshot of
one scan's output.

That mismatch is the root cause. Component-recheck on top of the
per-scan model would be "re-run augmentation against a memory of
prior augmentation runs" — already non-deterministic upstream of
itself. Lifting components to scope-level state makes "the truth set"
a real thing the recheck can compare against, and unblocks several
adjacent features (manual additions, removal audit, persistent
component metadata).

So the plan has two halves:

1. **Architectural** — promote components to scope-level state, mirroring
   issues. Per-scan-run becomes a join table ("seen in this run"),
   not a primary container.
2. **Functional** — new `llm_sbom_recheck` phase that uses the
   scope-level state as the truth set, with a two-tier check (free
   file-existence pre-check, LLM fallback for ambiguous cases).

## Architectural shift: components as scope-level state

### Current model

```
sbom_components (scan_run_id, name, version, purl, ecosystem, cpe, ...)
  └── FK scanRunId → scan_runs.id
```

Every scan creates a fresh row set. The Components tab queries by
`WHERE scan_run_id = <latest successful for this scope>`. Older rows
are orphans (kept for audit-trail but never queried).

### Proposed model

```
scope_components (id, scope_id, name, version, ...)
  ├── firstSeenScanRunId  → first scan that surfaced it
  ├── lastSeenScanRunId   → most recent confirming scan
  ├── lastSeenAt          → timestamp
  ├── dismissedStatus     → "active" | "removed" | "manual_override"
  ├── dismissedReason     → "no_evidence" | "llm_confirmed_removed" | operator note
  ├── dismissedAt
  ├── source              → "scan" | "manual"
  └── ... (cpe, purl, llm_evidence, etc. — same columns as today)

scan_run_components (scan_run_id, scope_component_id)
  (join table — "this component was seen in this scan run")
```

The Components tab queries `scope_components WHERE scope_id = ? AND
dismissed_status = 'active'`. Audit drill-down into a specific scan
joins via `scan_run_components`.

**Migration**: backfill from existing `sbom_components`. For each
scope, take the most recent successful scan_run's components and
promote them to `scope_components` with `firstSeenScanRunId = lastSeenScanRunId`
= that scan id, `dismissedStatus = 'active'`. Older per-scan rows
stay in `sbom_components` until the schema fully cuts over, then
either get archived or migrated lazily to the join table.

### Why this shape

- Mirrors the proven `sast_issues` / `sca_issues` model. `firstSeenScanRunId`
  / `dismissedStatus` exist there for the same reason: scans contribute
  evidence, the row is the durable truth.
- Manual addition / maintenance becomes a non-event — the operator
  writes a `scope_components` row with `source = 'manual'` and it
  works the same as a scan-discovered one.
- Removal becomes auditable: the row stays in the DB with
  `dismissedStatus = 'removed'`, you can see when and why.
- Cross-scan trend reporting ("component was first seen 2026-03-04,
  last seen yesterday, still present") falls out for free.

## The new phase: `llm_sbom_recheck`

### Position

Between `llm_sbom` and `osv`:

```
... → llm_sbom → llm_sbom_recheck → osv → nvd → eol → llm_detection → ...
```

Why before OSV: a component recovered by the recheck needs to be
queried for vulnerabilities **this run**, not next run. The current
`llm_sbom` output and the recheck's recovered set together form the
"active components" snapshot the OSV / NVD / detection passes
operate on.

### Inputs

- `scope_components` rows for this scope where `dismissedStatus = 'active'`
  (the truth set)
- The component IDs surfaced by this run's `llm_sbom` augmentation
- The clone directory (filesystem accessible for evidence-path checks)

### Algorithm

For each `scope_component` in the truth set NOT surfaced by this
run's augmentation:

**Tier 1 — file existence check (free, fast):**

- If the row has an `evidence_path` (typical for LLM-added components):
  - `fs.exists(<scope_clone>/<evidence_path>)` returns false → component
    is **really** removed. Mark `dismissedStatus = 'removed'`,
    `dismissedReason = 'no_evidence'`, advance `dismissedAt`.
  - Returns true → file still there. Fall through to Tier 2.
- If the row has NO evidence path (came from cdxgen manifest discovery,
  pre-evidence-tracking, or manual addition):
  - Fall straight through to Tier 2.

**Tier 2 — focused LLM recheck:**

- Cost-bounded `claude -p` call, similar shape to SAST recheck.
- Prompt: "Component `<name>@<version>` was previously identified as
  vendored at `<evidence_path>`. The current SBOM augmentation didn't
  surface it. Inspect the codebase and confirm: is this component
  still vendored / used, or is it actually gone?"
- LLM emits one of:
  - `{verdict: "present", new_evidence_path: <optional>, rationale: "..."}` →
    carry forward. Update `lastSeenScanRunId`, add to this run's
    `scan_run_components` join, keep `dismissedStatus = 'active'`.
  - `{verdict: "removed", rationale: "..."}` → mark
    `dismissedStatus = 'removed'`, `dismissedReason = 'llm_confirmed_removed'`.

### Per-phase budget

- Tier 1 is filesystem stat calls — sub-millisecond per component.
- Tier 2 is one LLM call per ambiguous component. Typical scope has
  ≤5 components/run drift, so worst-case ~5 LLM calls at `medium`
  effort each ≈ $1–$2.
- New repo config: `Repo.llmSbomRecheckEffort` (default `medium`).
- Token budget: 50,000 (mirrors SAST recheck).

### Cost gating

The phase only fires if there's any candidate. A perfectly stable
scope where every previously-known component re-appears costs
zero LLM time — Tier 1 still runs but it's just filesystem stats.

## Schema changes (sketch)

New tables:

```prisma
model ScopeComponent {
  id              String   @id @default(uuid()) @db.Uuid
  scopeId         String   @map("scope_id") @db.Uuid
  orgId           String?  @map("org_id") @db.Uuid

  name            String
  version         String?
  purl            String
  ecosystem       String?
  licenses        String[]
  componentType   String   @default("library") @map("component_type")
  scope           String?
  isDevOnly       Boolean  @default(false) @map("is_dev_only")
  manifestFile    String?  @map("manifest_file")
  discoveryMethod String?  @default("manifest") @map("discovery_method")
  evidenceLine    Int?     @map("evidence_line")
  evidencePath    String?  @map("evidence_path")  // new — was implicit in llmEvidence
  llmEvidence     Json?    @map("llm_evidence")
  cpe             String?  @map("cpe")

  source          String   @default("scan")  // "scan" | "manual"
  dismissedStatus String   @default("active") @map("dismissed_status")
                                              // "active" | "removed" | "manual_override"
  dismissedReason String?  @map("dismissed_reason")
  dismissedAt     DateTime? @map("dismissed_at")

  firstSeenScanRunId String?   @map("first_seen_scan_run_id") @db.Uuid
  lastSeenScanRunId  String?   @map("last_seen_scan_run_id") @db.Uuid
  lastSeenAt         DateTime? @map("last_seen_at")

  createdAt       DateTime @default(now()) @map("created_at")
  updatedAt       DateTime @updatedAt @map("updated_at")

  scope_           ScanScope @relation(fields: [scopeId], references: [id], onDelete: Cascade)
  scanRunLinks     ScanRunComponent[]

  @@unique([scopeId, name, version, purl])  // dedup key — same as sbom_components effective
  @@index([scopeId, dismissedStatus])
  @@map("scope_components")
}

model ScanRunComponent {
  scanRunId        String @map("scan_run_id") @db.Uuid
  scopeComponentId String @map("scope_component_id") @db.Uuid
  discoveryMethod  String @map("discovery_method")  // "manifest" | "llm_augmentation" | "recheck_recovery"

  scanRun        ScanRun        @relation(fields: [scanRunId], references: [id], onDelete: Cascade)
  scopeComponent ScopeComponent @relation(fields: [scopeComponentId], references: [id], onDelete: Cascade)

  @@id([scanRunId, scopeComponentId])
  @@map("scan_run_components")
}
```

The existing `sbom_components` stays for one milestone as the audit
trail backing the curated-SBOM builder (`sbomCurated.ts`); curated
SBOM eventually switches to read from `scope_components`. After the
cut-over `sbom_components` can be dropped or kept gated as "raw scan
output."

Migration backfill: for each `ScanScope`, take the latest successful
`scan_runs.id` and copy its `sbom_components` rows into
`scope_components` with `dismissedStatus = 'active'`, `firstSeenScanRunId
= lastSeenScanRunId = <latest scan_run_id>`. Build the join rows in
the same pass.

## Worker integration

- New phase `llm_sbom_recheck` in `backend/src/schemas.ts` `ScanPhase`
  enum.
- Frontend `SCAN_PHASE_LABELS` + `SCAN_PHASE_UNITS` update (per the
  CLAUDE.md "Live scan progress" bullet).
- New service `backend/src/services/llmSbomRecheckService.ts` —
  mirrors `llmSastService.runRecheck` shape: takes the scope ID +
  current scan run ID, queries scope-level truth set, runs the
  two-tier check, returns recovery + removal verdicts.
- Worker calls it after `llm_sbom` applies, before OSV. Persistence
  writes to `scope_components` (update existing rows) and
  `scan_run_components` (insert join row for each component seen
  this run, including recoveries).

## Failure modes & sticky-component defense

The big risk: LLM rubber-stamps "still there" on every recheck →
components persist forever even after legitimate removal.

Defenses, in order:

1. **Tier 1 is the strong signal.** When the recorded evidence path is
   missing, we don't ask the LLM. Removal is mechanical.
2. **Tier 2 LLM has fresh-eyes context.** It doesn't see the prior
   "still there" verdicts; each recheck is independent. So persistent
   bias would have to recur across runs.
3. **Manual override.** The Components tab UI gets a "mark removed"
   button. `source = 'manual'` rows can be overridden by the operator.
4. **Evidence-path requirement on add records.** Tighten the
   augmentation prompt: every `add` record MUST include an
   `evidence_path`. Existing rows without paths fall straight to
   Tier 2 — fine for now, but new additions never enter that bucket.

The worst case: a component with a still-existing evidence file
that the LLM keeps confirming despite the file being unrelated.
Detectable by manual audit; rare in practice given the LLM has the
file content to inspect.

## Failure modes (new warning codes)

| Code | Severity | What happens | Recovery |
|---|---|---|---|
| `llm_sbom_recheck_failed` | error | The recheck subprocess crashed or timed out. Recovered set is empty; potentially missing components stay in `active` status from prior runs (safe default). Scan marked untrustworthy so SCA auto-fix doesn't run. | Inspect logs; re-run. |
| `llm_sbom_recheck_partial` | info | Some Tier-2 verdicts unparseable. The unambiguous ones applied; ambiguous components stay `active` for safety. | Usually self-clears next run. |

## UI implications

- **Components tab:** queries `scope_components WHERE
  dismissed_status = 'active'` by default. New filter chip "Show
  removed" surfaces dismissed rows with a "Last seen <date> · <reason>"
  caption.
- **Component detail:** new section showing first-seen / last-seen
  scan dates, dismissed-status history, source.
- **Manual addition:** "Add component" button on the Components tab.
  Opens a form (name, version, ecosystem, optional CPE, evidence path,
  rationale). Writes a `scope_components` row with `source = 'manual'`.
- **Audit page:** per-scan view (existing `/scans/:id`) gains a
  "Components contributed by this run" section reading from
  `scan_run_components`.

## Effort estimate

| Piece | Effort |
|---|---|
| Schema + migration + backfill | L (1 day) |
| `llmSbomRecheckService.ts` + prompt | M (half-day) |
| Worker integration + phase wiring | M (half-day) |
| Persistence layer rewrite (Components tab queries) | M (half-day) |
| UI: Components tab filter + dismissed-row rendering | M (half-day) |
| UI: "Add component" / "Mark removed" manual paths | M (half-day) — defer if needed |
| Tests + backfill verification | M (half-day) |
| Documentation (SCAN_LIFECYCLE.md + CLAUDE.md "for AI agents") | S (1 hr) |
| **Total** | **~3–4 days** |

## Sequencing

This is feature work, not production-readiness, so it doesn't gate
the first prod deploy. But the FSS demo regression demonstrated the
cost of non-determinism in concrete dollars and credibility — this
should be prioritized post-demo, ahead of most M7 P2 items.

Suggested order:

1. **After tomorrow's demo** — schema design review with the operator.
2. **Schema + migration first** as its own commit; the migration is the
   load-bearing change. Old `sbom_components` writes continue
   side-by-side until the new model is proven.
3. **Service + worker phase** second; behind a feature flag if needed.
4. **UI cut-over** third; the Components tab moves from `sbom_components`
   to `scope_components` reads in a single coordinated commit.
5. **Manual add/remove UI** last (genuinely optional for v1).
6. **Drop `sbom_components`** in a follow-up milestone once the new
   model has run for a few weeks. Keep one curated-SBOM-builder
   regression test that exercises both paths during the cross-over.

## Out of scope

- **Multi-scope component coalescing.** Two scopes of the same repo
  that both vendor zlib should ideally share a single component
  identity. Out of scope; today every scope has its own component
  row. Revisit when a customer asks.
- **Cross-repo component identity.** Same as above but across repos.
  Out of scope.
- **Component CPE editing UI.** Operator-editable CPEs would help when
  the LLM gets the canonical CPE wrong. Track separately.
- **Component review queue.** A dashboard of recently-removed or
  recently-added components for operator approval. Track separately.

## Open questions to resolve before implementation

1. **What's the eviction policy for `scope_components`?** Never (audit
   trail forever)? Or prune `removed` rows after N days/scans?
   Recommend never — disk is cheap and an auditable removal record
   is valuable for CRA compliance.
2. **Recheck and `dismissedStatus = 'manual_override'`.** If the
   operator manually marked a component "removed", the recheck
   shouldn't re-add it just because the LLM finds it. Need an explicit
   "don't touch operator decisions" rule in the recheck logic.
3. **Truncation policy for very large drift.** If 50 components drop
   between scans (e.g., a major refactor), do we Tier-2-LLM all 50,
   or stop after N? Recommend hard cap of 20 with an `info` warning
   ("recheck_capped: more components dropped than budget; oldest by
   `last_seen_at` were skipped").
