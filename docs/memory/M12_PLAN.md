# M12 — Trustworthiness signals + `maybe_fixed` state machine

> **Status:** queued (2026-05-25). Spun out of an M11 shake-out: a fresh
> FSS scan finished `status=success` despite the LLM SAST detection
> subprocess being killed by the stdout-staleness watchdog. The
> trustworthiness gate (M6i `hasErrorWarnings`) correctly held
> `scope.lastScanRunId` at the prior trustworthy scan — but the scope
> page filter (`lastSeenScanRunId === scope.lastScanRunId`) then hid
> every legitimate finding from the new scan, leaving the operator
> staring at "0 SCA · 0 SAST · No open issues" with zero indication
> that anything had gone wrong.
>
> **Two problems exposed, two milestones.**
>
> **Phase A (M12) — trustworthiness & UX.** Cheap, ship-first.
> Per-subsystem trustworthiness classification, status surfacing on
> every UI that shows scans, and the SCA auto-fix gate split per
> subsystem. No schema change to issue tables.
>
> **Phase B (M13) — `maybe_fixed` state machine.** Larger. Replaces
> the naive "auto-mark fixed" / "filter by lastSeenScanRunId"
> approach with an explicit state for "automation thinks this is
> gone; operator confirmation needed." Schema migration, new
> operator actions, removal of the lastSeenScanRunId visibility
> filter.

This document covers both phases as a single contract. M12 ships first
as one commit; M13 follows as its own milestone with its own commit.

---

## Goal

Make scan failure visible and consequences proportional.

1. **No scan failure ever silently degrades the operator's view of
   findings.** Today the operator opened FSS and saw "0 open issues."
   Nothing on the page hinted that the most recent scan was
   untrustworthy or that the displayed counts were stale.

2. **Don't paint the entire scan red when only one subsystem broke.**
   When SAST stalls but SBOM + OSV + NVD + EOL completed cleanly, the
   SCA auto-resolve sweep can still run safely — it just needs to be
   gated per-subsystem.

3. **Stop pretending "wasn't detected" means "fixed."** False-negative
   resolutions are far more dangerous in security tooling than
   false-positive findings. Operator judgment belongs in the loop for
   every auto-resolution, regardless of scan trustworthiness.

---

## Phase A — Trustworthiness signals (M12)

### A1. Warning code classification

Every existing error-severity warning code is classified as
SCA-impacting, SAST-impacting, or BOTH. A new helper
`subsystemImpact(warningCode) → { sca: boolean; sast: boolean }`
centralises the mapping.

Audited against `worker.ts` 2026-05-25 — every code below was found at
the line indicated. Error-severity codes are the only ones that ever
enter the impact calculation (helpers filter on `severity === "error"`),
but info-severity codes are listed here too so future maintainers can
see they were considered and intentionally classified as no-impact.

| Code | Severity | Source | SCA | SAST |
|---|---|---|---|---|
| `scope_path_missing` | error | worker.ts:1274 | ✓ | ✓ |
| `remote_unreachable` | error | worker.ts:1830 | ✓ | ✓ |
| `auth_failed` | error | worker.ts:1843 | ✓ | ✓ |
| `branch_not_found` | error | worker.ts:1840 | ✓ | ✓ |
| `clone_failed` | error | worker.ts:1846 | ✓ | ✓ |
| `cdxgen_failed` | error | worker.ts:1305 | ✓ | ✓ |
| `cdxgen_zero_components` | error | worker.ts:1323 | ✓ | (no — SAST has its own LLM-driven path) |
| `llm_sbom_augmentation_failed` | error | worker.ts:1416 | ✓ | ✓ |
| `llm_sbom_parse_errors` | error \| info | worker.ts:1382 | ✓ (when error) | (no) |
| `llm_sbom_recheck_failed` | error | worker.ts:1602, 1610 | ✓ | (no) |
| `llm_sbom_recheck_partial` | error \| info | worker.ts:1577 | ✓ (when error) | (no) |
| `sbom_persist_failed` | error | worker.ts:1460 | ✓ | ✓ |
| `sbom_emit_failed` | error | worker.ts:1677 | (no — artifact-only) | (no — artifact-only) |
| `llm_sast_detection_failed` | error | worker.ts:373, 399 | (no) | ✓ |
| `llm_sast_parse_errors` | error \| info | worker.ts:382 | (no) | ✓ (when error) |
| `llm_recheck_failed` | error | worker.ts:628 | (no) | ✓ |
| `llm_recheck_parse_errors` | error \| info | worker.ts:637 | (no) | ✓ (when error) |
| `sarif_emit_failed` | error | worker.ts:461 | (no — artifact-only) | (no — artifact-only) |
| `sast_ingest_failed` | error | worker.ts:491 | (no) | ✓ |
| `nvd_query_failed` | info | worker.ts:1647 | (no — info, not error) | (no) |
| `llm_sast_detection_retry` | info | worker.ts:359 | (no — info) | (no — info) |
| `llm_recheck_retry` | info | worker.ts:617 | (no — info) | (no — info) |
| `sast_duplicates_merged` | info | worker.ts:677 | (no — info) | (no — info) |
| `recheck_capped` | info | worker.ts:1564 | (no — info) | (no — info) |

Codes with `error | info` are dual-severity: the worker calls
`parseErrorSeverity(accepted, parseErrors)` which returns `error` when
the drop rate is at or above the trustworthiness threshold, `info`
otherwise. The classification table column captures the
**when-error-severity** impact; `info`-severity emissions of those
same codes never enter the helper.

Two helpers replace today's single `hasErrorWarnings`:

```ts
export async function hasScaImpactingErrorWarnings(scanRunId: string): Promise<boolean>;
export async function hasSastImpactingErrorWarnings(scanRunId: string): Promise<boolean>;
```

The existing scalar `hasErrorWarnings` stays (other callers depend on
it for the `lastScanRunId` advance gate — see A4).

**Location: new module `backend/src/services/scanWarnings.ts`.** Three
sites consume these helpers (`worker.ts`, `llmSastService.ts`,
`services/mappers.ts`); putting them on a leaf module avoids the
circular-dep risk of importing from `worker.ts`. The existing
`hasErrorWarnings` (currently defined in worker.ts:153) moves to the
same file in the same change; worker.ts re-imports from the new
location instead of relying on the local function. `subsystemImpact`
takes the warning code (string) and returns `{ sca: boolean; sast:
boolean }`. The dual-severity codes resolve at the helper level: each
`has*ImpactingErrorWarnings` filters the warnings array first by
`severity === "error"`, then by the relevant subsystem bit.

### A2. `scan_runs.trustworthy` — computed exposure

No new column. Compute at mapper time inside `scanRunToOut`:

```ts
trustworthy_overall: !hasErrorSev(warnings),
trustworthy_sca: !hasErrorSev(filter(warnings, subsystemImpact(c).sca)),
trustworthy_sast: !hasErrorSev(filter(warnings, subsystemImpact(c).sast)),
```

Add the three booleans to `ScanRunOutSchema`. Frontend OpenAPI regen
picks them up.

Rationale for "no column": the warnings array is the source of truth;
deriving on read prevents drift. If we ever add a new warning code we
update the helper, not a migration.

### A3. UI surfacing

Three places must show a trustworthiness signal so operators can't
miss it:

1. **Scope detail page header (`/scopes/:id`).** Amber banner directly
   under the title row when `latest_scan.trustworthy_overall === false`.
   Insert at the spot where `ScanProgressBanner` renders today
   (`ScopeDetailPage.tsx:2095`); coexists with the live-progress
   banner during an active scan. Copy: *"Most recent scan completed
   with errors. Findings shown reflect the last fully-trustworthy
   scan from <date>. Click for details."* Click expands a panel
   listing each error warning + its subsystem impact. **Style after
   the existing warnings Card on `ScanDetailPage.tsx:935-983`** —
   amber-bordered Card with `AlertTriangle` icon and per-warning
   message rows. Re-use the per-warning detail rendering pattern
   (raw payloads collapsible) for consistency.

2. **Scopes list row (`/scopes`).** Small amber chip next to the
   scope name when latest scan was untrustworthy. Tooltip on hover
   names the failing subsystems.

3. **Scan rows (audit list `/scans` + recent-scans drawer on the
   scope page).** **No trustworthiness chip exists today** — the
   original plan's "verify wired" claim was wrong (M9 added the
   `lastScanRunId` advance gate and the scan-detail warnings banner;
   no per-row chip was added). M12 ADDS an amber chip on each scan
   row when `trustworthy_overall === false`. Surface on:
   - `ScansPage.tsx` table row (next to `ScanStatusBadge`)
   - `ScopeDetailPage.tsx` recent-scans drawer
     (`RecentScansSection`, ~line 1884) next to the status dot
   Tooltip lists the failing subsystems.

### A4. Per-subsystem auto-fix gating — symmetric

Gating must be symmetric: SCA stalls can block SAST cleanup just as
much as SAST stalls block SCA cleanup. Both directions get explicit
gates.

| Auto-resolve path | Currently gated on | After M12 |
|---|---|---|
| SCA sweep (`worker.ts:1759`) | `hasErrorWarnings(scanRunId)` (overall) | `hasScaImpactingErrorWarnings(scanRunId)` |
| SAST recheck `fixed`/`file_deleted` verdicts (`llmSastService.ts:applyRecheckVerdicts`) | (no explicit gate) | `hasSastImpactingErrorWarnings(scanRunId)` |

The SAST recheck path doesn't have an explicit gate today; in practice
if SAST detection fails the recheck also produces no verdicts.
M12 makes this explicit: if a SAST-impacting error fired before
`applyRecheckVerdicts` runs, the "fixed" and "file_deleted" branches
no-op (verdict counted as `missingVerdict` and the issue stays at its
current `triageStatus`). The `still_present` branch is always safe to
apply — confirming an existing issue isn't a destructive operation.

`scope.lastScanRunId` advance gate (also tied to `hasErrorWarnings`):
**keep using the overall gate for now.** Per-subsystem advance is more
work — splits `lastScanRunId` into `lastScaScanRunId` + `lastSastScanRunId`
or similar. M13 retires the gate's visibility role entirely (see B6),
so deferring the per-subsystem split is correct.

### A5. Scope-detail count query

The current filter
`{ scopeId, dismissedStatus: { notIn: TERMINAL }, lastSeenScanRunId === scope.lastScanRunId }`
was the proximate cause of the "0 open issues" trap. **For M12 only**
the filter stays, but the amber banner on the scope page makes the
behavior visible. M13 removes the filter entirely.

### A6. Documentation

- `frontend/src/manual/content/scans.md` — extend the "Trustworthiness
  gate" section: spell out the per-subsystem classification table,
  call out which warning codes are SCA-only vs SAST-only.
- `frontend/src/manual/content/scopes.md` — describe the new amber
  banner and what it means for the displayed counts.
- `frontend/src/manual/content/sca-issues.md` — one-line
  cross-reference: "If the SCA Issues tab unexpectedly shows zero
  rows, check for an amber trustworthiness banner on the scope page;
  it indicates the most recent scan's SCA pipeline failed and counts
  reflect the last trustworthy scan." Reduces operator confusion when
  arriving at the tab from a deep link without seeing the banner
  first.
- `frontend/src/manual/content/sast-issues.md` — same one-line
  cross-reference, SAST-specific wording.
- `CLAUDE.md` — update the "Trustworthiness gate" pin to mention the
  per-subsystem split and the helpers (`hasScaImpactingErrorWarnings`
  / `hasSastImpactingErrorWarnings`).

### A7. Version bump

`0.11.1 → 0.12.0` (MINOR — operator-visible new UI element + new
fields in OpenAPI).

### Phase A exit criteria

- [ ] `subsystemImpact` helper exists; unit tests cover the
  classification table.
- [ ] `hasScaImpactingErrorWarnings` / `hasSastImpactingErrorWarnings`
  exported from worker.ts (or a new `scanWarnings.ts` service if
  that's cleaner).
- [ ] `scanRunToOut` emits `trustworthy_overall` /
  `trustworthy_sca` / `trustworthy_sast`. Zod schema updated. Frontend
  schema.d.ts regenerated.
- [ ] SCA auto-fix gate switched to `hasScaImpactingErrorWarnings`.
- [ ] SAST recheck `fixed`/`file_deleted` branches gated on
  `hasSastImpactingErrorWarnings` (symmetric with SCA).
- [ ] Amber banner renders on `/scopes/:id` when latest scan
  untrustworthy. Click expands warnings list.
- [ ] Scopes list row chip + scan rows chip wired to
  `trustworthy_overall`.
- [ ] Manual sections updated. Browser-checked.
- [ ] Live FSS scan that simulates a SAST stall (kill claude-p) shows
  the banner correctly. SCA sweep still runs.
- [ ] Live FSS scan that simulates an SCA stall (force cdxgen_failed)
  shows the banner correctly. SAST recheck cleanup branches no-op
  but `still_present` verdicts still apply.
- [ ] Version bump, PROGRESS.md entry.

---

## Phase B — `maybe_fixed` state machine (M13)

### B0. Triage field unification (pre-step for the state machine work)

Today the two issue tables have asymmetric, partially-misleading
triage-related field names. Pre-1.0 is the right time to fix it; the
state-machine work in B1+ is easier on top of a coherent base.

**The asymmetry today:**

| Concept | `sca_issues` | `sast_issues` |
|---|---|---|
| Operator triage state | `dismissed_status` | `triage_status` |
| Operator action timestamp | `dismissed_at` | `suppressed_at` (misnamed — used for any non-pending status) |
| Operator who acted | `dismissed_by_user_id` | `suppressed_by_user_id` (misnamed — same) |
| Operator's short reason | `dismissed_reason` | `suppressed_reason` (misnamed — same) |
| Free-text operator notes | `notes` | *(missing)* |
| LLM-set reasoning narrative | *(n/a — no LLM triage on SCA)* | `triage_reasoning` |
| LLM telemetry | *(n/a)* | `triage_confidence`, `triage_model`, `triage_input_tokens`, `triage_output_tokens` |

Two problems:
1. **Same concept, different names across tables.** Fixed by aligning
   on the `triage*` prefix (better than `dismissed*` because operator
   actions include confirming and planning, not just dismissing).
2. **`suppressed*` on SAST is misleading.** The fields are stamped on
   every non-pending operator action, not just suppression — calling
   them `suppressedAt` is actively wrong for a `confirmed` or
   `planned` operator action. Confused me; will confuse the next
   contributor.

**The target schema (both tables):**

```
triage_status         text   default 'pending'
triaged_at            timestamptz null
triaged_by_user_id    uuid   null
triage_reason         text   null     -- operator's short reason
notes                 text   null     -- free-text operator notes
```

Plus on `sast_issues` only (LLM-specific, kept as-is but the polysemy
in `triage_reasoning` gets resolved):

```
llm_triage_reasoning  text   null     -- rename of triage_reasoning;
                                      -- LLM-set narrative only
triage_confidence     float  null     -- LLM-set, unchanged
triage_model          text   null     -- LLM-set, unchanged
triage_input_tokens   int    null
triage_output_tokens  int    null
```

**Migration steps:**

1. New migration `unify_triage_fields`:
   - On `sca_issues`: rename `dismissed_status` → `triage_status`,
     `dismissed_at` → `triaged_at`, `dismissed_by_user_id` →
     `triaged_by_user_id`, `dismissed_reason` → `triage_reason`.
   - On `sast_issues`: rename `suppressed_at` → `triaged_at`,
     `suppressed_by_user_id` → `triaged_by_user_id`,
     `suppressed_reason` → `triage_reason`, `triage_reasoning` →
     `llm_triage_reasoning`. Add `notes` (nullable text).
   - Update indexes that reference the renamed columns
     (`@@index([scopeId, triageStatus])` on both, already exists for
     SAST under that name; SCA's `@@index([scopeId, dismissedStatus])`
     gets recreated).
2. Update `schema.prisma` field declarations + `@map` directives.
3. Generate Prisma client.
4. Find-and-replace across `backend/src/` for the renamed identifiers
   (predictable scope — every reference is in the SCA route handler,
   issueService, mappers, scaIssueToOut, the dismiss endpoint, tests).
5. Update Zod schemas:
   - Drop `ScaDismissedStatusSchema`; alias `ScaTriageStatusSchema =
     SastTriageStatusSchema` (or just have one shared
     `IssueTriageStatusSchema` and use it both sides).
   - `ScaIssueDismissBodySchema` → `ScaIssueTriageBodySchema` (and
     align field names with the SAST body).
6. Rename the endpoint `POST /api/sca-issues/:id/dismiss` →
   `POST /api/sca-issues/:id/triage` for symmetry with the SAST
   endpoint. There are no external integrations yet (pre-1.0), so
   breaking the URL is acceptable. Mention in PROGRESS.md so the
   change is discoverable for anyone with a curl bookmark.
7. Frontend: regenerate `schema.d.ts`; update the SCA mutation
   call-sites that hit `/dismiss` to hit `/triage` with the unified
   body shape; rename any `dismissedStatus` references in components.
8. Update manual sections: `sca-issues.md` and `sast-issues.md`
   reference the new field names + endpoint.

**Why include this in M13:**

- B1's new `maybe_fixed` value applies to ONE column. Doing the
  rename first means we add the value once, not in two namespaces
  that need to converge later.
- B4's re-detection auto-revert logic in
  `upsertScaIssueFromDetection` is cleaner when the field name
  matches the SAST side (the code pattern is genuinely identical).
- B5's two new endpoints can adopt the unified naming from day one.

**What this does NOT change:**

- The two underlying tables stay separate. SCA findings and SAST
  findings have genuinely different data models (CVE/package/severity
  vs file/line/CWE); a single `issues` table would be wrong.
- LLM telemetry stays on SAST only. SCA doesn't use an LLM for
  triage today.
- Existing data: no row content changes, just column renames.

### B1. New state value

Add `"maybe_fixed"` to:

- `backend/src/schemas.ts` `ScaDismissedStatusSchema` enum.
- `backend/src/schemas.ts` `SastTriageStatusSchema` enum.
- Frontend types regenerated via `npm run gen:types`.
- Frontend filter UI: new chip in the dismissedStatus / triageStatus
  filter bar.

No DB migration needed — both columns are plain TEXT.

### B2. New schema column: `prior_status`

```prisma
// On both ScaIssue and SastIssue:
priorStatus String? @map("prior_status")
```

Nullable. Captured at the moment of transition to `maybe_fixed`;
cleared on any transition out. Holds the operator-visible state that
existed before automation moved the issue to `maybe_fixed`.

App-level invariant (no DB constraint): when `dismissedStatus ==
"maybe_fixed"`, `priorStatus IN ("pending", "confirmed", "planned")`.
When `dismissedStatus != "maybe_fixed"`, `priorStatus IS NULL`.

Migration: `pnpm prisma migrate dev --name add_prior_status`.

### B3. Worker auto-resolve sweep — rewrite for `maybe_fixed`

**SCA path** (`worker.ts:1759`). The current `updateMany` becomes a
per-row update so `priorStatus` can be captured:

```ts
if (!await hasScaImpactingErrorWarnings(scanRunId)) {
  const TRANSITIONABLE = ["pending", "confirmed", "planned"];
  const candidates = await prisma.scaIssue.findMany({
    where: {
      scopeId: run.scopeId,
      lastSeenScanRunId: { not: scanRunId },
      dismissedStatus: { in: TRANSITIONABLE },
    },
    select: { id: true, dismissedStatus: true },
  });
  // updateMany per status bucket so all rows in a bucket can be moved
  // in a single SQL UPDATE — avoids N writes for N issues.
  for (const status of TRANSITIONABLE) {
    const ids = candidates.filter(c => c.dismissedStatus === status).map(c => c.id);
    if (ids.length === 0) continue;
    await prisma.scaIssue.updateMany({
      where: { id: { in: ids } },
      data: { dismissedStatus: "maybe_fixed", priorStatus: status },
    });
  }
}
```

**SAST path** (`llmSastService.ts:1234`, the `applyRecheckVerdicts`
function). The `fixed` and `file_deleted` verdicts both currently set
`triageStatus = "fixed"`. Change to `maybe_fixed` with `priorStatus`
captured from the row's current `triageStatus`. `file_deleted` keeps
its `triageReasoning` prefix so the operator confirmation flow shows
WHY automation thinks it's gone.

### B4. Re-detection — auto-revert from `maybe_fixed`

`upsertScaIssueFromDetection` (`issueService.ts:128`) and
`upsertSastIssueFromDetection` (`issueService.ts:45`) currently
overwrite `latest*` fields on every detection but never touch
`dismissedStatus` / `triageStatus`. Extend both:

```ts
// Pseudocode (SCA — SAST mirrors with triageStatus):
const existing = await db.scaIssue.findUnique({ where: ..., select: { dismissedStatus, priorStatus } });

let statusUpdate = {};
if (existing?.dismissedStatus === "maybe_fixed") {
  statusUpdate = {
    dismissedStatus: existing.priorStatus ?? "pending",   // defensive fallback
    priorStatus: null,
  };
}

await db.scaIssue.upsert({
  ...,
  update: {
    ...latestFields,
    lastSeenScanRunId,
    ...statusUpdate,
  },
});
```

Defensive fallback to `"pending"` when `priorStatus IS NULL` — that
should never happen given the B2 invariant, but a bad migration or
manual DB poke shouldn't strand the issue.

**Terminal states stay terminal.** Re-detecting a `fixed` /
`suppressed` / `false_positive` issue does NOT re-open it. That's
out-of-scope for M13 (separate latent bug; deserves its own
discussion).

### B5. Operator actions

Two new actions on each `maybe_fixed` issue:

| Action | Endpoint | Effect |
|---|---|---|
| **Confirm fixed** | `POST /sca-issues/:id/confirm-fixed` (and `/sast-issues/:id/confirm-fixed`) | `dismissedStatus = "fixed"`; `priorStatus = null`. |
| **Still present** | `POST /sca-issues/:id/mark-still-present` (and `/sast-issues/:id/mark-still-present`) | `dismissedStatus = priorStatus` (or `"pending"` fallback); `priorStatus = null`. |

Both routes admin-only (mirror existing triage routes). Both audit
the actor in `dismissedByUserId` / `dismissedAt`.

UI: a dedicated row badge on `maybe_fixed` issues with two buttons.
Place near the existing dismissedStatus chip so the operator can act
in one click without expanding the row.

### B6. Remove the `lastSeenScanRunId` visibility filter

`backend/src/routes/scopes.ts` — the `lastSeenFilter` block in the
scope-detail count query AND the scope-list aggregation. With the
state machine, the dismissed/triage status IS the visibility decision:

- Detected this run → status stays in `pending|confirmed|planned`.
- Not detected, subsystem trustworthy → moved to `maybe_fixed`.
- Not detected, subsystem untrustworthy → status unchanged (operator
  sees "stuck" status; the trustworthiness banner explains why).
- Operator dismissed → terminal status, hidden by default.

Net: `lastSeenScanRunId` filter goes away. Issues show based on
`dismissedStatus NOT IN (fixed, suppressed, false_positive)` alone.

### B7. New count surface: `maybe_fixed_count`

Per A4 answer (user confirmed): `maybe_fixed` issues count toward
"open." Add `maybe_fixed_count` to both `ScopeListItemSchema` and
`ScopeDetailSchema`. Render as a dedicated chip on the scope page
("12 pending review") in the severity-summary row.

Severity-bucket counts (critical/high/medium/low) include
`maybe_fixed` rows so the operator sees the full risk surface.

### B8. Documentation

- `frontend/src/manual/content/sca-issues.md` — new section
  "Auto-resolution and confirmation" explaining the `maybe_fixed`
  state, when issues land there, what the operator does.
- `frontend/src/manual/content/sast-issues.md` — same.
- `frontend/src/manual/content/scopes.md` — describe the new
  "pending review" chip and how it relates to severity buckets.
- `CLAUDE.md` — update the trustworthiness-gate pin to mention the
  state machine; add a note that "wasn't detected" never means
  "silently fixed" anymore.

### B9. Version bump

`0.12.x → 0.13.0` (MINOR — new operator-visible state, new endpoints,
new schema column).

### Phase B exit criteria

- [ ] Migration `unify_triage_fields` committed (B0). SCA + SAST
  field renames applied. All call sites updated. `/api/sca-issues/:id/dismiss`
  renamed to `/api/sca-issues/:id/triage`.
- [ ] Migration `add_prior_status` committed.
- [ ] Schemas updated with `maybe_fixed`; OpenAPI regenerated.
- [ ] SCA worker sweep emits `maybe_fixed` + captures `priorStatus`.
- [ ] SAST `applyRecheckVerdicts` emits `maybe_fixed` + captures
  `priorStatus` for both `fixed` and `file_deleted` verdicts.
- [ ] `upsertScaIssueFromDetection` + `upsertSastIssueFromDetection`
  auto-revert from `maybe_fixed` to `priorStatus`.
- [ ] Two new endpoints per issue type (4 routes) with Zod schemas +
  audit fields.
- [ ] `lastSeenScanRunId`-based filters removed from scope list +
  detail aggregation queries.
- [ ] `maybe_fixed_count` surfaced on scope responses.
- [ ] UI: filter chip, row badge, two action buttons. Severity counts
  include `maybe_fixed` rows.
- [ ] Tests cover: SCA sweep → maybe_fixed; SAST recheck → maybe_fixed;
  re-detection auto-revert (all 3 prior states); confirm-fixed action;
  mark-still-present action; per-subsystem gate matrix.
- [ ] Existing `fixed` issues left untouched (no migration to
  `maybe_fixed`).
- [ ] Manual sections updated. Browser-checked.

---

## Risks + design tradeoffs

### Existing `fixed` issues stay terminal

Operators may have a long backlog of "fixed" issues that were
auto-resolved naively. M13 does NOT retroactively move them to
`maybe_fixed`. Rationale: operators have already moved on, and a bulk
state regression at upgrade time would erode trust. Net: the new
discipline starts from M13's deploy date forward.

### `priorStatus` as schema column vs. JSON field on a notes/audit blob

Chose dedicated nullable column over packing it into `notes` or an
audit-trail JSON because:
- App-level invariant (B2) is cleanly enforceable in upsert code.
- Single-column index possible if we ever query "all maybe_fixed
  issues that were planned" (we don't today, but cheap to add).
- Migration is one column add — trivial.

### Per-subsystem `lastScanRunId` split deferred

A future milestone may want `lastScaScanRunId` / `lastSastScanRunId` so
the SCA truth set can advance independently of SAST trustworthiness.
M12 deliberately keeps the single `lastScanRunId` to limit scope.
B6 removes the filter that depended on it; the column itself remains
for "what was the most recent scan we touched this scope with" which
is still useful for the SBOM endpoint metadata, etc.

### SAST `file_deleted` verdict goes to `maybe_fixed`

Could argue: "file deleted" is a stronger signal than "didn't appear."
We're choosing consistency over nuance — every automation-driven
resolution requires confirmation. Operator confirmation for a
file-deleted issue is one click and the LLM's reasoning is already
captured in `triageReasoning`. Future iteration could add an
"auto-confirm file_deleted" knob if operators want it.

### What if an operator's `still_present` action then conflicts with the next scan?

Scenario: maybe_fixed issue → operator clicks "still present" →
reverts to (say) `planned`. Next scan again doesn't detect it. The
sweep moves it back to `maybe_fixed` with priorStatus=planned. This
is correct behavior — the operator's "still present" assertion is a
point-in-time claim, not a permanent immunity. If the operator wants
to stop the cycle they should investigate (maybe the analyzer is
genuinely blind to this case, in which case a `suppressed` with
`dismissedReason="false negative — confirmed manually"` is the right
move).

---

## Out of scope

- Re-opening terminal-state (`fixed` / `suppressed` / `false_positive`)
  issues on re-detection. Latent bug; deserves its own discussion.
- Per-subsystem `lastScanRunId`. M12 keeps the overall pointer.
- Migrating historical `fixed` issues to `maybe_fixed`. M13 starts the
  new discipline forward-only.
- "Auto-confirm file_deleted" operator preference. Possible future
  iteration; not in M13.
- Watchdog stall RCA. The proximate trigger (claude-p stdout
  staleness) is a separate ops concern. M12 + M13 make the
  consequences proportional; they don't fix the underlying LLM
  reliability question.
