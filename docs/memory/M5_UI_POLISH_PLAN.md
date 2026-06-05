# M5 UI polish — filter bars, column unification, LLM summaries

Scope: clean up `ScopeDetailPage.tsx` filter bars and tables so SAST and SCA feel like two views of the same thing, and make LLM-generated summaries the authoritative "what is this issue about" blurb on both sides.

Current relevant files:
- `frontend/src/routes/ScopeDetailPage.tsx` (1365 lines — contains `FilterGroup`, `Pipe`, `ToggleGroup`, `SastIssueRow`, `ScaIssueRow`, both tab components)
- `backend/src/routes/scopes.ts` (list endpoints + filter query params)
- `backend/src/services/issueService.ts` (upsert writers for both issue types)
- `backend/src/services/llmTriageService.ts`, `llmClient.ts` (existing LLM wiring, gated by `llmAssistanceEnabled`)
- `backend/src/services/reachabilityService.ts` (writes `confirmedReachable`)
- `backend/src/worker.ts` (scan pipeline order)
- `backend/prisma/schema.prisma` (`SastIssue.latestRuleMessage`, `ScaIssue.latestSummary`)

## Bugs / inconsistencies to confirm first

1. **SCA has no status filter.** `ScaIssueFilters` has no `dismissed_statuses`; the filter bar omits a status `FilterGroup`. But SCA now has a real lifecycle (`active → confirmed → planned + wont_fix/false_positive/acknowledged`), so a status filter is appropriate.
2. **Scope list's `pending_triage_count` counts only SAST.** `backend/src/routes/scopes.ts:169` filters `prisma.sastIssue.count({ ... triageStatus: "pending" })`. That explains "46 pending" on the scopes page with zero visible pendings on the SCA tab — pending is SAST-only. Decide: rename to "SAST pending" in the scopes page badge, or include SCA `active` (pre-triage) in the count. Prefer: make it an SAST-only count but label it clearly (`46 SAST pending`) **or** extend SCA to have a `pending` state and roll both up. Recommend keeping SAST-only and relabeling — SCA doesn't need a "pending" state if the LLM triage doesn't gate it.
3. **"Reachable" lozenge missing.** Row code at `ScopeDetailPage.tsx:861` still renders the badge when `issue.confirmed_reachable` is true. `reachabilityService.ts:268` writes it. So the symptom is data, not UI. Check:
   - Is `llmAssistanceEnabled=true`?
   - Did reachability run on the last GoPxL scan? (look for reachability confirmations in logs)
   - Are any `ScaIssue.confirmedReachable=true` rows in the DB?
   Fix whichever is wrong; re-kick scan to verify.

## Design decisions

### D1. Filter bar separators
Tiny `|` glyphs between intra-group items (critical|high|medium|low) are hard to distinguish from the thin `Pipe` between groups. Pick one:
- **Recommended:** drop the intra-group `|` entirely. Buttons in a `FilterGroup` share a segmented-control look (connected pill group, no gap, shared border radius at the group edges only). Keeps a single unambiguous separator — the `Pipe` — between groups.
- Alternative: keep `|` but make the group-separator `Pipe` taller and darker.

### D2. Capitalization
All button labels and badges use sentence case (first word capped, rest lowercase). Known acronyms are ALL CAPS: `CVE`, `EOL`, `CWE`, `OSV`, `SBOM`, `SAST`, `SCA`, `DEV`.
- `"critical"` → `"Critical"`
- `"has fix"` → `"Has fix"`
- `"hide dev"` → `"Hide dev"`
- `"include resolved"` → `"Include resolved"`
- `"cve"` → `"CVE"`, `"eol"` → `"EOL"`, `"deprecated"` → `"Deprecated"`
- `"To do"` stays as-is (sentence case already)
- `"planned"` → `"Planned"`, `"fixed"` → `"Fixed"`, `"pending"` → `"Pending"`, `"won't fix"` → `"Won't fix"`, `"invalid"` → `"Invalid"`, `"acknowledged"` → `"Acknowledged"`
- Remove the `capitalize` Tailwind class on badges and bake casing into the labels, to prevent double-capping bugs on multi-word strings.

### D3. Column unification (SAST + SCA)

Both tables get the **same column order, same widths, same typography**:

| # | Column      | Width    | SAST value                                      | SCA value                                        |
|---|-------------|----------|-------------------------------------------------|--------------------------------------------------|
| 1 | chevron     | `w-6`    | expand toggle                                   | expand toggle                                    |
| 2 | Severity    | `w-24`   | `SeverityBadge`                                 | `SeverityBadge`                                  |
| 3 | Summary     | flex-1   | LLM-generated 1-liner (see D4)                  | LLM-generated 1-liner                            |
| 4 | Location    | `w-64`   | `file/path:line` (mono, muted)                  | `package@version` (mono, muted)                  |
| 5 | Status      | `w-28`   | `JiraStatusPill` or `TriageBadge`               | `JiraStatusPill` or SCA status badge             |
| 6 | Last seen   | `w-24`   | relative time                                   | relative time                                    |

Notes:
- Font: Summary = `text-sm`, Location = `text-xs font-mono text-muted-foreground`. Same everywhere.
- Move secondary badges (`CVE link`, `DEV`, `Has fix`, `Reachable` on SCA; `Rule ID` on SAST) to a **second line underneath the Location cell** in mono/small style, so both sides look structurally identical.
- Copy-link button stays in the Summary cell (rightmost, hover-reveal), to match SAST's current placement.
- Column widths set via `<TableHead className="w-…">` and header-only widths; cells auto-fit.

### D4. LLM-generated summaries (authoritative, non-optional)

The backend must generate a succinct one-line `latest_llm_summary` for every issue and the frontend must show it in the Summary column.

**Schema** — add both:
- `SastIssue.latestLlmSummary String?` (`@map("latest_llm_summary")`)
- `ScaIssue.latestLlmSummary String?` (`@map("latest_llm_summary")`)

Keep existing fields (`latestRuleMessage`, `latestSummary`) as raw-source fallbacks; don't remove.

**Generation** — add `llmClient.generateIssueSummary(context) → string` (single-shot, max ~25 tokens output, temperature 0). Prompts live next to `llmTriageService.ts`:
- SAST prompt: given rule ID, rule name, rule message, file path, snippet, produce ≤ 100-char plain English summary starting with a verb.
- SCA prompt: given package, version, OSV ID, CVSS, OSV summary, produce ≤ 100-char plain English summary of the vulnerability's impact.

Wire into the scan pipeline in `worker.ts` after detection + before triage:
- Iterate new/changed issues (from `upsertSastIssue` / `upsertScaIssue` return shape — extend to return `isNew | changed`).
- Call `generateIssueSummary`; update `latestLlmSummary`.
- Batch where possible (see `cveKnowledgeService` batching pattern).

**Fallback policy — pick one:**
- **(A) Hard-require LLM.** Scan fails if LLM is misconfigured. Simple, aligns with user's ask.
- **(B) Soft-require.** Issues without a summary display the raw fallback (`latestRuleMessage` for SAST / `latestSummary` for SCA) *and* get queued for backfill on next successful LLM check.
- **(C) Deprecate the `llmAssistanceEnabled` toggle.** Remove the checkbox and the code paths that short-circuit on it. Triage + summary + reachability all assume LLM is live. Keep `checkLlmConnection` on settings page so ops can validate.
- **Recommended:** (C) + (A). Commit to LLM-mandatory; remove the toggle. `/admin/settings/llm/check` must pass before Scan Now is enabled, otherwise the button is disabled with a tooltip. Any current rows without `latestLlmSummary` are backfilled by a one-shot worker job `backfillLlmSummaries` on next boot (or a manual admin action).

**Backfill path** — one of:
- Add a `POST /admin/maintenance/backfill-llm-summaries` admin route that iterates `{issues | where: latestLlmSummary IS NULL }` across all scopes and fills them in batches. Safe to run repeatedly.
- Or fire this automatically on worker startup if any rows are missing. Simpler.

### D5. SCA status filter parity

`ScaIssueFilters`: add `dismissed_statuses?: ScaDismissedStatus[]`.
- Statuses to expose: `active`, `confirmed`, `planned`, `acknowledged`, `wont_fix`, `false_positive`. `planned` is implicit (comes from linking a Jira ticket).
- Backend route: add `z.array(z.enum([...]))` to query schema, filter `prisma.scaIssue.findMany({ where: { dismissedStatus: { in: ... } } })`.
- Frontend: add a `FilterGroup` identical to SAST's, between the type group and the toggle group. Same labels via a shared `SCA_STATUS_LABELS` constant (already exists — just capitalize).

## Implementation order

Recommended ordering (minimize churn on migrations/data):

1. **Schema + LLM summary plumbing** (backend)
   - Migration: add `latestLlmSummary` to both `SastIssue` and `ScaIssue`.
   - Add `llmClient.generateIssueSummary()` with SAST + SCA prompts.
   - Wire into `worker.ts` scan pipeline for new / changed issues.
   - Add `backfillLlmSummaries` maintenance function; run on boot or via admin route.
   - Delete `llmAssistanceEnabled` toggle + all call sites that branch on it (the LLM is now required). Keep `checkLlmConnection`.
2. **API + types**
   - Extend `SastIssue` and `ScaIssue` API schemas in `mappers.ts` + `scopes.ts` with `latest_llm_summary`.
   - Add `dismissed_statuses` filter to SCA list endpoint.
   - Regenerate frontend OpenAPI types (`cd frontend && npm run gen:types`).
3. **Frontend filter bar**
   - Rewrite `FilterGroup` as a segmented control (no `|` glyphs).
   - Add `SCA_STATUSES` + status `FilterGroup` to `ScaTab`.
   - Capitalize all labels per D2; delete `capitalize` Tailwind class where used.
4. **Frontend table unification**
   - Swap columns: Summary before Location.
   - Rename SCA "Package" header to "Location".
   - Align font/widths per D3.
   - Read `issue.latest_llm_summary` for the Summary column; fall back to `latest_rule_message` / `latest_summary` only if null.
   - Move secondary badges (CVE link, DEV, has fix, reachable) under the Location cell.
5. **Scope list tweak**
   - Either relabel the badge to `N SAST pending` in `ScopesPage.tsx`, or fold SCA `active` into the count (prefer: relabel — SCA doesn't need a `pending` gate).
6. **Reachability investigation**
   - Run a scan on GoPxL BE after #1–#4 land, confirm reachable lozenge reappears. If not: inspect worker logs for reachability confirmations, check `llmTriageService` configuration, add logging if needed.

## Scope guardrails

- Don't touch M5d/5e work — this is pure UX polish on top of shipped functionality.
- Don't rename or move existing API fields; only add `latest_llm_summary` and `dismissed_statuses`.
- No DB data loss: `latestRuleMessage` and `latestSummary` stay as raw-source fallbacks.
- Keep this change behind one PR — it's self-contained.

## Acceptance checklist

- [ ] SCA tab shows a status filter identical in style to SAST.
- [ ] All filter bar labels use sentence case; acronyms (CVE, EOL, CWE, OSV, DEV) are all caps.
- [ ] Segmented-control look between intra-group buttons; clear separator between groups.
- [ ] SAST and SCA tables have identical column order, widths, and typography.
- [ ] SCA's second column header reads "Location", not "Package".
- [ ] Summary column is populated by an LLM-generated 1-liner for every issue (backfilled for existing data).
- [ ] Reachable lozenge appears again on a GoPxL BE re-scan.
- [ ] `llmAssistanceEnabled` toggle removed; LLM connection check gates Scan Now.
- [ ] `pending_triage_count` badge on scopes page is either correctly labeled or correctly computed.
