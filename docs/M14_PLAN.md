# M14 — Ignore components + dismissed_status vocabulary cleanup

Status: in progress (2026-05-27)
Target version: 0.13.0 → 0.14.0 (MINOR)

## Goal

Give operators a first-class way to mark a `scope_component` as "I don't care about this, don't surface it or its CVEs anywhere." Sticky across scans. Sweep the `scope_components.dismissed_status` vocabulary while we're touching it.

## Why now

The current dismissed_status vocabulary on `scope_components` has accreted three problems:

1. `'removed'` overstates certainty. The worker writes it when (a) an `evidence_path` file no longer exists on disk or (b) the LLM SBOM recheck verdicts a component as absent. Neither is a confirmed removal — just "we can't find evidence anymore." The right name is `not_found`.
2. `'manual_override'` is documented as a dismissed_status value but is never actually written there. The PATCH route writes `source = 'manual_override'`, and that's where the operator-edited-row signal correctly lives. Two queries in `llmSbomRecheckService.ts` defensively check `dismissed_status = 'manual_override'` — they're semantically pointing at the wrong column.
3. There's no operator-facing "mute this component" affordance. The trashcan does a hard DELETE, which is right for "this row is wrong" but wrong for "this row is correct but I don't want to see it." Operators have been using the trashcan as a heavy hammer because there was no lighter tool.

## End state

```
scope_components.dismissed_status ∈ { active, not_found, ignored }
scope_components.source           ∈ { scan, manual_override }
```

Three lifecycle states, one orthogonal source flag. Disjoint concerns.

## Changes — at a glance

### Schema (one new migration folder)

`backend/prisma/migrations/<ts>_rename_removed_to_not_found_drop_manual_override_from_dismissed/migration.sql`:

```sql
UPDATE scope_components SET dismissed_status = 'not_found' WHERE dismissed_status = 'removed';
UPDATE scope_components SET dismissed_status = 'active'    WHERE dismissed_status = 'manual_override';
```

No DDL. `dismissed_status` is a TEXT column with no enum constraint. The folder IS the schema version bump per CLAUDE.md policy. Commit the folder.

### Backend code

**Rename `removed` → `not_found`** (must move with the migration):

- `backend/src/services/scopeComponentService.ts` — 8 references in raw SQL CASE-WHEN clauses + header doc comments. `'removed'` → `'not_found'`. Update the comment block at lines 45-48 to reflect the new vocabulary.
- `backend/src/services/llmSbomRecheckService.ts:461,637` — the two UPDATE statements that write `dismissed_status = 'removed'` become `'not_found'`. **Leave the LLM verdict text alone** — the prompt's JSON contract still says `"verdict":"removed"`, only the database column flips. Update the doc comment at line 19.
- `backend/src/services/llmSbomRecheckService.ts:412,695` — change `dismissed_status = 'manual_override'` → `source = 'manual_override'`. Same defensive intent, correct column. Line 412-413 currently has both `dismissed_status != 'manual_override' AND dismissed_status = 'active'` — the != check becomes `source != 'manual_override'`.
- `backend/prisma/schema.prisma:619` comment: `// "active" | "not_found" | "ignored"`.
- `CLAUDE.md` — search for any mention of `'removed'` / `manual_override` lifecycle and update.

**New routes** in `backend/src/routes/scopes.ts` (next to existing delete/patch):

```
POST /api/scopes/:id/components/:componentId/ignore   (requireAdmin)
  body: { reason?: string }
  → 200 { ok: true, suppressed_sca_count: number }

POST /api/scopes/:id/components/:componentId/unignore (requireAdmin)
  → 200 { ok: true, restored_sca_count: number }
```

Both return the count of cascaded sca_issues for operator confirmation.

**Extend `GET /api/scopes/:id/components`** querystring with `dismissed_statuses` (plural, matching SCA tab convention):

- Zod: `dismissed_statuses: toArrayLocal(z.enum(["active", "not_found", "ignored"]))` — make it optional.
- Default behavior (omitted/empty): `dismissed_status = 'active'`.
- When provided: `dismissed_status IN <chips>`. Replaces default, doesn't add.

**New service** `backend/src/services/scopeComponentService.ts`:

```ts
export async function ignoreScopeComponent(
  componentId: string,
  reason?: string | null,
): Promise<{ suppressed_sca_count: number }>;

export async function unignoreScopeComponent(
  componentId: string,
): Promise<{ restored_sca_count: number }>;
```

`ignoreScopeComponent` in a single `prisma.$transaction`:
1. Fetch the component (need `scopeId`, `name`). Throw if not found.
2. `UPDATE scope_components SET dismissed_status='ignored', dismissed_reason=:reason, dismissed_at=now(), updated_at=now() WHERE id=:id`
3. `UPDATE sca_issues SET dismissed_status='suppressed', dismissed_reason='component_ignored', dismissed_at=now(), updated_at=now() WHERE scope_id=:scopeId AND package_name=:name AND dismissed_status NOT IN ('fixed', 'false_positive')` — skip terminal triage states (operator's prior triage stands).
4. Return the row count from step 3.

`unignoreScopeComponent`:
1. Fetch the component.
2. `UPDATE scope_components SET dismissed_status='active', dismissed_reason=null, dismissed_at=null, updated_at=now() WHERE id=:id`
3. `UPDATE sca_issues SET dismissed_status='pending', dismissed_reason=null, dismissed_at=null, updated_at=now() WHERE scope_id=:scopeId AND package_name=:name AND dismissed_status='suppressed' AND dismissed_reason='component_ignored'` — only revive issues we suppressed via this cascade; leave dev_tree_policy suppressions alone.
4. Return the row count from step 3.

**Worker sticky cascade** — the operator-ignored state must survive new scans for new CVEs. Find the OSV/NVD phase where sca_issues are upserted (likely in `worker.ts` or `osvService.ts` / `nvdService.ts`). Before each upsert:

1. Look up the scope_component for `(scopeId, name=packageName)`.
2. If it exists with `dismissed_status='ignored'`, set the new sca_issue's `dismissed_status='suppressed'` + `dismissed_reason='component_ignored'`.
3. Use a single batched lookup per scan, not per-issue (build an in-memory `Set<string>` of ignored component names at the start of the OSV/NVD phase).

**SBOM filter** in `backend/src/services/sbomCurated.ts:buildCuratedSbomJsonForScope`:

- Components: already filters `dismissedStatus: "active"` — no change.
- Vulnerabilities (line ~575 and ~788): compute `excludedNames = Set<scope_components.name WHERE dismissed_status IN ('ignored', 'not_found')>` (the existing `where: { scopeId, dismissedStatus: "active" }` query already gives us the non-excluded set; subtract that name set from a separate query, OR fetch all scope_components and partition). Filter scaIssues where `packageName ∈ excludedNames` BEFORE building vulnerabilities[].

**The scan-level SBOM** (`buildCuratedSbomJson` and `emitSbomArtifact`) is **unchanged** — it's a per-scan audit snapshot of what the scan saw, not a curated scope export. Operator-ignored state doesn't belong there.

### Frontend code

**Components tab** (`frontend/src/routes/ScopeDetailPage.tsx`):

UX shuffle:
- Move the trashcan icon from the row action area into the detail-pane action row (next to the existing pencil/edit icon). Same component, same handler, different parent.
- In the row action slot the trashcan vacated, add the new Ignore button. Use the `Ban` lucide icon. Click → opens AlertDialog.
- In the ignored-only view, replace the Ignore button with a Restore button (un-ignore). The trashcan stays in the detail pane (operators may still want to hard-delete from any view).

Filter group:
- Replace the current implicit "active only" behavior with a FilterGroup matching the SCA tab pattern. Items: `["not_found", "ignored"]`. Labels: "Not found", "Ignored".
- Empty selection = backend defaults to active. One or more chips = `dismissed_statuses=<chips>` in the query.
- Hide the new chips behind a sensible default (no chips selected → standard active view).
- Style: same `colorFn` convention as SCA. Suggest: `not_found` = muted grey; `ignored` = amber.

Confirm dialog (shadcn `AlertDialog`):
- Title: `Ignore "<component-name>"?`
- Body: `This will also suppress N pending and confirmed SCA issues on this package.` (compute N client-side from the row's `linked_issue_ids.sca.length` minus any in terminal state — or just use the array length; the backend will skip terminals).
- Optional reason: a `<textarea>` for free-text. Stored on `scope_components.dismissed_reason`.
- Buttons: Cancel / Ignore.

Hooks (`frontend/src/api/queries/scopes.ts`):
- Extend `useScopeComponents` to accept `dismissed_statuses?: ScopeDismissedStatus[]`.
- Add `useIgnoreScopeComponent` and `useUnignoreScopeComponent` mutations. Invalidate the components list + SCA issues list on success.

Types:
- After backend changes land, regenerate via `npm run gen:types`.

**User manual** (`frontend/src/manual/content/components-sbom.md`):

- Update the actions table:
  - **Ignore** (new, row-level Ban icon) — soft-suppresses the component and all its SCA issues, sticky across scans. Future CVEs on the package also auto-suppress. Reversible via Restore in the Ignored view.
  - **Edit** (pencil, detail pane) — unchanged behavior.
  - **Delete** (trashcan, now in detail pane) — hard-delete; row gone but the next scan re-creates a fresh row via componentMatch. Use for duplicate/garbage rows the matcher didn't catch.
- Document the filter chips: "Not found" and "Ignored". Default view is active.
- Note the relationship between `dismissed_status='not_found'` (worker decision: evidence file missing or LLM-confirmed absent) and `dismissed_status='ignored'` (operator decision).
- Note that the scope-level SBOM artifact (`GET /api/scopes/:id/sbom-json`) naturally excludes both ignored and not-found components, plus all their vulnerabilities.

## Tests

Backend:
- `tests/scopeComponentService.test.ts` — `ignoreScopeComponent` cascades correctly, skips terminal triage states. `unignoreScopeComponent` reverses only the component_ignored cascades, not dev_tree_policy. Both work in a transaction (no partial state on error).
- New worker-cascade test — when scope_component is ignored, newly-created sca_issue rows land as suppressed/component_ignored.
- `tests/sbomCuratedScope.test.ts` (or extend existing) — ignored components excluded from `components[]`, their vulnerabilities excluded from `vulnerabilities[]`, not_found components also excluded.
- Route tests — 200 happy paths for /ignore and /unignore, 404 unknown component, 403 non-admin, 401 unauthenticated.

Frontend:
- Component-level test for the AlertDialog (confirm dialog opens, reason captured, mutation fires).
- Filter chip integration test — empty = active, chip toggle updates query.

Existing tests:
- `pnpm test` must stay green. Any test that hardcoded `'removed'` as a dismissed_status value gets updated to `'not_found'`. Grep for tests touching `dismissed_status` before assuming none.

## Version bump

0.13.0 → 0.14.0 — MINOR. Three surfaces per CLAUDE.md:
- `backend/package.json`
- `frontend/package.json` + `frontend/package-lock.json` top-level `version`
- `backend/src/routes/version.ts` `APP_VERSION`

Verify after restart: `curl -s http://localhost:8000/version | jq .app` shows `0.14.0`.

## PROGRESS.md

One entry, dated 2026-05-27, titled "M14 — ignore components + dismissed_status cleanup (v0.14.0)". Sections: What shipped / What we learned. Mention:
- The rename + value cleanup (one migration, idempotent, low blast radius).
- The new operator workflow.
- The fact that we caught the `manual_override` mis-list during design and disentangled it from `source`.

## Out of scope (explicitly)

- No UI surface for `not_found` rows beyond the new filter chip. Operators can opt into seeing them; if they want them surfaced more prominently, separate follow-up.
- No bulk-ignore (multi-select + ignore-all). One row at a time for v1.
- Scan-level SBOM artifacts stay as per-scan snapshots — operator state lives on scope, not scan.
- The LLM SBOM recheck pass still writes `not_found` autonomously (renamed from `removed`). We don't change that worker decision logic.

## Done definition

1. Migration folder committed.
2. All references to `'removed'` (as a dismissed_status value) in backend code replaced with `'not_found'`. Verified with `grep -a "'removed'" backend/src` returning only non-dismissed_status hits (e.g. LLM verdict prompt text).
3. `manual_override` no longer appears as a dismissed_status value anywhere in code (only in `source`).
4. Ignore + unignore routes working end-to-end (manual curl test passes).
5. Worker sticky cascade tested with a synthetic ignored-component fixture.
6. Scope SBOM JSON excludes ignored + not_found components AND their vulnerabilities.
7. Frontend UX shuffle complete: trashcan in detail pane, Ignore in row, FilterGroup chips visible.
8. Manual section updated and renders correctly at `/manual/components-sbom`.
9. Version 0.14.0 reflects on `GET /version`.
10. `pnpm test` green; `pnpm exec tsc --noEmit -p tsconfig.build.json` clean.
