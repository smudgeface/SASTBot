# M5 — Issue identity, scope-centric UX, Jira read-only sync, scheduling + hardening

Implementation plan for Milestone 5. Read this entire document before writing code.

## Context

M1–M4 shipped a working SAST + SCA pipeline with LLM-assisted triage, LLM-extracted CVE knowledge, reachability via ripgrep + LLM, and a scan-detail page with per-scan Findings / SAST / Components tabs. The current data model stores one finding row per scan run — so the same vulnerability in lodash across 10 scans produces 10 rows, with "decisions" (triage, suppression, soon-to-be Jira links) inherited forward via a lookup on `(scopeId, fingerprint)` at scan time. It works, but it fights every downstream goal: diffing duplicates the list, pagination fragments it, and ticket linkage has ambiguous ownership ("which of the 10 rows owns the Jira key?").

M5 corrects that. An **Issue** is the stable unit — one row per `(scope, fingerprint)` for SAST or `(scope, packageName, osvId)` for SCA — and a scan produces **detections** that update the issue's `firstSeenAt` / `lastSeenAt`. Triage, suppression, and Jira links live on the issue, so decisions never drift. Per-scan detection rows stay for audit, but they stop being the unit the user sees.

M5 also deliberately drops the "create Jira ticket from SASTBot" direction: users create tickets however they already do, link a ticket key to an issue in the SASTBot UI, and SASTBot pulls ticket metadata (status, assignee, fix versions, project) on a cadence so findings can be filtered by real ticket state.

See `docs/PROGRESS.md` for the M4 retrospective. See `CLAUDE.md` for conventions.

## Decisions already locked — do not re-debate

1. **Full schema refactor to Issue identity.** New `SastIssue` and `ScaIssue` tables carry stable identity and all user decisions. `SastFinding` and `ScanFinding` become detection events pointing at their issue. Data is backfilled from existing rows (homelab dev DB is small; no prod exists yet). The pain is up front; the payoff is clean diff / dedup / ticketing for the rest of the project.
2. **SCA identity key = `(scopeId, packageName, osvId)`.** Version is metadata, not identity. Upgrading lodash 4.17.15 → 4.17.21 resolves the issue (lastSeen stops advancing). The package version on the issue always reflects the *latest detected* version, stored as denormalized display metadata.
3. **SAST identity key = `(scopeId, fingerprint)`.** Fingerprint already excludes file path, so a finding that moves files is the same issue. Unchanged from M4's fingerprint semantics.
4. **Jira integration is read-only.** Users paste a ticket key (`SEC-123`) into SASTBot after creating the ticket in Jira. SASTBot fetches metadata and caches it in a new `JiraTicket` table. No issue creation from SASTBot in M5.
5. **Jira sync cadence:** open/in-progress tickets polled every 15 min; "Done" (terminal `statusCategory`) polled every 60 min. Both via JQL batch (one HTTP call per org per cadence). Plus an on-demand "Refresh" button per ticket and an initial fetch when the user first links a ticket.
6. **One JiraTicket can link to many Issues.** Realistic: a "fix lodash" ticket often covers several CVEs.
7. **Scheduler = BullMQ repeat job, single process, every 60 s.** Reconciles from DB on each tick — doesn't chase per-repo repeat jobs. Minimum per-repo cadence is 5 minutes (enforced at save). Jira sync ticks live in the same scheduler process but are separate jobId'd repeat jobs.
8. **Scan detail page is demoted to an audit/debug view.** Primary UX becomes scope-centric: scopes → current issues. The scan detail route stays alive (reachable from a "Recent scans" drawer on the scope page) so we can still inspect what a specific run produced.
9. **Pagination is offset-based** (`page`, `page_size`), max 500. Applies to all list endpoints. Default 100.
10. **Rate limit only `/auth/login` + `/auth/logout`** via `@fastify/rate-limit` with Redis backend. 10/min per IP. Everything else is authenticated and human-paced — broaden later when we have abuse data.
11. **Migration is a backfill, not a wipe.** Even though we're pre-production, writing the backfill script forces us to prove the model is expressible from current data, which is the same exercise needed to ship to real environments later.

## Conceptual model

```
Repo ──< ScanScope ──< ScanRun ──< (detections: SastFinding, ScanFinding, SbomComponent)
                  ╰──< SastIssue ──> JiraTicket?   (decisions + stable identity)
                  ╰──< ScaIssue  ──> JiraTicket?

 Issue = (scope, stable-key)          Decision fields live here
 Detection = (scan, issue, metadata)  Per-run evidence lives here
 JiraTicket = (orgId, issueKey)       Synced cache of remote Jira state
```

Every scan:
1. Produces detection rows (unchanged from M4).
2. Upserts Issue rows for each detection, advancing `lastSeenAt` and `lastSeenScanRunId`.
3. Stamps `firstSeenAt` on issues created for the first time.
4. Runs LLM triage only on `SastIssue` rows where `triageStatus = 'pending'` AND the issue was detected in this scan.
5. Runs reachability only on `ScaIssue` rows that satisfy the severity threshold AND were detected in this scan. The verdict overwrites the issue's latest reachability fields.
6. Issues not detected in this scan are *not* deleted — their `lastSeenAt` simply stays put, and the scope view surfaces them as "resolved" (detected previously, absent in latest scan).

## Schema changes

### New model: `SastIssue`

```prisma
model SastIssue {
  id                   String    @id @default(uuid()) @db.Uuid
  orgId                String?   @map("org_id") @db.Uuid
  scopeId              String    @map("scope_id") @db.Uuid
  fingerprint          String
  // Decisions (stable, span all scans)
  triageStatus         String    @default("pending") @map("triage_status")
  // "pending" | "confirmed" | "false_positive" | "suppressed" | "error"
  triageConfidence     Float?    @map("triage_confidence")
  triageReasoning      String?   @map("triage_reasoning")
  triageModel          String?   @map("triage_model")
  triageInputTokens    Int?      @map("triage_input_tokens")
  triageOutputTokens   Int?      @map("triage_output_tokens")
  suppressedAt         DateTime? @map("suppressed_at") @db.Timestamptz(6)
  suppressedByUserId   String?   @map("suppressed_by_user_id") @db.Uuid
  suppressedReason     String?   @map("suppressed_reason")
  notes                String?
  jiraTicketId         String?   @map("jira_ticket_id") @db.Uuid
  // Denorm from latest detection (so the scope view doesn't need a join)
  latestRuleId         String    @map("latest_rule_id")
  latestRuleName       String?   @map("latest_rule_name")
  latestRuleMessage    String?   @map("latest_rule_message")
  latestSeverity       String    @default("info") @map("latest_severity")
  latestCweIds         String[]  @default([]) @map("latest_cwe_ids")
  latestFilePath       String    @map("latest_file_path")
  latestStartLine      Int       @map("latest_start_line")
  latestSnippet        String?   @map("latest_snippet")
  // Lifecycle
  firstSeenAt          DateTime  @default(now()) @map("first_seen_at") @db.Timestamptz(6)
  firstSeenScanRunId   String    @map("first_seen_scan_run_id") @db.Uuid
  lastSeenAt           DateTime  @default(now()) @map("last_seen_at") @db.Timestamptz(6)
  lastSeenScanRunId    String    @map("last_seen_scan_run_id") @db.Uuid
  createdAt            DateTime  @default(now()) @map("created_at") @db.Timestamptz(6)
  updatedAt            DateTime  @updatedAt @map("updated_at") @db.Timestamptz(6)

  org        Org?        @relation(fields: [orgId], references: [id], onDelete: SetNull)
  scope      ScanScope   @relation(fields: [scopeId], references: [id], onDelete: Cascade)
  jiraTicket JiraTicket? @relation(fields: [jiraTicketId], references: [id], onDelete: SetNull)
  detections SastFinding[]

  @@unique([scopeId, fingerprint], name: "uq_sast_issues_scope_fingerprint")
  @@index([scopeId, triageStatus])
  @@index([scopeId, latestSeverity])
  @@index([jiraTicketId])
  @@map("sast_issues")
}
```

### New model: `ScaIssue`

```prisma
model ScaIssue {
  id                        String    @id @default(uuid()) @db.Uuid
  orgId                     String?   @map("org_id") @db.Uuid
  scopeId                   String    @map("scope_id") @db.Uuid
  // Identity: (packageName, osvId). osvId may be a synthetic id for
  // deprecated / eol findings (e.g. "DEPRECATED:lodash", "EOL:node:12").
  packageName               String    @map("package_name")
  osvId                     String    @map("osv_id")
  // Decisions
  dismissedStatus           String    @default("active") @map("dismissed_status")
  // "active" | "acknowledged" | "wont_fix" | "false_positive"
  dismissedAt               DateTime? @map("dismissed_at") @db.Timestamptz(6)
  dismissedByUserId         String?   @map("dismissed_by_user_id") @db.Uuid
  dismissedReason           String?   @map("dismissed_reason")
  notes                     String?
  jiraTicketId              String?   @map("jira_ticket_id") @db.Uuid
  // Denorm from latest detection
  latestPackageVersion      String?   @map("latest_package_version")
  latestEcosystem           String?   @map("latest_ecosystem")
  latestComponentScope      String?   @map("latest_component_scope") // "required" | "optional"
  latestFindingType         String    @default("cve") @map("latest_finding_type")
  latestCveId               String?   @map("latest_cve_id")
  latestSeverity            String    @default("unknown") @map("latest_severity")
  latestCvssScore           Float?    @map("latest_cvss_score")
  latestCvssVector          String?   @map("latest_cvss_vector")
  latestSummary             String?   @map("latest_summary")
  latestAliases             String[]  @default([]) @map("latest_aliases")
  latestActivelyExploited   Boolean   @default(false) @map("latest_actively_exploited")
  latestEolDate             DateTime? @map("latest_eol_date") @db.Timestamptz(6)
  latestHasFix              Boolean   @default(false) @map("latest_has_fix")
  // Reachability (latest assessment; overwritten each scan the issue is detected in)
  confirmedReachable          Boolean   @default(false) @map("confirmed_reachable")
  reachableViaSastFingerprint String?   @map("reachable_via_sast_fingerprint")
  reachableReasoning          String?   @map("reachable_reasoning")
  reachableAssessedAt         DateTime? @map("reachable_assessed_at") @db.Timestamptz(6)
  reachableModel              String?   @map("reachable_model")
  reachableAtScanRunId        String?   @map("reachable_at_scan_run_id") @db.Uuid
  // Lifecycle
  firstSeenAt          DateTime @default(now()) @map("first_seen_at") @db.Timestamptz(6)
  firstSeenScanRunId   String   @map("first_seen_scan_run_id") @db.Uuid
  lastSeenAt           DateTime @default(now()) @map("last_seen_at") @db.Timestamptz(6)
  lastSeenScanRunId    String   @map("last_seen_scan_run_id") @db.Uuid
  createdAt            DateTime @default(now()) @map("created_at") @db.Timestamptz(6)
  updatedAt            DateTime @updatedAt @map("updated_at") @db.Timestamptz(6)

  org        Org?        @relation(fields: [orgId], references: [id], onDelete: SetNull)
  scope      ScanScope   @relation(fields: [scopeId], references: [id], onDelete: Cascade)
  jiraTicket JiraTicket? @relation(fields: [jiraTicketId], references: [id], onDelete: SetNull)
  detections ScanFinding[]

  @@unique([scopeId, packageName, osvId], name: "uq_sca_issues_scope_pkg_osv")
  @@index([scopeId, latestSeverity])
  @@index([scopeId, dismissedStatus])
  @@index([jiraTicketId])
  @@map("sca_issues")
}
```

### New model: `JiraTicket`

```prisma
model JiraTicket {
  id             String    @id @default(uuid()) @db.Uuid
  orgId          String?   @map("org_id") @db.Uuid
  issueKey       String    @map("issue_key")          // "SEC-123"
  issueId        String?   @map("issue_id")           // Jira internal id
  projectKey     String?   @map("project_key")
  projectName    String?   @map("project_name")
  summary        String?
  status         String?                              // "In Progress"
  statusCategory String?   @map("status_category")    // "new" | "indeterminate" | "done"
  assigneeName   String?   @map("assignee_name")
  assigneeEmail  String?   @map("assignee_email")
  fixVersions    String[]  @default([]) @map("fix_versions")
  issueType      String?   @map("issue_type")
  url            String?
  resolvedAt     DateTime? @map("resolved_at") @db.Timestamptz(6)
  lastSyncedAt   DateTime? @map("last_synced_at") @db.Timestamptz(6)
  syncError      String?   @map("sync_error")
  linkedByUserId String?   @map("linked_by_user_id") @db.Uuid
  createdAt      DateTime  @default(now()) @map("created_at") @db.Timestamptz(6)

  org        Org?         @relation(fields: [orgId], references: [id], onDelete: SetNull)
  sastIssues SastIssue[]
  scaIssues  ScaIssue[]

  @@unique([orgId, issueKey], name: "uq_jira_tickets_org_key")
  @@index([orgId, statusCategory])
  @@map("jira_tickets")
}
```

### Additions to existing models

```prisma
model Repo {
  // +
  lastScheduledScanAt DateTime? @map("last_scheduled_scan_at") @db.Timestamptz(6)

  @@index([isActive, scheduleCron])
}

model ScanScope {
  // +
  lastScanRunId       String?   @map("last_scan_run_id") @db.Uuid
  lastScanCompletedAt DateTime? @map("last_scan_completed_at") @db.Timestamptz(6)
  sastIssues SastIssue[]
  scaIssues  ScaIssue[]
}

model ScanRun {
  @@index([scopeId, createdAt(sort: Desc)])
  @@index([repoId, createdAt(sort: Desc)])
}

model SastFinding {
  // + (detection pointer)
  issueId String @map("issue_id") @db.Uuid
  issue   SastIssue @relation(fields: [issueId], references: [id], onDelete: Cascade)

  // REMOVE these — they migrate to SastIssue:
  //   triageStatus, triageConfidence, triageReasoning, triageModel,
  //   triageInputTokens, triageOutputTokens,
  //   suppressedAt, suppressedByUserId, suppressedReason
}

model ScanFinding {
  // + (detection pointer)
  issueId String @map("issue_id") @db.Uuid
  issue   ScaIssue @relation(fields: [issueId], references: [id], onDelete: Cascade)

  // REMOVE (migrate to ScaIssue):
  //   confirmedReachable, reachableViaSastFingerprint, reachableReasoning,
  //   reachableAssessedAt, reachableModel
}

model AppSettings {
  // + (Jira sync needs email for Basic auth)
  jiraEmail String? @map("jira_email")
  // jira_base_url, jira_credential_id already exist. jira_project_key NOT
  // needed in read-only mode — the project name comes from the ticket itself.
}

model Org {
  // +
  jiraTickets JiraTicket[]
  sastIssues  SastIssue[]
  scaIssues   ScaIssue[]
}
```

**Migration name:** `m5_issue_identity_and_jira`. Two steps in one migration:

1. DDL: create `sast_issues`, `sca_issues`, `jira_tickets` tables; add new columns on `repos`, `scan_scopes`, `scan_runs`, `scan_findings`, `sast_findings`, `app_settings`; new indexes.
2. Data backfill (run in the same migration, transactional):
   - For every distinct `(scopeId, fingerprint)` across existing `sast_findings`: insert a `sast_issues` row. `firstSeenAt` = `MIN(createdAt)`, `lastSeenAt` = `MAX(createdAt)`. Triage fields, denorm fields come from the row with the newest `createdAt`. Associated `scanRunId` links become `firstSeenScanRunId` / `lastSeenScanRunId`.
   - For every distinct `(scopeId, packageName, osvId)` across `scan_findings` joined with `sbom_components` joined with `scan_runs`: insert a `sca_issues` row. Same pattern. Reachability fields from the newest detection.
   - Update each detection row's `issueId` foreign key.
   - Drop the migrated columns from `sast_findings` / `scan_findings` once FK population is complete.

The backfill runs once, inside the migration transaction. Prisma `migrate dev` handles this fine — wrap the SQL in `BEGIN; ... COMMIT;` (which is implicit for a single migration file in Postgres).

## Phases

Each phase has a testing gate. Do not advance until the gate passes. Commit at each gate.

### Phase 5a — Schema refactor + backfill + Issue-centric backend (~2 days)

**Schema + migration:**
- Apply `m5_issue_identity_and_jira` (DDL + backfill).
- Dry-run the backfill on a copy of the current dev DB first: export with `pg_dump`, restore to a sibling DB, apply the migration, verify counts (`sast_issues.count == DISTINCT(scopeId, fingerprint).count`, `sca_issues.count == DISTINCT(scopeId, packageName, osvId).count`).
- Then apply for real.

**New service `backend/src/services/issueService.ts`** — upsert helpers used by the worker:

```ts
async function upsertSastIssueFromDetection(
  tx: Tx,
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  detection: {
    fingerprint, ruleId, ruleName, ruleMessage, severity, cweIds,
    filePath, startLine, snippet
  }
): Promise<{ issue: SastIssue, isNew: boolean }>
  // Upsert on (scopeId, fingerprint). On conflict update:
  //   lastSeenAt = now(), lastSeenScanRunId = scanRunId,
  //   latest* fields overwritten.
  // On insert: firstSeenAt + firstSeenScanRunId also set.
  // Return whether this is a brand-new issue so the worker knows to triage it.

async function upsertScaIssueFromDetection(
  tx: Tx,
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  component: SbomComponent,
  detection: {
    osvId, cveId, findingType, severity, cvssScore, cvssVector,
    summary, aliases, activelyExploited, eolDate, hasFix
  }
): Promise<{ issue: ScaIssue, isNew: boolean }>
```

**Worker refactor (`backend/src/worker.ts`):**

Replace the existing "insert SastFinding then triage + inherit" flow with:

```ts
// SAST
const sarifInputs = parseSarif(sarif);
for (const input of sarifInputs) {
  const { issue, isNew } = await upsertSastIssueFromDetection(tx, scanRunId, scopeId, orgId, input);
  await tx.sastFinding.create({ data: { ...detectionFields, issueId: issue.id, scanRunId, scopeId, orgId } });
}
// Then: run LLM triage on issues where triageStatus='pending' AND lastSeenScanRunId === scanRunId

// SCA
for (const component of components) {
  const osvFindings = await queryOsv(component);
  for (const f of osvFindings) {
    const { issue, isNew } = await upsertScaIssueFromDetection(tx, scanRunId, scopeId, orgId, component, f);
    await tx.scanFinding.create({ data: { ...detectionFields, issueId: issue.id, scanRunId, componentId: component.id } });
  }
}
// Then: reachability on ScaIssues where severity >= threshold AND lastSeenScanRunId === scanRunId
```

**Triage service refactor (`llmTriageService.ts`):**
- Query changes from "SastFinding WHERE triageStatus='pending'" to "SastIssue WHERE triageStatus='pending' AND lastSeenScanRunId = ?".
- Result is written to the SastIssue row, not the SastFinding.
- The "opportunistic SCA reachability hint" path now updates a ScaIssue directly (by matching against `scaIssue.id` passed in via the prompt) rather than a ScanFinding.
- Triage inheritance code (`inheritTriage`) **deleted** — no longer needed. Triage persistence is inherent to the Issue model.

**Reachability service refactor (`reachabilityService.ts`):**
- Query changes from "ScanFinding WHERE cvssScore >= threshold" to "ScaIssue WHERE (cvssScore OR severity-string) AND lastSeenScanRunId = ?".
- Verdict is written to the ScaIssue.

**Scope summary denorm:**
After every scan, update the scope:

```ts
await tx.scanScope.update({
  where: { id: scopeId },
  data: { lastScanRunId: scanRunId, lastScanCompletedAt: new Date() },
});
```

**New routes (`backend/src/routes/scopes.ts` — new file):**

```
GET /scopes
  query: repo_id?, include_inactive?
  response: [{ id, repo_id, repo_name, repo_branch, path, display_name,
              last_scan_run_id, last_scan_completed_at,
              active_sast_issue_count, active_sca_issue_count,
              critical_count, high_count,
              pending_triage_count }]

GET /scopes/:id
  response: full ScopeDetail

GET /scopes/:id/sast-issues
  query (paginated):
    page, page_size, severity?, triage_status?, has_jira_ticket?,
    jira_status_category?, seen_since_last_scan?, include_resolved?
  response: PaginatedOf(SastIssueOut)

GET /scopes/:id/sca-issues
  query (paginated):
    page, page_size, severity?, finding_type?, dismissed_status?,
    has_jira_ticket?, jira_status_category?, reachable?, has_fix?,
    hide_dev?, seen_since_last_scan?, include_resolved?
  response: PaginatedOf(ScaIssueOut)

GET /scopes/:id/components
  query (paginated): page, page_size, has_findings?
  response: PaginatedOf(ComponentOut) — reads from the most recent scan run's components

GET /scopes/:id/scans
  query: limit (max 100, default 20)
  response: [ScanRunSummary] — for the "recent scans" drawer
```

**New routes for issue actions** (scoped by issue id, not scan id):

```
POST /sast-issues/:id/triage
  admin-only
  body: { status: confirmed|false_positive|suppressed|pending, reason?: string }
  response: SastIssueOut

POST /sca-issues/:id/dismiss
  admin-only
  body: { status: active|acknowledged|wont_fix|false_positive, reason?: string }
  response: ScaIssueOut

PUT /sast-issues/:id/notes       — body: { notes: string } — any authed user
PUT /sca-issues/:id/notes        — body: { notes: string } — any authed user
```

The old per-scan triage route (`POST /scans/:id/sast-findings/:fid/triage`) stays in the codebase but becomes a thin redirect: look up the detection's `issueId`, forward to the issue route. Marked deprecated in OpenAPI. Delete in a later milestone.

**Schemas (`backend/src/schemas.ts`):**
- New: `SastIssueOutSchema`, `SastIssueListSchema`, `ScaIssueOutSchema`, `ScaIssueListSchema`, `ScopeOutSchema`, `ScopeListSchema`, `ScopeDetailSchema`, `PaginationQuerySchema`, `PaginatedSchema` factory.
- Update existing finding schemas: remove triage / reachability / Jira fields (now on the issue). Add `issue_id`.
- `AppSettingsOutSchema`/`AppSettingsUpdateSchema`: add `jira_email`.

**Mappers (`backend/src/services/mappers.ts`):**
- New: `sastIssueToOut`, `scaIssueToOut`, `scopeToOut`, `jiraTicketToOut`, `paginate` helper.
- Update: `scanFindingToOut`, `sastFindingToOut` lose the migrated fields but gain `issue_id` (and optionally include the whole issue via `include` when we want denorm).

**Gate 5a:**
- [ ] Migration applies on a fresh DB AND on a backfill-tested copy of the current dev DB. Counts match: `COUNT(sast_issues)` = distinct `(scopeId, fingerprint)` in pre-migration `sast_findings`; same for SCA.
- [ ] `pnpm typecheck` and `pnpm test` pass.
- [ ] Trigger a scan against the existing test-vuln-repo. Issues are upserted, not inserted duplicatively (re-scan → issue count unchanged, `lastSeenAt` advances).
- [ ] Triage an SAST issue via `POST /sast-issues/:id/triage` → status persists on issue. Re-scan → status still set (no inheritance needed).
- [ ] Resolve a vulnerability in the test repo (remove the lodash call), re-scan → ScaIssue `lastSeenAt` does not advance for that issue, issue appears in the "resolved" filter.
- [ ] Reintroduce the vuln → `lastSeenAt` advances again (same row, no duplicate). Triage state preserved.
- [ ] `GET /scopes/:id/sast-issues?include_resolved=false` hides resolved issues. `?include_resolved=true` includes them.
- [ ] Paginated response shape verified (`{ items, total, page, page_size }`).

### Phase 5b — Scope-centric UI (~1.5 days)

**New top-level routes / pages:**
- `/scopes` — the new landing page. Hierarchical table: `Repo name · Branch · Path · Last scan · Active critical/high · Pending triage · Resolved count`. Click a row → scope detail.
- `/scopes/:id` — scope detail page. Three tabs (same content as current scan detail, but pulled from the *scope*, not a scan):
  - **SCA Issues** — paginated list, filter bar, expand rows.
  - **SAST Issues** — same.
  - **Components** — most recent scan's SBOM components.
  - Sidebar or drawer: **Recent scans** (link-only list, with a "View this scan" button that drops you onto the demoted scan-detail page).
- `/scans/:id` — retained but demoted. No longer in the main nav. Tabs become "Raw findings" / "Raw SAST detections" / "Raw components" — explicitly labeled as scan-specific audit data.
- `/scans` — the scans list stays, but is labeled "Scan runs (audit)". Trigger scans from here and from the scope page.

**Filter bar additions on scope issue lists (new filters vs M4):**
- `has_jira_ticket`: Any / Yes / No
- `jira_status_category`: Any / To Do / In Progress / Done
- `jira_fix_version`: multi-select of distinct fix versions across the org's linked tickets (populated from a new `GET /admin/jira-tickets/fix-versions` endpoint)
- `seen_since_last_scan`: Any / New / Unchanged / Resolved
  - "New" = `firstSeenAt >= scope.lastScanCompletedAt`
  - "Unchanged" = detected in latest scan AND not new
  - "Resolved" = `lastSeenAt < scope.lastScanCompletedAt`
- Keep existing filters: severity, type (CVE/EOL/Deprecated), reachable, has-fix, hide-dev

**Navigation:**
- Top nav: **Scopes** (primary) | **Repos** | **Scans (audit)** | **Settings**
- Dashboard: "Scopes at risk" card with top 5 scopes by `critical + high` count; "Recent scans" card; "Pending triage" card.

**Decisions surface on issue rows:**
- Triage chip (unchanged semantics)
- ⚡ Reachable / DEV / Has-fix badges (unchanged)
- Jira chip: `SEC-123 · In Progress · @alice · v2.4.0` — click to open in Jira
- When no ticket: a small "+ Link Jira ticket" action in the expanded row

**Breaking-change churn:**
- `frontend/src/api/queries/scans.ts` gains new hooks (`useScope`, `useScopeSastIssues`, etc.) and the old `useSastFindings` etc. are rewritten on top of the old /scans endpoints (retained for the demoted scan detail page).
- Regenerate `frontend/src/api/schema.d.ts` at the end of 5b; commit in a single sweep.

**Gate 5b:**
- [ ] `/scopes` loads, shows all scopes with accurate counts.
- [ ] `/scopes/:id` shows three tabs; triage/dismiss actions work (admin only, server-enforced).
- [ ] Filter bar: "New this scan" correctly isolates newly-seen issues after re-scan.
- [ ] Filter bar: "Resolved" shows issues whose `lastSeenAt` trails the latest scan.
- [ ] Scan detail page still reachable via the "Recent scans" drawer on the scope page.
- [ ] Dashboard cards populate from the scope endpoints.
- [ ] Visual QA: the `/scopes` page renders for a dev with 3 repos × 2 scopes × ~50 issues each without jank.

### Phase 5c — Jira read-only integration (~1.5 days)

**New service `backend/src/services/jiraClient.ts`:**

```ts
interface JiraConfig {
  baseUrl: string;       // https://acme.atlassian.net (no trailing slash)
  email: string;
  apiToken: string;
}

interface JiraTicketMeta {
  issueId: string;
  issueKey: string;
  projectKey: string | null;
  projectName: string | null;
  summary: string | null;
  status: string | null;
  statusCategory: "new" | "indeterminate" | "done" | null;
  assigneeName: string | null;
  assigneeEmail: string | null;
  fixVersions: string[];
  issueType: string | null;
  resolvedAt: Date | null;
  url: string;
}

async function loadJiraConfig(orgId, tx?): Promise<JiraConfig | null>;
async function fetchTicket(cfg: JiraConfig, issueKey: string): Promise<JiraTicketMeta>;
async function fetchTicketsBatch(cfg: JiraConfig, issueKeys: string[]): Promise<Map<string, JiraTicketMeta | { error: string }>>;
  // Single POST to /rest/api/3/search/jql with JQL "key in (K1, K2, ...)"
  // Batch size ≤ 50 keys per request. Caller chunks.
  // Response includes only keys that exist + user has permission to see.
  // Missing keys in response → mark with error "Ticket not found or inaccessible".

async function checkJiraConnection(cfg: JiraConfig): Promise<{ ok: true, accountName: string } | { ok: false, error: string }>;
  // GET /rest/api/3/myself → returns { displayName, emailAddress, ... }
```

All requests use `Authorization: Basic base64(email:apiToken)`. 10 s timeout. Retry once on 5xx.

**New service `backend/src/services/jiraTicketService.ts`:**

```ts
async function linkSastIssueToTicket(orgId, sastIssueId, issueKey, userId): Promise<JiraTicket>
  // 1. Validate issueKey format ^[A-Z][A-Z0-9]+-\d+$ (reject otherwise, 400)
  // 2. Load or create JiraTicket row for (orgId, issueKey)
  // 3. If row is brand new: immediately fetch metadata (sync call, fail loudly if config missing)
  // 4. Set sastIssue.jiraTicketId
  // 5. Return the JiraTicket

async function unlinkSastIssue(orgId, sastIssueId): Promise<void>
  // Clear sastIssue.jiraTicketId. Leave the JiraTicket row alone (other issues may reference it).

// Mirror for SCA.

async function refreshTicket(orgId, issueKey): Promise<JiraTicket>
  // On-demand sync. Called by the UI Refresh button.

async function reconcileJiraSync(now: Date): Promise<{ synced: number; errors: number }>
  // Scheduler tick. Pulled from the scheduler in 5d.
  // 1. For each org with Jira config:
  //    - Open tickets: WHERE statusCategory != 'done' AND (lastSyncedAt IS NULL OR lastSyncedAt < now - 15m)
  //    - Done tickets: WHERE statusCategory = 'done' AND lastSyncedAt < now - 60m
  // 2. Chunk issueKeys into batches of 50.
  // 3. For each batch call fetchTicketsBatch.
  // 4. Update JiraTicket rows with metadata + lastSyncedAt. On missing key → mark syncError, bump lastSyncedAt anyway (so it rate-limits retries).
```

**Routes:**

```
POST   /sast-issues/:id/jira-ticket    body: { issue_key } → JiraTicketOut
DELETE /sast-issues/:id/jira-ticket    → 204
POST   /sca-issues/:id/jira-ticket     body: { issue_key } → JiraTicketOut
DELETE /sca-issues/:id/jira-ticket     → 204

POST   /admin/jira-tickets/:key/refresh    → JiraTicketOut (immediate fetch)
GET    /admin/jira-tickets                 query: (page, page_size, status_category?, has_error?) → PaginatedOf(JiraTicketOut)
GET    /admin/jira-tickets/fix-versions    → string[]   (distinct fixVersions across org's tickets; for filter dropdown)

POST   /admin/settings/jira/check          → { success, account_name, error? }
```

**Settings UI:**
- Jira card: `jira_base_url`, `jira_email` (new), `jira_credential` (existing `jira_token` kind). "Check connection" button → hits `/admin/settings/jira/check` → shows "Connected as {accountName}" or error.
- Remove the `jira_project_key` / `jira_default_issue_type` / `jira_labels` fields that existed in the earlier draft of this plan. Read-only mode doesn't need them.

**Issue-row UI (shared across SAST + SCA):**
- No ticket linked:
  - Inline `+ Link Jira ticket` in expanded row → opens a small popover with a text input + "Link" button
  - After submit: synchronous fetch; if the key doesn't exist in Jira, popover shows "Jira returned: ticket not found" and the link is rejected (don't create an orphaned JiraTicket row with an error)
- Ticket linked:
  - Compact chip: `SEC-123 · ⏳ In Progress · @Alice Smith · v2.4.0` (fixVersions joined with commas, truncated with tooltip at 3+ versions)
  - Chip menu: `Open in Jira` (external link) / `Refresh now` / `Unlink`
  - If `syncError` set: chip turns amber with an icon, tooltip shows the error + lastSyncedAt

**Filter integration:**
- `has_jira_ticket` toggle in filter bar
- `jira_status_category` multi-select (To Do / In Progress / Done)
- `jira_fix_version` multi-select, populated from `/admin/jira-tickets/fix-versions`

**Scheduler addition (implemented in Phase 5d but declared here):**
- A separate repeat job in the scheduler queue with `jobId: "sastbot-jira-sync"` every 5 minutes (the tick itself is cheap; the service decides per-ticket whether to actually hit Jira).

**Gate 5c:**
- [ ] Settings: save Jira base URL + email + credential. "Check connection" returns `Connected as <name>`.
- [ ] Connection check with bad token → clear 401 error message.
- [ ] Connection check with wrong email → clear 401.
- [ ] Link a valid ticket key to a SAST issue → chip appears with status, assignee, fixVersions.
- [ ] Link an invalid/nonexistent key → popover shows error, no JiraTicket row is left behind.
- [ ] Click "Refresh now" on a linked ticket → fresh metadata pulled; `lastSyncedAt` advances.
- [ ] Filter "Has Jira ticket: No" hides issues that are linked.
- [ ] Filter by `jira_status_category=done` shows only issues whose ticket is in a Done category.
- [ ] Filter by `jira_fix_version=v2.4.0` shows only issues whose ticket's fixVersions include that value.
- [ ] Change the ticket's status/assignee/fixVersion in Jira → within ~15 min, the SASTBot chip reflects the change (wait or force the next scheduler tick in testing).
- [ ] Unlink a ticket → the JiraTicket row persists (other issues may still reference it), but the issue's `jiraTicketId` is null.

### Phase 5d — Scheduled scans + scheduler process (~1 day)

Unchanged conceptually from the original M5 plan. Key points:

**New queue `backend/src/queue/schedulerQueue.ts`** with `SCHEDULER_QUEUE_NAME = "scheduler"`.

**New worker process `backend/src/scheduler.ts`:**
- Ensures three repeat jobs exist on startup (dedup'd via jobId):
  - `sastbot-scan-tick` — `every: 60_000` → runs `reconcileSchedules()` from `schedulerService.ts`
  - `sastbot-jira-sync` — `every: 300_000` → runs `reconcileJiraSync()` from `jiraTicketService.ts`
  - Optional (future): `sastbot-cleanup` for orphaned JiraTickets etc. Skip in M5.
- Single worker on `SCHEDULER_QUEUE_NAME` dispatches based on job name.

**Dependency:** add `cron-parser` (~30 KB).

**Scan reconciliation (`schedulerService.ts`):**

```ts
async function reconcileSchedules(now: Date) {
  // 1. SELECT * FROM repos WHERE schedule_cron IS NOT NULL AND is_active
  // 2. For each repo:
  //    a. const next = nextFireAt(repo.scheduleCron, repo.lastScheduledScanAt ?? repo.createdAt)
  //    b. if next > now: skip
  //    c. debounce: if any scan on this repo is pending/running: skip with warning
  //    d. triggerScan({ repoId, triggeredBy: 'schedule', ... })
  //       (triggerScan will set repo.lastScheduledScanAt at the end)
  // 3. Log { considered, triggered, skipped, debounced }
}
```

**Validation on save (`adminRepos.ts`):**
- Parse with `cron-parser` (invalid → 400).
- Compute next 3 fire times; if any gap < 5 minutes → 400 "Schedule fires more often than every 5 minutes".

**Frontend:**
- Repo create/edit dialog:
  - Preset dropdown (No schedule / Every hour / Every 6 hours / Daily 02:00 / Weekly Mon 06:00 / Custom)
  - Text input for custom
  - Live preview "Next 3 runs (UTC):" computed client-side with cron-parser (already in the frontend bundle or add as a small dep)
- Repos list: schedule column with human-readable label ("Daily 02:00") or raw cron.
- Scans list: `triggered_by` rendered as a chip.

**Compose:**
```yaml
scheduler:
  image: sastbot-backend
  command: pnpm tsx src/scheduler.ts   # node dist/scheduler.js in prod
  depends_on: [postgres, redis]
  environment: [ ...same as worker... ]
  volumes: [ ...same hot-reload as worker... ]
  restart: unless-stopped
```

**Gate 5d:**
- [ ] Set a repo's cron to `*/5 * * * *` → scheduled scan appears within 5 minutes with `triggered_by='schedule'`.
- [ ] Restart the scheduler → no duplicate repeat jobs (verify via `redis-cli KEYS 'bull:scheduler:*'`).
- [ ] Cron `* * * * *` rejected with clear error.
- [ ] Invalid cron string rejected with parser error surfaced in UI.
- [ ] Disable a repo (`is_active=false`) → scheduler skips it.
- [ ] Force a Jira sync tick while a linked ticket has stale data → ticket refreshes, `lastSyncedAt` advances.
- [ ] Jira sync tick with no Jira config → no-op, no errors in logs.
- [ ] UI: preset dropdown populates field; "Next 3 runs" preview updates live.

### Phase 5e — Operational hardening (~1 day)

**Rate limiting:**
- Add `@fastify/rate-limit` with Redis backend.
- Register globally with `global: false` (opt-in per route).
- Apply `max: 10, timeWindow: "1 minute"` to `/auth/login` and `/auth/logout`.
- `skipOnError: true` so Redis downtime doesn't take down auth.
- Frontend: on 429, login form shows "Too many attempts, please wait {Retry-After} seconds".

**Pagination:**
- Already built into 5a's new endpoints. This phase audits the remaining endpoints:
  - `/scans` (list scan runs) → paginate, default 50 / max 200.
  - `/admin/repos`, `/admin/credentials` → paginate, default 100 / max 500.
  - `/admin/jira-tickets` → paginated (done in 5c).
- Frontend: pager component (`< 1 2 3 ... 7 >`) on every list.

**Indexes:**
- All four declared in the schema section.
- After migration, run `EXPLAIN ANALYZE` on:
  - `SELECT * FROM sast_issues WHERE scope_id = $1 AND triage_status = 'pending' ORDER BY latest_severity;`
  - `SELECT * FROM sca_issues WHERE scope_id = $1 AND dismissed_status = 'active' ORDER BY latest_severity;`
  - `SELECT * FROM scan_runs WHERE scope_id = $1 ORDER BY created_at DESC LIMIT 20;`
  - `SELECT * FROM repos WHERE is_active = true AND schedule_cron IS NOT NULL;`
- Confirm index scans (not seq scans) and capture the plans in `docs/PROGRESS.md` M5 entry.

**Worker concurrency:**
- Add env var `SCAN_WORKER_CONCURRENCY`, default 2.
- `Worker` constructor gets `{ concurrency: Number(process.env.SCAN_WORKER_CONCURRENCY ?? "2") }`.
- Cap at 4 (LiteLLM has shared rate limits; overshoot bites).

**Gate 5e:**
- [ ] 15 rapid `POST /auth/login` from one IP → 11th returns 429 with `Retry-After` header.
- [ ] Kill Redis → login still works; logs a warning; rate limit temporarily disabled.
- [ ] Paginated list on `/scopes/:id/sast-issues?page=2&page_size=50` returns items 51–100, accurate total.
- [ ] `EXPLAIN ANALYZE` for the four queries shows index usage; plans captured in PROGRESS.md.
- [ ] `SCAN_WORKER_CONCURRENCY=2`: trigger 3 back-to-back scans → first 2 run in parallel (check interleaved logs), 3rd queued.
- [ ] `page_size=1000` request returns 400 (validator rejects > 500).

### Phase 5f — Verification + docs (~0.5 day)

**End-to-end scenarios (manual, documented):**

1. Fresh start: clone repo, configure Jira (base URL + email + token), Check connection → success.
2. Add test-vuln-repo, schedule every 5 min. Wait → scan fires automatically.
3. Open `/scopes/<id>` → SCA tab shows 13 issues, SAST tab shows 2 issues, all with correct severity.
4. Mark one SAST issue as FP → triage chip turns green.
5. Link one SCA issue (lodash CVE) to a real Jira ticket → chip shows status / assignee / fixVersion within seconds of linking.
6. Modify the ticket in Jira (change status) → force a refresh on the chip → status updates.
7. Remove the lodash call, push, wait for next scheduled scan → issue appears under "Resolved" filter; re-add → `lastSeenAt` advances on the same row; triage decision (if any) preserved.
8. Filter bar: `jira_status_category=In Progress` hides resolved tickets; `has_jira_ticket=No` shows unticketed issues only.
9. Hammer `/auth/login` → blocked after 10 attempts.
10. Big scope with 100 historical scans: `GET /scopes/:id` returns in < 200 ms (check `lastScanRunId` denorm hits, not a live aggregation).

**Documentation updates:**

- `docs/PROGRESS.md` M5 entry — "What shipped" + "What we learned", include EXPLAIN plans, explicitly note the Issue-identity refactor as an architectural shift worth referencing in the final presentation.
- `docs/OPERATIONS.md` new sections:
  - "Scheduled scans" — cron setup, troubleshooting (scheduler logs via `docker compose logs scheduler`), repeat-job jobIds for debugging.
  - "Jira integration" — configure email + token; read-only model explanation; sync cadence; troubleshooting common errors (401 bad email/token, 403 missing permission on the ticket, 404 bad key, sync errors surfaced on the chip).
  - "Rate limiting" — thresholds + how to tune via env vars if needed.
  - "Issue identity" — one-paragraph explainer of Issue vs Detection for new operators reading the codebase.
- `CLAUDE.md` — update the repo-layout and services tree. Note the demotion of the scan detail page.
- `README.md` — update feature list (scope-centric views, scheduled scans, Jira sync).

## Pitfalls — read before each phase

1. **Backfill idempotency.** The backfill is run inside the migration transaction, so it must produce the same result regardless of order. Use `INSERT ... ON CONFLICT DO NOTHING` + a second `UPDATE ... FROM (SELECT DISTINCT ON ... ORDER BY createdAt DESC)` pass to set the denorm fields. Don't rely on row ordering within a single `INSERT ... SELECT`.
2. **FK population.** Every existing `sast_findings.issueId` / `scan_findings.issueId` must be non-null after the backfill. The migration should add the column nullable, backfill, then alter it to `NOT NULL` at the end. A stray null means the detection → issue join silently drops rows.
3. **Don't delete the old triage columns until after FK population.** Keep them through the backfill so we can verify counts against the pre-state. Drop in the final DDL step of the same migration.
4. **SCA reachability overwrite semantics.** On each scan where a ScaIssue is detected, its reachability fields are *overwritten* with the latest verdict. If the LLM returns `reachable=false` for a scan where the code removed the call, we correctly flip the issue. Make sure the worker always calls reachability for detected issues over the severity threshold — not just "issues created by this scan" or "pending triage".
5. **Triage "error" state recovery.** An issue whose previous scan failed triage (LLM timeout, malformed JSON) has `triageStatus='error'`. The next scan should retry it when detected. Query: `triageStatus IN ('pending', 'error') AND lastSeenScanRunId = ?`.
6. **Jira Basic auth requires `base64(email:apiToken)`, not `base64(apiToken)`**. Silently returns 401 with no body if you get this wrong.
7. **Jira status categories** use the internal keys `"new"` (To Do), `"indeterminate"` (In Progress), `"done"` (Done). The user-facing name is a separate field (`statusCategory.name`). Store the key, display the name.
8. **Jira JQL `key in (...)` with missing keys:** Jira returns only the keys it can find. Missing keys do *not* error — they're silently absent. The service must compare request vs response and mark absent keys with `syncError`.
9. **Jira ticket fixVersions can be renamed in Jira.** Our cached fix-version list may drift from Jira reality. Acceptable — the sync repairs it on the next tick. Don't over-index on the fix version dropdown UX; show a hint "(as of last sync: HH:MM)".
10. **Scheduler tick race.** If a scan is enqueued but hasn't moved to `running` yet, the next tick may see no "running" scan and re-enqueue. Debounce check must include `status IN ('pending', 'running')`.
11. **cron-parser timezone.** Default is UTC. Document this in OPERATIONS.md. Don't silently interpret as local time.
12. **BullMQ repeat-job dedup.** Always specify `jobId` on `queue.add(name, data, { repeat, jobId })`. Missing jobId creates a new repeat job on every scheduler restart.
13. **Scope page must not do live aggregation across all scans.** It should read denorm counts from `sast_issues` / `sca_issues` via `COUNT(*) FILTER (...)` in a single query — not loop scans. If the COUNT becomes slow, add a denorm counter on `ScanScope` like we did on `ScanRun`. For M5's scale, the indexed COUNT is fine.
14. **Pagination is breaking.** Backend + frontend + `schema.d.ts` regen must land in one commit per endpoint, otherwise the frontend will break when the backend changes shape.
15. **Demoted scan detail page still reads old columns.** Since we move triage/reachability off the detection rows, the demoted scan detail view must either (a) join through to the Issue, or (b) accept that it shows the historical evidence without current decision state. (b) is simpler and probably correct — the scan detail page is an audit artifact, not a decision surface.
16. **One JiraTicket, many Issues.** Unlinking an issue doesn't delete the JiraTicket. The JiraTicket is garbage-collected manually via a cleanup job (future M6) or stays until the org is deleted. Acceptable — it's cache.
17. **Auth rate limit on `/auth/logout`** means a user can be blocked from logging out after a bad-actor flood. 10/min is high enough that this is theoretical, but document the policy.
18. **Issue visibility:** Issues are scoped via `scopeId → scope.org`. Every Issue query must filter `org = current user's org`, both directly and via the scope relation. A raw `SELECT FROM sast_issues WHERE id = $1` without an org check is a cross-tenant leak. Use the same pattern as existing scan routes.

## Open questions — decide at implementation time

1. **Per-issue history.** Do we want an "evidence log" on the issue showing all detection rows + their scan ids + their timestamps? Useful for audit. Deferrable — the join is cheap; add a `GET /sast-issues/:id/detections` route later if someone asks.
2. **Jira webhook support.** Jira Cloud webhooks would replace polling for open tickets. Requires a publicly reachable SASTBot endpoint. Deferred to M6+ once SASTBot has a public URL.
3. **Bulk actions.** "Select 15 SCA issues, link to ticket SEC-123." Not in M5; add after we see real usage.
4. **Issue comments / discussion thread.** Out of scope; Jira is the source of truth for ticket discussion.
5. **SCA issue dismissal = suppression?** `dismissedStatus` on ScaIssue is modeled as active/acknowledged/wont_fix/false_positive. Matches how security programs categorize accepted risk. Open: do we also want a per-issue "snooze until date"? Defer.
6. **Scope summary counter denorm.** If the `COUNT(*) FILTER` on the scope list page becomes slow past ~1000 issues per scope, add columns like `scopeCache.activeSastIssueCount`. For M5's scale, skip.
7. **"Multiple scopes per branch" vs "one scope = one branch":** current model has scopes as `(repo, path)` with the branch implicit in the repo's `defaultBranch`. Fine for M5. First-class branch support is a separate milestone (and a deeper change to the Repo model).

## Final deliverables

- [ ] Migration `m5_issue_identity_and_jira` with DDL + data backfill (verified on a pg_dump copy of the current dev DB).
- [ ] New services: `issueService.ts`, `jiraClient.ts`, `jiraTicketService.ts`, `schedulerService.ts`.
- [ ] Refactored services: `llmTriageService.ts`, `reachabilityService.ts` (both now write to Issues, not detections).
- [ ] New worker entrypoint `scheduler.ts` + compose service `scheduler`.
- [ ] New routes:
  - `GET /scopes`, `GET /scopes/:id`, `GET /scopes/:id/sast-issues`, `GET /scopes/:id/sca-issues`, `GET /scopes/:id/components`, `GET /scopes/:id/scans`
  - `POST /sast-issues/:id/triage`, `POST /sca-issues/:id/dismiss`, `PUT .../notes`
  - `POST/DELETE /sast-issues/:id/jira-ticket`, same for sca
  - `POST /admin/jira-tickets/:key/refresh`, `GET /admin/jira-tickets`, `GET /admin/jira-tickets/fix-versions`
  - `POST /admin/settings/jira/check`
  - Updated paginated versions of `/scans`, `/admin/repos`, `/admin/credentials`
- [ ] Deprecated (kept but marked): old per-scan `/scans/:id/sast-findings/:fid/triage` forwards to the issue route.
- [ ] Frontend: new `/scopes` pages, scope-centric issue views, Jira chip + link popover, cron preset + preview, pagination controls. Old scan detail page demoted (route kept, not in main nav).
- [ ] Rate limiting on `/auth/login` + `/auth/logout`.
- [ ] Regenerated `frontend/src/api/schema.d.ts` committed.
- [ ] `docs/PROGRESS.md` M5 entry with EXPLAIN plans.
- [ ] `docs/OPERATIONS.md` additions (Scheduled scans, Jira integration, Rate limiting, Issue identity primer).
- [ ] All phase gates passed; committed at each gate.
- [ ] Manual end-to-end scenarios (5f) documented as passed.
