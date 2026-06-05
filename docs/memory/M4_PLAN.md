# M4 — SAST vertical slice + LLM triage + reachability

Implementation plan for Milestone 4. Read this entire document before writing code.

## Context

M3 shipped: SCA pipeline (cdxgen → OSV → EOL) with `Findings` + `Components` tabs on the scan detail page. `ScanScope` is the canonical unit of analysis — `(repo, path)` pair, scans belong to scopes. CVE IDs link out to NVD/GHSA/OSV. Deprecation/EOL findings coexist with CVE findings in the same `ScanFinding` table via a `finding_type` discriminator.

See `docs/PROGRESS.md` for the full M3 retrospective. See `CLAUDE.md` for conventions.

## Decisions already locked — do not re-debate

1. **Opengrep**, not Semgrep. If the binary download fails at image build, that's OK — worker detects missing binary at runtime, writes a scan warning, continues with SCA only.
2. **Fingerprint = `sha256(ruleId + ":" + normalizeSnippet(snippet))`**, 16 hex chars. File path deliberately **excluded** so moving code keeps suppressions. Normalization: `.trim().replace(/\s+/g, ' ')`.
3. **Both reachability directions**:
   - SAST-originated: inline in SAST triage prompt (free, opportunistic).
   - SCA-originated: grep + LLM-confirm for CVEs at/above CVSS threshold (authoritative).
4. **`CveKnowledge` is global, not org-scoped.** One function-name extraction per CVE for the entire tool lifetime.
5. **Regex extraction is provisional.** Low confidence triggers LLM fallback. Accuracy not yet validated at scale — this is the biggest known risk in the plan and must be flagged in PROGRESS.md.
6. **Combined LLM calls.** SAST triage + opportunistic reachability hints in one prompt. Saves tokens.
7. **LLM toggle default OFF.** Admin opts in via Settings.
8. **CVSS threshold default 7.0**, configurable in Settings (covers critical + high).
9. **Scope-confined grep.** Ripgrep only searches within `scope.path` subtree of the clone.
10. **Admin-only triage actions** for M4. Server-side enforcement in the route, not just UI gating.

## Schema changes

### New model: `SastFinding`

```prisma
model SastFinding {
  id                  String    @id @default(uuid()) @db.Uuid
  scanRunId           String    @map("scan_run_id") @db.Uuid
  scopeId             String    @map("scope_id") @db.Uuid
  orgId               String?   @map("org_id") @db.Uuid
  fingerprint         String    // sha256(ruleId + ":" + normalizedSnippet), 16 hex
  ruleId              String    @map("rule_id")
  ruleName            String?   @map("rule_name")
  ruleMessage         String?   @map("rule_message")
  cweIds              String[]  @map("cwe_ids")
  severity            String    @default("info")
  filePath            String    @map("file_path")
  startLine           Int       @map("start_line")
  endLine             Int?      @map("end_line")
  snippet             String?
  triageStatus        String    @default("pending") @map("triage_status")
  // "pending" | "confirmed" | "false_positive" | "suppressed" | "error"
  triageConfidence    Float?    @map("triage_confidence")
  triageReasoning     String?   @map("triage_reasoning")
  triageModel         String?   @map("triage_model")
  triageInputTokens   Int?      @map("triage_input_tokens")
  triageOutputTokens  Int?      @map("triage_output_tokens")
  suppressedAt        DateTime? @map("suppressed_at") @db.Timestamptz(6)
  suppressedByUserId  String?   @map("suppressed_by_user_id") @db.Uuid
  suppressedReason    String?   @map("suppressed_reason")
  detailJson          Json?     @map("detail_json")
  createdAt           DateTime  @default(now()) @map("created_at") @db.Timestamptz(6)

  scanRun ScanRun   @relation(fields: [scanRunId], references: [id], onDelete: Cascade)
  scope   ScanScope @relation(fields: [scopeId],   references: [id], onDelete: Cascade)
  org     Org?      @relation(fields: [orgId],     references: [id], onDelete: SetNull)

  @@unique([scanRunId, fingerprint])
  @@index([fingerprint])
  @@index([scopeId, fingerprint])
  @@map("sast_findings")
}
```

### New model: `CveKnowledge`

```prisma
model CveKnowledge {
  id                   String    @id @default(uuid()) @db.Uuid
  osvId                String    @unique @map("osv_id")
  cveId                String?   @map("cve_id")
  ecosystem            String
  packageName          String    @map("package_name")
  vulnerableFunctions  String[]  @map("vulnerable_functions")
  extractionMethod     String    @map("extraction_method")
  // "regex" | "llm" | "manual"
  extractionConfidence Float     @map("extraction_confidence")
  extractionModel      String?   @map("extraction_model")
  extractionReasoning  String?   @map("extraction_reasoning")
  osvModifiedAt        DateTime? @map("osv_modified_at") @db.Timestamptz(6)
  createdAt            DateTime  @default(now()) @map("created_at") @db.Timestamptz(6)
  updatedAt            DateTime  @updatedAt @map("updated_at") @db.Timestamptz(6)

  @@index([ecosystem, packageName])
  @@map("cve_knowledge")
}
```

### Additions to existing models

```prisma
model ScanRun {
  // +
  warnings                Json          @default("[]")
  llmInputTokens          Int           @default(0) @map("llm_input_tokens")
  llmOutputTokens         Int           @default(0) @map("llm_output_tokens")
  llmRequestCount         Int           @default(0) @map("llm_request_count")
  sastFindingCount        Int           @default(0) @map("sast_finding_count")
  confirmedReachableCount Int           @default(0) @map("confirmed_reachable_count")
  sastFindings            SastFinding[]
}

model ScanFinding {
  // + (applies to SCA findings)
  confirmedReachable          Boolean   @default(false) @map("confirmed_reachable")
  reachableViaSastFingerprint String?   @map("reachable_via_sast_fingerprint")
  reachableReasoning          String?   @map("reachable_reasoning")
  reachableAssessedAt         DateTime? @map("reachable_assessed_at") @db.Timestamptz(6)
  reachableModel              String?   @map("reachable_model")
}

model AppSettings {
  // +
  llmAssistanceEnabled      Boolean @default(false) @map("llm_assistance_enabled")
  llmTriageTokenBudget      Int     @default(50000) @map("llm_triage_token_budget")
  reachabilityCvssThreshold Float   @default(7.0)   @map("reachability_cvss_threshold")
}

model ScanScope {
  // +
  sastFindings SastFinding[]
}

model Org {
  // +
  sastFindings SastFinding[]
}
```

The shape of the `warnings` JSON array:
```ts
type ScanWarning = { code: string; message: string; context?: Record<string, unknown> };
```

Known codes used by M4:
- `opengrep_missing` — Opengrep binary not installed; SAST skipped.
- `triage_budget_exhausted` — LLM token budget exceeded mid-triage; `context.remaining` = N findings left pending.
- `llm_not_configured` — LLM assistance enabled but credentials/URL/model incomplete.
- `llm_transient_error` — LLM call failed after retry; `context.findingId` included.

## Phases

Each phase has a testing gate. Do not advance until the gate passes. Commit at each gate.

### Phase 4a — Schema + Opengrep install (~1 day)

**Dockerfile** (`docker/backend.Dockerfile`):
- Add `ARG OPENGREP_VERSION` near the top of the `base` stage.
- Download the pre-built Linux x86_64 binary to `/usr/local/bin/opengrep`.
- Wrap in `|| echo "WARN: opengrep install failed — SAST will be unavailable"` so a bad version doesn't fail the image build.
- Also install `ripgrep` via apt — needed for reachability grep.

Verify the latest Opengrep release tag before pinning; binary URL shape is approximately `https://github.com/opengrep/opengrep/releases/download/v${VERSION}/opengrep_v${VERSION}_manylinux_x86`. Confirm exact filename at implementation time.

**Prisma schema:** apply the schema changes above. Create migration `m4_sast_scaffold`:

```
docker compose -f docker/compose/docker-compose.yml exec backend \
  pnpm prisma migrate dev --name m4_sast_scaffold
```

No data backfill needed — all new columns are nullable or defaulted.

**Zod schemas in `backend/src/schemas.ts`:**
- `SastFindingOutSchema`, `SastFindingListSchema`
- `SastTriageBodySchema` = `{ status: enum, reason?: string }`
- `ScanWarningSchema` = `{ code, message, context?: object }`
- Update `ScanRunOutSchema` with new counters + warnings array
- Update `AppSettingsOutSchema` + `AppSettingsUpdateSchema` with `llm_assistance_enabled`, `llm_triage_token_budget`, `reachability_cvss_threshold`

**Mapper updates in `backend/src/services/mappers.ts`:**
- `sastFindingToOut`
- Update `scanRunToOut` for new counters + warnings
- Update `appSettingsToOut` for new fields

**Gate 4a:**
- [ ] Migration applies cleanly
- [ ] `pnpm typecheck` passes in backend
- [ ] Docker image builds (warn if opengrep download fails, don't hard-fail)
- [ ] `docker compose exec backend opengrep --version` succeeds (if skipped, document why)
- [ ] Manual `psql` insert of a SastFinding row succeeds

### Phase 4b — SAST pipeline + routes + UI (~1 day)

**New service `backend/src/services/sastService.ts`:**

```ts
// Pseudocode — see patterns in sbomService.ts and osvService.ts
async runOpengrep(workingDir, scopePath): Promise<SarifDoc | null>
  // execFile('/usr/local/bin/opengrep', ['scan', '--config', 'auto', '--sarif', ...])
  // 10 min timeout, return null on ENOENT (binary missing)

function parseSarif(doc): SastFindingInput[]
  // Handle SARIF 2.1.0:
  //   runs[].results[].ruleId, .level, .message.text, .locations[].physicalLocation
  //   Severity mapping: error→high, warning→medium, note→low, none→info
  //   CWE extraction from properties.cwe or taxa references

function normalizeSnippet(snippet: string): string
  return snippet.trim().replace(/\s+/g, ' ')

function computeFingerprint(ruleId: string, normalizedSnippet: string): string
  // sha256 hex, first 16 chars

async inheritTriage(scopeId, fingerprint, tx): Promise<{status, reason} | null>
  // Find most recent SastFinding in same scope with same fingerprint
  // where triageStatus IN ('suppressed', 'false_positive')
  // Return its status + reason

async persistSastFindings(scanRunId, scopeId, orgId, inputs, tx): Promise<SastFinding[]>
  // For each input: look up inheritable triage, create row
```

**Worker integration** (`backend/src/worker.ts`, after OSV/EOL step):

```ts
if (scope.repo.analysisTypes.includes('sast')) {
  const sarif = await runOpengrep(clone.workingDir, scope.path)
  if (sarif === null) {
    await appendWarning(scanRunId, { code: 'opengrep_missing', message: '...' })
  } else {
    const inputs = parseSarif(sarif)
    const findings = await persistSastFindings(...)
    await prisma.scanRun.update({ where: { id: scanRunId }, data: { sastFindingCount: findings.length } })
  }
}
```

**Helper for warnings:**

```ts
async function appendWarning(scanRunId: string, warning: ScanWarning): Promise<void>
  // UPDATE scan_runs SET warnings = warnings || $1 WHERE id = $2
  // Use Prisma's raw query or a read-modify-write in a tx
```

**Routes in `backend/src/routes/scans.ts`:**

```
GET  /scans/:id/sast-findings
  query: severity?, triage_status?, file_path? (prefix match)
  response: SastFindingListSchema

POST /scans/:id/sast-findings/:fid/triage
  preHandler: [app.requireAdmin]
  body: { status: "confirmed"|"false_positive"|"suppressed", reason?: string }
  response: SastFindingOutSchema
  side-effects: sets suppressedAt/suppressedByUserId if status=suppressed
```

**Test repo prep:** Add `backend/test-vuln-repo/src/app.js`:

```javascript
const express = require('express');
const app = express();
app.get('/user', (req, res) => {
  const q = `SELECT * FROM users WHERE id = '${req.query.id}'`;
  db.query(q, (e, r) => res.json(r));
});
app.get('/redirect', (req, res) => {
  res.redirect(req.query.url);
});
module.exports = app;
```

Commit this to the test repo (`cd backend/test-vuln-repo && git add . && git commit -m "..."`).

**Frontend:**
- Add `SastFinding` type to `frontend/src/api/types.ts`.
- Add `useSastFindings`, `useTriageSastFinding` hooks in `frontend/src/api/queries/scans.ts`.
- In `ScanDetailPage.tsx`: add a third tab "SAST" with `SastTab` component.
- SAST table: severity badge | rule name | file:line | triage chip | snippet (truncated, monospace).
- Expandable row: full snippet + reasoning + [Confirm] [Mark FP] [Suppress] buttons (admin-only — hide for non-admin).
- Scan detail warnings banner: if `scan.warnings.length > 0`, render a warning card above the tabs listing each warning's message.

**Gate 4b:**
- [ ] Scan test-vuln-repo → SAST findings appear (at least the SQL-injection and open-redirect rules fire)
- [ ] Manually triage a finding as FP via UI → DB updated, badge changes
- [ ] Re-scan same repo → FP status persists (suppression inheritance works)
- [ ] All SAST findings have `triageStatus = "pending"` except inherited ones — no LLM involvement yet
- [ ] Fingerprint robustness pre-test: add a blank line above the vuln code → re-scan → same fingerprint

### Phase 4c — LLM client + triage + connection check (~1.5 days)

**New service `backend/src/services/llmClient.ts`:**

```ts
interface LlmCallInput {
  scanRunId?: string;       // if set, token counters updated atomically
  prompt: string;
  maxTokens?: number;       // default 1024
  tx?: TransactionClient;
}

interface LlmCallResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
  model: string;
  latencyMs: number;
}

async function callLlm(input: LlmCallInput): Promise<LlmCallResult | null>
  // 1. Load settings; if llmAssistanceEnabled=false OR llmCredential/llmBaseUrl/llmModel missing → return null
  // 2. Decode credential via decodeCredential()
  // 3. Switch on llmApiFormat:
  //    "anthropic-messages": POST {baseUrl}/v1/messages
  //      body: { model, max_tokens, messages: [{role:'user', content: prompt}] }
  //      auth: { 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' }
  //      response: { content: [{text}], usage: { input_tokens, output_tokens } }
  //    "openai-chat": POST {baseUrl}/chat/completions
  //      body: { model, messages, max_tokens }
  //      auth: { Authorization: `Bearer ${apiKey}` }
  //      response: { choices: [{message:{content}}], usage: { prompt_tokens, completion_tokens } }
  //    "openai-completions": legacy, similar
  // 4. Retry once on 5xx / network timeout (1s backoff)
  // 5. If scanRunId set: atomically increment scanRun.llmInputTokens/llmOutputTokens/llmRequestCount
  // 6. Return { text, inputTokens, outputTokens, model, latencyMs }

function parseJsonResponse<T>(text: string, schema: ZodSchema<T>): T | null
  // Strict parse — return null if invalid
  // Caller decides retry strategy
```

**New service `backend/src/services/llmTriageService.ts`:**

```ts
async function triageFindings(scanRunId, scopeId, tx): Promise<void>
  // 1. Load settings; if LLM not enabled/configured → return (scan warning already added elsewhere)
  // 2. Load SAST findings ordered by severity DESC
  // 3. Load high-severity SCA findings for this scope (for reachability context in prompt)
  // 4. For each finding:
  //    a. Skip if triageStatus != 'pending' (already inherited)
  //    b. Build prompt (see below)
  //    c. Call llmClient; if null → break loop (not configured)
  //    d. Parse response as { triage, confidence, reasoning, confirmed_reachable_sca_ids? }
  //    e. If parse fails → retry once with error feedback; if still fails → triageStatus='error'
  //    f. Persist triage result + token usage
  //    g. Apply reachable_sca_ids hints (update ScanFinding.confirmedReachable + reachableViaSastFingerprint)
  //    h. After each call, check scanRun.llmInputTokens+outputTokens vs settings.llmTriageTokenBudget
  //       If exceeded: append warning 'triage_budget_exhausted' with {remaining: N}, break
```

**Prompt template:**

```
You are a security code reviewer. Analyze this static analysis finding and classify it.

## SAST Finding
Rule: {ruleId} - {ruleName}
Severity: {severity}
Description: {ruleMessage}
CWE: {cweIds.join(', ')}

## Location
{filePath}:{startLine}

## Code
```
{snippet}
```

## Known dependency vulnerabilities in this scope
{for each high-severity SCA finding:
  - [id={scanFinding.id}] {componentName}@{version} - {cveId}: {summary}
}

## Task
Classify the SAST finding. Additionally, for each dependency vulnerability listed,
determine if the code shown above appears to call the vulnerable function.

Respond with ONLY valid JSON:
{
  "triage": "confirmed" | "false_positive",
  "confidence": 0.0-1.0,
  "reasoning": "brief explanation",
  "confirmed_reachable_sca_ids": ["<id>", ...]  // empty array if none
}
```

**Route `POST /admin/settings/llm/check`** (in `adminSettings.ts`):

```ts
preHandler: [app.requireAdmin]
response: {
  success: boolean,
  latencyMs: number,
  model: string,
  inputTokens: number,
  outputTokens: number,
  error?: string,
}

handler:
  const result = await callLlm({ prompt: "Reply with exactly: ok", maxTokens: 20 })
  if (result === null) → { success: false, error: "LLM assistance not configured" }
  else → { success: true, latencyMs, model, inputTokens, outputTokens }
  catch errors by HTTP status:
    401 → "Authentication failed — check API key credential"
    404 → "Model not found — check llm_model"
    timeout/ECONNREFUSED → "Could not reach LLM base URL"
    other → error.message
```

**Frontend — `SettingsPage.tsx`:**
- New section "LLM-assisted analysis":
  - Toggle (Switch component): "Enable LLM assistance" ↔ `llmAssistanceEnabled`
  - Input[number]: "Token budget per scan" (default 50000, min 1000)
  - Input[number]: "Reachability CVSS threshold" (0–10, step 0.5, default 7.0)
  - Button: "Check connection" — on click, POST to `/admin/settings/llm/check`, show inline result card
- When toggle is on but `llmCredentialId` is null: render inline warning "LLM credentials not configured"

**Frontend — `ScanDetailPage.tsx`:**
- New "LLM usage" card (displayed only when `scan.llmRequestCount > 0`):
  - Total tokens: input + output
  - Requests: `llmRequestCount`
  - Budget utilization: `(input+output) / llmTriageTokenBudget` as percent
- SAST tab triage badges: color-code by `triageStatus` (Pending grey, Confirmed red, FP dim green, Suppressed strikethrough, Error amber with icon)
- SAST expanded row: show `triageReasoning` if present

**Gate 4c:**
- [ ] `Check Connection` with valid config → success, latency reasonable
- [ ] `Check Connection` with wrong URL → clear error message
- [ ] `Check Connection` with wrong API key → clear 401 message
- [ ] Toggle OFF → scan runs, no LLM calls, findings pending, no warnings
- [ ] Toggle ON + valid config → findings triaged, reasoning visible
- [ ] Set budget to 100 tokens → scan completes, remaining findings stay pending, `triage_budget_exhausted` warning visible in UI
- [ ] Temporarily break base URL → scan completes, some findings marked `triageStatus='error'` with clear reason

### Phase 4d — Reachability + CveKnowledge cache (~1.5 days)

**New service `backend/src/services/cveKnowledgeService.ts`:**

```ts
async getOrExtract(osvVuln, tx): Promise<CveKnowledge>
  // 1. Lookup by osvId
  // 2. If found AND osvModifiedAt >= osvVuln.modified → return cached
  // 3. Run extractViaRegex(osvVuln) → { functions, confidence }
  // 4. If confidence < 0.5 AND LLM enabled → extractViaLlm(osvVuln)
  // 5. Upsert CveKnowledge row

function extractViaRegex(osvVuln): { functions, confidence, reasoning }
  // Patterns (note: provisional — accuracy not validated at scale):
  //   /via `([^`]+)`/g
  //   /in `([^`]+)`/g
  //   /\b_\.([a-z]+)\b/gi          // lodash
  //   /\b([a-z][a-zA-Z0-9]+)\(\)/g  // function call syntax
  //   Package name fallback with weight 0.3
  // Confidence = min(1, distinctDistinctPatternMatches / 4)
  // Include reasoning like "matched N patterns: via=_.template, in=_.template"

async extractViaLlm(osvVuln, tx): Promise<...>
  // Prompt: "Given vuln description, return affected_functions[], confidence, reasoning"
  // Cache result with extractionMethod='llm', extractionModel set
```

**New service `backend/src/services/reachabilityService.ts`:**

```ts
async function assessReachability(scanRunId, scopeId, scopeWorkingDir, tx)
  // 1. Load settings (skip if LLM not enabled)
  // 2. Load SCA findings for this scope where cvss_score >= threshold
  //    AND (reachableAssessedAt IS NULL OR reachableViaSastFingerprint has changed)
  // 3. For each finding:
  //    a. Get CveKnowledge (cached or extracted)
  //    b. If vulnerableFunctions empty → mark reachable=null, reasoning="functions not identifiable"
  //    c. Ripgrep scopeWorkingDir for each function name:
  //       rg --fixed-strings -n --max-count 20 \
  //          --glob '!node_modules' --glob '!.git' \
  //          "{functionName}" {scopeWorkingDir}
  //    d. Zero hits → reachable=false, high confidence, reasoning="no references in scope"
  //    e. Hits exist → build prompt with top 3 match sites + ±10 lines each + CVE details
  //                  → call llmClient → parse → persist
  // 4. Apply SAST-originated hints: for any SCA finding where a SAST triage returned
  //    confirmed_reachable_sca_ids containing this SCA's id → mark reachable=true
  //    with reachableViaSastFingerprint=<sast fingerprint>
  // 5. Update scanRun.confirmedReachableCount
```

**Worker integration:** After SAST triage step, call `assessReachability` (only if LLM enabled and at least one SCA finding at/above threshold).

**Frontend:**
- Add ⚡ REACHABLE badge to SCA findings in:
  - `ScanDetailPage` Findings tab row (before severity badge)
  - `ScanDetailPage` Components tab (next to CVE chips)
- Tooltip: `reachableReasoning` + "via SAST finding <short id>" if applicable
- New "Reachable" summary card (alongside Components/Critical/High/Medium/Low) showing `confirmedReachableCount`
- Finding expanded row (SCA): new "Reachability" section with status, reasoning, origin

**Gate 4d:**
- [ ] Add `const _ = require('lodash'); _.template(req.body.tpl);` to test-vuln-repo/src/app.js, commit
- [ ] Scan → lodash CVE-2021-23337 marked `reachable=true` with reasoning mentioning template
- [ ] Remove the template call, re-commit, re-scan → `reachable=false`
- [ ] `CveKnowledge` table has one row per analyzed CVE
- [ ] Second scan of same repo: CveKnowledge entries reused (check logs — no re-extraction)
- [ ] Ripgrep stays within scope — set up a repo with two scopes, verify reachability for scope A doesn't pick up hits in scope B

### Phase 4e — Verification + docs (~0.5 day)

**Fingerprint robustness tests:**
1. Baseline scan → record fingerprint F of a specific finding
2. Add blank line above vuln code → re-scan → same F, triage inherited ✓
3. Add end-of-line comment on adjacent non-matching line → re-scan → same F ✓
4. Reformat whitespace within matched pattern → re-scan → same F ✓
5. Rename a variable inside the matched pattern → re-scan → **different** F (new finding) ✓
6. Move the file within the scope → re-scan → same F (file path not in hash) ✓

**Reachability tests:**
1. Vuln-function present → `reachable=true`, LLM call made
2. Vuln-function absent → `reachable=false`, zero LLM calls (grep verdict)
3. Cache hit on second scan → `CveKnowledge` not re-extracted

**LLM error verification:**
1. Wrong base URL → Check Connection clear error; scan completes with warnings
2. Wrong model name → same
3. Budget = 100 → scan completes, warning surfaces, most findings pending

**Documentation:**
- `docs/PROGRESS.md` M4 entry: "What shipped", "What we learned"
- Explicitly note known issue: **regex extraction accuracy not validated at scale**. TODO: audit 50+ real OSV records, tune patterns, potentially drop regex entirely if LLM extraction proves cost-effective.

## Pitfalls — read before each phase

1. **File path must NOT be in fingerprint hash.** Verified by test 6 above.
2. **Worker hot-reload doesn't work** — tsx on worker doesn't watch. Always `docker compose -f docker/compose/docker-compose.yml restart worker` after changing worker/service code.
3. **Prisma client** — after schema change, `pnpm prisma generate` explicitly if typecheck shows missing types.
4. **Vite polling already configured.** If UI doesn't update: restart frontend container.
5. **Snippet trailing whitespace** — Opengrep SARIF output sometimes has CRLF on Windows-origin files. Normalize defensively.
6. **LLM token field names differ by API:** Anthropic uses `input_tokens`/`output_tokens`; OpenAI uses `prompt_tokens`/`completion_tokens`. Handle both in llmClient.
7. **Scope-confined grep** — ripgrep root must be `path.join(clone.workingDir, scope.path)`, not the whole working dir. Monorepo scopes must not leak.
8. **CveKnowledge re-extraction trigger** — only re-extract if `osvVuln.modified > cveKnowledge.osvModifiedAt`. Otherwise cached value is canonical regardless of extraction method.
9. **Token counting atomicity** — increment counters in the same tx that writes the finding/triage/reachability row, otherwise counters drift on partial failure.
10. **Admin-only on triage routes** — server-side `requireAdmin` preHandler, not just UI gating.
11. **`llmAssistanceEnabled` check in every LLM-touching code path** — toggle OFF must produce no LLM calls and no errors.
12. **Structured LLM output** — 1-3% of responses are malformed. Strict Zod parse + one retry with error feedback + fall through to `triageStatus='error'`. Don't let bad JSON kill a scan.
13. **Budget checks happen after each call**, not before — so an individual call is allowed to slightly overrun the budget. The next call is what stops.

## Open questions — decide at implementation time

1. **Opengrep version pin.** Check latest release when writing the Dockerfile. Confirm binary filename matches.
2. **Anthropic `tool_use` vs JSON-in-prompt for structured output.** Use `tool_use` if the LiteLLM proxy supports it (more reliable structured output). Otherwise JSON-in-prompt with strict Zod parse + one retry.
3. **Token cost estimation in UI card.** Requires per-model pricing tables that rot. Defer.

## Final deliverables

- [ ] Opengrep + ripgrep installed in backend image
- [ ] SastFinding + CveKnowledge schema + migration
- [ ] `sastService`, `llmClient`, `llmTriageService`, `cveKnowledgeService`, `reachabilityService`
- [ ] Routes: SAST findings list, SAST triage, LLM check-connection
- [ ] Frontend: SAST tab, triage actions (admin-only), LLM usage card, toggle + connection check in Settings, reachability threshold input, ⚡ REACHABLE badges, warning banners
- [ ] Warnings surfaced in UI (top-of-scan banner + SAST tab notes for SAST-specific warnings)
- [ ] `docs/PROGRESS.md` M4 entry written
- [ ] test-vuln-repo has `src/app.js` with intentional SAST-fire code
- [ ] All phase gates passed
- [ ] Committed at each phase gate with clear messages
