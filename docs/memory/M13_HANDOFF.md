# M13 Handoff — Schema-enforced LLM output via `claude -p --json-schema`

Paste the section below verbatim into the new session's first message.

---

## Handoff: implement M13 schema-enforced LLM output

**Goal.** Replace the reactive schema-alias chase (v0.12.0 → v0.12.4 shipped seven aliases as drift was discovered, each at the cost of one failed scan) with API-level structured output. Pass a JSON Schema to `claude -p` via `--json-schema`; the Agent SDK re-prompts the model until the response validates. The plan lives at `docs/M13_PLAN.md` — read it first, it has the locked decisions and the verified facts about `--json-schema` semantics.

**Branch state.** Start from `main` at v0.12.4, fully pushed to `origin/main`. Most recent commit: `b6b1b82 docs(m13): plan + handoff for LLM record self-validation` — that's the *old* M13 plan that's been replaced by this one. Backend tests green (367/367, run with `--no-file-parallelism` to dodge an unrelated Prisma teardown segfault). No uncommitted state expected. All seven alias defenses are in place and verified by tests; they stay as defense-in-depth.

**Orient in ≤ 3 tool calls:**

```bash
git log --oneline -10
tail -180 docs/PROGRESS.md     # v0.12.0 → v0.12.4 drift chase, the prompt-and-schema iteration loop
cat docs/M13_PLAN.md           # the full plan (phases, decisions, open questions)
```

CLAUDE.md auto-loads. The 🔖 versioning pin and 📖 manual-currency pin apply.

**Read first:**

- `backend/src/services/llmSastService.ts` lines 38-240 — the four record schemas, the seven aliases, the `DetectionRecord` union.
- `backend/src/services/llmSastService.ts` `spawnClaudeAndStream` (around line 462) — the current `--output-format stream-json` consumer that needs to grow a `--output-format json` mode.
- `backend/src/services/llmSbomService.ts` — same pattern, will need the same pivot in Phase C.
- `docs/M13_PLAN.md` "Open questions" section — verify those before writing code.

## Phase-by-phase build order

### Phase A — System-prompt schema reference (ship as v0.12.5, PATCH)

1. Install `zod-to-json-schema` in the backend (`docker compose ... exec backend pnpm add zod-to-json-schema` then commit the lockfile).
2. Create `backend/src/services/jsonSchema.ts` exporting `buildDetectionSchema()`, `buildRecheckSchema()`, `buildSbomAugmentationSchema()`. Use `zodToJsonSchema(MySchema, { target: 'jsonSchema2020-12' })` or whichever target Claude prefers (verify).
3. Validate the produced schemas pass Claude's feature list (M13_PLAN.md "Open questions" #1): `additionalProperties: false` on every object, no `oneOf` (should be `anyOf`), no recursive `$ref`, no `minItems > 1`.
4. Add template-token injection to `promptLoader.ts`: `{{DETECTION_SCHEMA}}` / `{{RECHECK_SCHEMA}}` / `{{SBOM_AUGMENTATION_SCHEMA}}` substitute the pretty-printed JSON Schema.
5. Update `sast_system.md` and `sbom_system.md` with an "Output schema" section embedding the schema in a fenced ```json``` block.
6. Smoke test: run an FSS scan, verify parse-error count drops vs v0.12.4 baseline. (Don't expect zero yet — that's Phase B.)
7. Version bump 0.12.4 → 0.12.5. PROGRESS.md entry. Commit. **Don't push until user approves.**

### Phase B — `--json-schema` for detection (ship as v0.13.0, MINOR)

1. Refactor `spawnClaudeAndStream` to accept a `responseShape: "stream-jsonl-records" | "structured-output"` parameter. Default keeps current behavior; detection caller passes `"structured-output"`.
2. For `"structured-output"`:
   - Args: `--output-format json` (replacing `stream-json`), `--json-schema <file>` (NOT inline — write the schema to `/tmp/sastbot-${scanRunId}/detection-schema.json` and pass the path), drop `--verbose`.
   - Consume one final JSON object from stdout. Pull `structured_output` from the result message. If `subtype === "error_max_structured_output_retries"`, emit one synthetic parse-error entry and let the existing M12 trustworthiness gate fire.
3. `runDetection` converts `structured_output.findings` directly into `DetectionRecord[]` via `DetectionRecord.array().parse()` — should pass cleanly because the aliases accept canonical names.
4. Verify (M13_PLAN.md "Open questions" #3): does `--output-format json` still surface tool-use events for `setPhase` progress? If yes, keep current progress wiring. If no, decide: accept progress regression for v0.13.0, or add periodic worker-side DB polling.
5. Wall-clock budget: keep the existing `wallClockTimeoutMs` cap. Add `--max-budget-usd` if you can map it cleanly to a per-scope budget config.
6. Smoke test on FSS, then GoPxL BE. **Zero parse errors is the target.** Cost within 1.5× of v0.12.4 baseline.
7. Version bump 0.12.5 → 0.13.0. PROGRESS.md entry. Commit. **Don't push until user approves.**

### Phase C — Recheck + SBOM augmentation (ship as v0.13.1 or fold into v0.13.0)

Same pattern, applied to `runRecheck` and `runSbomAugmentation`. Schemas:

- Recheck: `{ verdicts: RecheckVerdictRecord[], complete: RecheckCompleteRecord }`.
- SBOM augmentation: `{ keeps: KeepRecord[], drops: DropRecord[], adds: AddRecord[], complete: ... }`.

Both are mechanical once Phase B's plumbing is in place. Use Sonnet.

## Locked decisions (do not re-litigate — full rationale in M13_PLAN.md)

- **Use `zod-to-json-schema`** to derive schemas. Single source of truth stays Zod.
- **Keep existing aliases.** Defense in depth for the dry-run CLI and tests.
- **Schema file path, not inline argv.** `/tmp/sastbot-${scanRunId}/<phase>-schema.json`. Auditable, no argv-size limit risk.
- **Map `error_max_structured_output_retries` → existing parse-error severity gate.** No new gate machinery.
- **`anyOf`, not `oneOf`.** Claude doesn't accept `oneOf`. Zod unions compile to `anyOf` automatically.
- **`additionalProperties: false` everywhere.** Required by Claude. Verify zod-to-json-schema output.
- **`kind` field is the discriminator inside `anyOf`.** Each branch's `kind: { const: "..." }` is required.

## Verification gates before each ship

1. **Phase A:** `pnpm test` green; produced JSON Schema validates against Claude's feature list; FSS smoke test shows reduced parse-error count.
2. **Phase B:** `pnpm test` green; GoPxL BE scan emits zero parse errors; cost ≤ 1.5× v0.12.4 baseline; wall-clock ≤ 1.5× v0.12.4 baseline.
3. **Phase C:** `pnpm test` green; FSS or GoPxL scan shows zero recheck/SBOM parse errors.

## Model selection

- **Sonnet** for Phase A and Phase C (mechanical).
- **Opus** for Phase B design-level decisions only:
  - How `spawnClaudeAndStream` branches between stream-jsonl-records and structured-output.
  - How to handle progress-event regression if it shows up.
- Drop back to Sonnet for the actual code edits in Phase B.

## Open knobs for the user (ask before deciding)

- **Bundle B+C into one v0.13.0 PR, or split as v0.13.0 + v0.13.1?** Single PR is bigger blast radius but consistent; split is two ships.
- **`--max-budget-usd` per-scan cap?** Doc says it exists in print mode. Worth wiring as a safety net?
- **Smoke test on FSS first (cheap), then GoPxL BE (expensive, $7-8), or skip FSS to save time?** Default: FSS first, GoPxL only after FSS passes.

## What success looks like

- A fresh GoPxL BE scan emits zero parse errors.
- Cost per scan within 1.5× v0.12.4 baseline.
- Backend test suite green.
- PROGRESS.md entries are honest about retry rate, cost delta, and any progress-event regressions.

## What failure looks like

See M13_PLAN.md "What failure looks like" — three known failure modes, each with a fix.

## Don'ts

- Don't drop the existing Zod alias code.
- Don't hand-write JSON Schema — derive from Zod.
- Don't push without user approval.
- Don't skip the version bump policy (three files + lockfile).
- Don't restart the worker if a scan is running — check the DB first.
- Don't bundle Phase A into Phase B's PR — Phase A's drift-reduction signal is the input to Phase B's design choices.
- Don't burn Opus on Phases A or C.

## Context that may be useful

- The seven alias defenses we shipped (and that stay in place):
  - `cwe` / `cwe_id` (v0.12.2)
  - `file` / `file_path` (pre-existing)
  - `title` / `summary` (pre-existing)
  - `description` / `reasoning` (pre-existing)
  - string-vs-number `confidence` (v0.12.3)
  - summary-less `sast_absence` synthesizes from reasoning (v0.12.3)
  - `reachability` / `sca_reachability` kind alias (v0.12.4)
- The M12 trustworthiness gates we ship with: `PARSE_ERROR_FAILURE_THRESHOLD = 0.25`, `PARSE_ERROR_ABSOLUTE_FAILURE_COUNT = 10`. Both still fire for `--json-schema` failure mode.
- The Colima stuck-socket UX bug (CLAUDE.md "Vite dev-proxy"). After backend/worker restart for the version bump, the frontend container needs `stop && up -d` (not `restart`) to clear stranded sockets. Or just open the test browser in Incognito.
