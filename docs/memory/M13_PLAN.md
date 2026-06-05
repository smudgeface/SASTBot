# M13 Plan — Schema-enforced LLM output via `claude -p --json-schema`

**Goal.** Replace the reactive schema-alias chase with API-level structured output. Pass a JSON Schema to `claude -p` via `--json-schema`; the Agent SDK re-prompts the model until the response validates. Drift is enforced away at the API boundary instead of being patched at the Zod boundary inside SASTBot.

**Why now.** Through v0.12.0 → v0.12.4 we shipped seven alias defenses for known drift shapes (`cwe`/`cwe_id`, `file`/`file_path`, `title`/`summary`, `description`/`reasoning`, string-vs-number confidence, summary-less absence, `reachability`/`sca_reachability`). Each was discovered by a real production scan dropping records — typical cost $7-8 per failed scan. The pattern converges slowly: every new model revision, every prompt change, can produce new drift shapes we haven't seen.

`claude -p --json-schema` flips the loop: the model is forced (with SDK-managed retries) to match a schema we control. Same agentic loop (Bash/Read/Grep). Same prompts. The output shape is constrained.

## Pre-work — orient in ≤ 3 tool calls

```bash
git log --oneline -10
tail -180 docs/PROGRESS.md     # context: v0.12.0 → v0.12.4 drift-chase loop
cat docs/M13_PLAN.md           # this doc
```

You are starting from `main` at **v0.12.4**, fully pushed to `origin/main`. Tests green (367/367, run `--no-file-parallelism` to dodge the unrelated Prisma teardown segfault). All seven alias defenses are live. Worker is on v0.12.4.

## Key facts about `claude -p --json-schema` (verified 2026-05-26)

From `https://code.claude.com/docs/en/cli-reference`:

- `--json-schema '{...}'` — print-mode only. *"Get validated JSON output matching a JSON Schema after agent completes its workflow."*
- `--output-format json` — return the final structured response as a single JSON object (vs `stream-json`'s line-by-line stream).

From `https://code.claude.com/docs/en/agent-sdk/structured-outputs`:

- **The agent works agentically as before** (Bash/Read/Grep), then produces a final JSON output validated against the schema.
- **The SDK re-prompts on mismatch** until the retry limit is hit.
- **Success → full validated data.** Failure → result message with `subtype: "error_max_structured_output_retries"` — no partial data.
- Schema features supported: all basic types, `enum`, `const`, `anyOf`, `allOf` (without `$ref`), `$ref` / `$def` / `definitions` (internal only, no recursion, no external URLs), `default`, `required`, `additionalProperties` **(must be `false` for objects)**, common string formats (`date-time`, `uuid`, `email`, etc.), `minItems: 0` or `1` on arrays.
- **NOT supported**: `oneOf`, recursive schemas, external `$ref`.
- **Complexity limits**: max 24 optional parameters total, max 16 parameters with `anyOf` / union types across all strict schemas in a single request.

From `https://platform.claude.com/docs/en/build-with-claude/structured-outputs`:

- The Messages API itself supports this — `--json-schema` is the CLI surface for it.

## Architectural implications

### What changes in `llmSastService.ts`

- `spawnClaudeAndStream` currently appends `--output-format stream-json --verbose` and parses each line as a stream event with `text` content-blocks. **Switch to `--output-format json`** and consume one final response (the doc shows the `result` message still arrives through the stream and contains the parsed `structured_output`).
- Add `--json-schema <path-to-schema.json>` to the args. We will pass a *file* path rather than an inline string — schemas are large, command-line argv size limits exist on some platforms, and a file is auditable.
- The `onLine` callback that today builds `records` / `parseErrors` arrays goes away. Replace with a single "consume the final structured_output" step.

### What changes in our schemas

Today: `DetectionRecord = z.union([SastRecord, SastAbsenceRecord, ReachabilityRecord, CompleteRecord])`, with `.refine()` and `.transform()` callsthat encode the alias rules.

The `.refine()` and `.transform()` calls are **runtime-only Zod features** — they do NOT serialize into JSON Schema via `zod-to-json-schema`. This is actually a feature, not a bug: we generate a **clean structural schema** that requires the *canonical* field names directly (`cwe`, `summary`, `file_path`, `reasoning`), and the SDK forces the model to use them.

**Drift dies at the source.** The aliases stay in the Zod code as defense-in-depth (the dry-run CLI at `backend/src/cli/dry-run-llm-sast.ts` still parses through Zod), but the production path is schema-enforced upstream.

### What the top-level schema looks like

Detection emits multiple records plus a terminal `complete` record. The top-level structured-output schema wraps them:

```jsonc
{
  "type": "object",
  "additionalProperties": false,
  "required": ["findings", "complete"],
  "properties": {
    "findings": {
      "type": "array",
      "items": {
        "anyOf": [
          <SastRecord JSON Schema (canonical fields only)>,
          <SastAbsenceRecord JSON Schema>,
          <ReachabilityRecord JSON Schema>
        ]
      }
    },
    "complete": <CompleteRecord JSON Schema>
  }
}
```

Recheck mirrors this:

```jsonc
{
  "type": "object",
  "additionalProperties": false,
  "required": ["verdicts", "complete"],
  "properties": {
    "verdicts": { "type": "array", "items": <RecheckVerdictRecord schema> },
    "complete": <RecheckCompleteRecord schema>
  }
}
```

SBOM augmentation similarly wraps `keeps` / `drops` / `adds`.

### What we keep

- **The existing Zod schemas with aliases.** Defense-in-depth for any code path that doesn't go through `--json-schema` (the dry-run CLI, future test fixtures, etc.).
- **The trustworthiness gates.** `PARSE_ERROR_FAILURE_THRESHOLD` and `PARSE_ERROR_ABSOLUTE_FAILURE_COUNT` keep firing if the SDK *does* return an `error_max_structured_output_retries` result — we'd surface that as a parse-error event with one synthetic entry and let the gate fire.
- **The same prompts.** No prompt rewrite needed beyond adding the schema reference at the top (Phase A). The output-shape rules in `sast_detection.md` become *belt + suspenders* alongside the schema enforcement.

## Phasing

### Phase A — System-prompt schema reference (cheap, additive)

Drop the JSON Schema into `sast_system.md` and `sbom_system.md` so the model sees the expected shape upfront. No API change, no CLI flag change. Reduces drift on the first attempt → fewer SDK retries → lower cost when Phase B ships.

- Add `backend/src/services/jsonSchema/` (new module) with one function per record union:
  - `buildDetectionSchema()`
  - `buildRecheckSchema()`
  - `buildSbomAugmentationSchema()`
- Use `zod-to-json-schema` (existing npm package, ~10 KB, no transitive deps to worry about). Configure it to:
  - Produce 2020-12 draft (or whatever Claude's structured outputs expects — verify).
  - Set `additionalProperties: false` on all objects (REQUIRED for Claude).
  - Strip Zod refines/transforms — `zod-to-json-schema` does this automatically (they don't have a JSON Schema representation).
- In `promptLoader.ts`, add a `{{DETECTION_SCHEMA}}` template token that injects `JSON.stringify(buildDetectionSchema(), null, 2)`.
- Update `sast_system.md` to include the schema in a fenced ```json block under a new "Output schema" section. The existing field-name pins stay — they're now consistent with the schema rather than redundant.

**Ship as v0.12.5 (PATCH).** No behavior change beyond the prompt size growing by a few KB. Re-run a scan and look for whether parse-error counts drop. Token cost will rise slightly (the schema is ~3-5 KB of tokens per call).

**Acceptance:** A GoPxL BE re-run after Phase A drops < 25% parse errors (i.e., scan succeeds rather than failing the threshold gate). Doesn't have to be zero — Phase B is what gets us to zero.

### Phase B — `--json-schema` for detection (the meat)

**Revised 2026-05-26 after empirical probe.** The original plan said "replace
`--output-format stream-json` with `--output-format json` and drop `--verbose`."
A probe with `claude` CLI 2.1.144 (`backend/src/cli/probe-claude-structured-output.ts`)
showed two things that change the design:

1. **`--output-format json` emits ZERO events before the final blob.** Every
   tool-use / assistant / progress signal disappears. `setPhase` mid-phase
   progress would freeze for the whole LLM phase (~24 min for GoPxL BE
   detection). Documented as Open Question #3 — answered: yes, progress is
   completely lost.
2. **`--json-schema` works with `--output-format stream-json --verbose`.** The
   schema is enforced by exposing a NEW built-in tool called `StructuredOutput`
   to the model. The model invokes that tool with the schema-validated payload;
   the SDK acknowledges with `"Structured output provided successfully"`; the
   final `result` event carries the same payload under `structured_output`.
   Schema enforcement happens inside the agent loop, not as a re-prompt cycle.

**Revised approach.** Keep `--output-format stream-json --verbose`. Add
`--json-schema <inline JSON>`. Read the validated payload from the final
`result` event's `structured_output` field. Almost everything else stays.

- Add `buildDetectionSchema()` if Phase A didn't already. ✓ (done in A)
- Refactor `spawnClaudeAndStream` to accept a `responseShape: "stream-jsonl-records" | "structured-output"` parameter and an optional `jsonSchema: object`. Default keeps current behavior; detection caller passes `"structured-output"` plus the wrapper schema.
- For `"structured-output"`:
  - Args: KEEP `--output-format stream-json --verbose`. Add `--json-schema <JSON.stringify(schema)>`. Schema goes INLINE on argv — CLI 2.1.144 expects an inline JSON string, NOT a file path (a file-path argument was tested and silently produced empty stdout). Linux ARG_MAX (≥128 KB) easily handles the 3-5 KB schemas we generate.
  - On the existing `result` event, capture `structured_output` (the schema-validated payload, equivalent to invoking the wrapper schema). Also capture `subtype` — `error_max_structured_output_retries` means the SDK gave up after retries; map to one synthetic parse-error entry so M12's trustworthiness gate fires.
  - The existing JSONL-from-assistant-text extraction can stay; it just produces zero records in structured-output mode because the model uses the `StructuredOutput` tool instead of emitting text. The `records[]` array gets populated from `result.structured_output.findings`.
- Update `runDetection` to convert the validated `findings` array directly into `DetectionRecord[]`. The Zod aliases stay as defense-in-depth (dry-run CLI + legacy callers).
- **`setPhase` progress survives** because the `--verbose --output-format stream-json` flow still emits `assistant` events with per-turn token usage. Open Question #3 is resolved without a regression.

**Ship as v0.13.0 (MINOR — new feature, backwards-compatible API but new internal architecture).**

**Acceptance:**

1. Backend test suite stays green (`--no-file-parallelism`).
2. A GoPxL BE re-run emits **zero parse errors** (target — the SDK either succeeds or fails wholesale).
3. Cost per scan is within 1.5× of the v0.12.4 baseline. (Retries cost tokens; we want to confirm it doesn't blow up.)
4. Wall-clock time is within 1.5× of the v0.12.4 baseline.

### Phase C — Mirror to recheck + SBOM augmentation

Same pattern. Each phase has its own schema builder, each caller passes `"structured-output"`. SBOM augmentation has the most surface (`AddRecord` / `DropRecord` / `KeepRecord` plus a wrapper), but the work is mechanical.

- `runRecheck` → schema wrapping `RecheckVerdictRecord[]` + `RecheckCompleteRecord`.
- `runSbomAugmentation` → schema wrapping `KeepRecord[]` + `DropRecord[]` + `AddRecord[]` + complete record.

**Ship as v0.13.1 or fold into v0.13.0 if it lands cleanly in the same session.**

## Decisions locked

### Schema delivery: inline argv (revised)

Originally planned to write to `/tmp/sastbot-${scanRunId}/<phase>-schema.json` and pass the file path. **Empirically that doesn't work.** CLI 2.1.144 treated a file-path argument as a literal JSON string, failed to parse it, and silently produced zero stdout. The CLI's `--json-schema` help shows an inline JSON example with no file-path syntax mentioned. Linux `ARG_MAX` is ≥128 KB on every supported platform and our derived schemas are 3-5 KB — well within limits.

Pass as inline JSON via `JSON.stringify(schema)`. The argv blob in `ps` is uglier than a path but the alternative (silent failure) is worse.

### Keep Zod aliases in place

They're not redundant — the dry-run CLI (`backend/src/cli/dry-run-llm-sast.ts`) and unit tests still feed JSON into `DetectionRecord.safeParse` directly. The aliases are also cheap insurance if a future refactor opens a non-structured-output code path.

### What about `oneOf`?

Not supported. Zod's `z.union(...)` compiles to `anyOf` via `zod-to-json-schema`, which IS supported. No work needed — verify after generation that the produced schema uses `anyOf`.

### Discriminator strategy

Today our `kind` literals are the discriminator. JSON Schema `anyOf` with each branch requiring its own `kind: { const: "sast" | "sast_absence" | ... }` IS the discriminator at the schema level. The SDK's validation will use `kind` to narrow which branch to validate against.

The `kind` field is `required` in each branch, with `const` set to the canonical value. That means the model literally cannot emit `"kind":"sca_reachability"` — the schema would reject. The alias `sca_reachability → reachability` in Zod stays for the dry-run CLI.

### `additionalProperties: false`

Required by Claude's structured outputs. Every object in our derived schema gets this. Watch: Zod's default is `passthrough` — `zod-to-json-schema` should still emit `additionalProperties: false` by default, but verify in tests.

### Schema-derivation library: `zod-to-json-schema`

Standard, ~20K weekly downloads, MIT, no security history. The alternative is hand-writing JSON Schema, which is error-prone and duplicates the source of truth. Stick with derived.

### What if the SDK's retry-loop fails?

The `error_max_structured_output_retries` result subtype. Map it to an `error`-severity parse-error warning with one synthetic entry describing the failure. The existing M12 trustworthiness gates fire automatically — scan marked `failed`, SCA sweep skipped, recheck destructive branches no-op. No new gate machinery needed.

### Cost model

Each SDK retry is a fresh API turn with full conversation context. The doc doesn't say how many retries the SDK does by default. Worst case: schema is too constrained and every scan hits retries. Mitigation:

- Phase A (schema-in-prompt) primes the model so the first attempt is closer to valid.
- `--max-budget-usd` is a CLI flag (saw it in the reference) — wire it to a per-phase ceiling so a runaway retry loop is bounded.
- If retries dominate, simplify the schema (fewer required fields, broader enums) until they stop dominating.

### What we DON'T change in this milestone

- Prompt structure beyond adding the schema reference.
- Zod schemas (just the structural derivation).
- The trustworthiness gates (`PARSE_ERROR_FAILURE_THRESHOLD`, `PARSE_ERROR_ABSOLUTE_FAILURE_COUNT`).
- The streaming-progress events that drive setPhase — those come from the agent's tool-use events, which `--output-format json` still emits before the final result. Verify in smoke test.

## Open questions — all resolved 2026-05-26

1. **Does `zod-to-json-schema` produce a schema Claude accepts?** **Resolved (Phase A).** Yes. Defaults emit `anyOf` for unions, `additionalProperties: false` on every object, no recursive `$ref` when `$refStrategy: "none"`. All Phase A canonical schemas pass `validateClaudeFeatures()`.

2. **What does the `result` message look like with `--output-format json`?** **Resolved (Phase B probe).** Pure-json mode emits ONE 1304-byte blob: `{ type: "result", subtype: "success" | "error_max_structured_output_retries", structured_output, total_cost_usd, usage: {input_tokens, output_tokens, cache_*}, num_turns, permission_denials[], session_id, ... }`. Identical fields appear in stream-json's final `result` event.

3. **How are tool-use events delivered when `--output-format json` is in play?** **Resolved (Phase B probe). Pure-json mode emits ZERO events before the final blob — all progress is lost.** Mitigation: use `stream-json --verbose` alongside `--json-schema` instead; the agent loop still emits every event AND the schema is enforced via the `StructuredOutput` tool. This combo is the revised Phase B direction.

4. **Does claude-p surface the SDK retry count anywhere?** **Partially resolved.** `result.num_turns` counts agent turns (3 for a single Read + StructuredOutput sequence). The SDK's per-tool-call retry count for schema enforcement isn't exposed separately — but `subtype: "error_max_structured_output_retries"` is the only failure mode we need to handle.

## Smoke test sequence

Before each ship:

1. **Unit:** run `pnpm test --run` (full suite). Must stay green.
2. **Schema generation:** unit-test `buildDetectionSchema()` produces valid JSON Schema (parses with `ajv` or similar; no `oneOf`; `additionalProperties: false` everywhere).
3. **Manual smoke (cheap):** trigger an FSS scan (`$3-4`) and observe the worker logs. Detection should complete with zero or near-zero parse errors. Note: FSS is a smaller repo than GoPxL BE — the drift surface is real but smaller, so passing here isn't a guarantee for GoPxL.
4. **Manual smoke (expensive):** trigger a GoPxL BE scan (`$7-8`). This is the canonical test case — it surfaced all four drift shapes we've shipped aliases for.

## Estimated effort

- Phase A (system-prompt schema): **~2 hrs** including testing.
- Phase B (detection `--json-schema`): **~1 day** including schema-shape verification + structured-output consumer rewrite + smoke tests.
- Phase C (recheck + SBOM): **~half day** (mechanical).

Total: **~2 days** if done sequentially with a smoke test between each phase. Use Sonnet for implementation; reach for Opus only on Phase B's design-level decisions about how `spawnClaudeAndStream` should branch.

## What success looks like

- v0.13.0 ships with structured-output enforcement for detection (Phase A + B).
- v0.13.1 ships Phase C (or 0.13.0 if bundled).
- A fresh GoPxL BE scan emits **zero parse errors**.
- Cost per scan stays within 1.5× of v0.12.4 baseline.
- PROGRESS.md entry: what shipped, what we learned, whether the SDK retry rate is a concern.

## What failure looks like

- **Schema rejected by Claude (Phase A discovers it).** Means our zod-to-json-schema output uses features Claude doesn't accept. Inspect the rejection message; either constrain the Zod schema (e.g. add `.strict()`) or post-process the JSON Schema output before sending. Don't switch to hand-written schemas — that defeats the single-source-of-truth purpose.
- **SDK retries blow up cost or wall-clock.** Cap with `--max-budget-usd` AND a wall-clock timeout. Phase A's prompt-side schema reference is the primary mitigation; if it doesn't help, the schema is too constrained — relax required fields.
- **Progress events disappear with `--output-format json`.** Decide: accept the regression (Phase A + B ship without live progress), or add periodic DB polling from the worker.

## Don'ts

- Don't drop the existing Zod alias code. Defense in depth.
- Don't drop the trustworthiness gates. They handle the `error_max_structured_output_retries` case automatically.
- Don't hand-write JSON Schema. Use `zod-to-json-schema` so the source of truth stays Zod.
- Don't push without explicit user approval, per CLAUDE.md.
- Don't bump 0.13.0 until Phase B is verified by a real scan (not just unit tests).
- Don't burn Opus on Phase A or Phase C — mechanical work.
