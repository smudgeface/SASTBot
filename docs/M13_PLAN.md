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

- Add `buildDetectionSchema()` if Phase A didn't already.
- Refactor `spawnClaudeAndStream` to accept a `responseShape: "stream-jsonl-records" | "structured-output"` parameter. Default keeps current behavior; detection caller passes `"structured-output"`.
- For `"structured-output"`:
  - Args: replace `--output-format stream-json` with `--output-format json`, add `--json-schema "$(cat /tmp/schema-${scanRunId}.json)"` (or use a file). Drop `--verbose` (no streaming events needed).
  - Write the rendered schema to `/tmp/sastbot-${scanRunId}/detection-schema.json` so the path is per-scan and auditable.
  - On process close, parse stdout as one JSON object. Pull out `structured_output` if present; if the result message has `subtype: "error_max_structured_output_retries"`, treat it as a parse-error scenario (one synthetic warning entry, escalate via the existing severity helper).
- Update `runDetection` to convert the validated `findings` array directly into `DetectionRecord[]` — they should already match because the Zod aliases accept all canonical names.

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

### Schema delivery: file path, not inline argv

`--json-schema` accepts an inline string per the docs, but: schemas are large (~5-10 KB each), shell argv has platform limits, and an inline blob in `ps` output is ugly to debug. Write to `/tmp/sastbot-${scanRunId}/<phase>-schema.json` and pass the file path. Auditable, debuggable, no shell-escaping risk.

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

## Open questions (verify before / during implementation)

1. **Does `zod-to-json-schema` produce a schema Claude accepts?** Specifically: `additionalProperties: false` on every object, `anyOf` for unions (not `oneOf`), no recursive `$ref`, no `minItems > 1`. **Verify** by running it on `DetectionRecord` and validating the output against Claude's schema-feature list before wiring it into the CLI args.

2. **What does the `result` message look like with `--output-format json`?** The doc shows the SDK delivers `structured_output` on the result message. The CLI may flatten differently. **Verify** with a minimal smoke test before refactoring `spawnClaudeAndStream`.

3. **How are tool-use events delivered when `--output-format json` is in play?** Today our `setPhase` progress comes from `assistant` events with `usage` data. `--output-format json` may suppress those (one final response only) — or may still stream them via stderr / a different channel. **Verify** before declaring Phase B done; if progress is lost, we'd need to add periodic polling or accept loss-of-progress as a known v0.13.0 regression.

4. **Does claude-p surface the SDK retry count anywhere?** Useful for cost monitoring. Look for it in the `result` message; if not present, count by `usage.requestCount` deltas across the conversation.

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
