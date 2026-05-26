# M13 Plan — LLM record self-validation tool

**Goal.** Replace the reactive alias-chase pattern with a proactive self-correction loop: give the detection agent a `validate_detection_record` tool it can invoke before emitting any record. If the tool says FAIL, the agent fixes and retries — within the same claude-p session, no SASTBot-side restart, no failed scan.

**Why now.** Through v0.12.0 → v0.12.4 we shipped six alias defenses (`cwe_id`, `file`/`file_path`, `title`/`summary`, `description`/`reasoning`, string-confidence, summary-less absence, `sca_reachability`). Each was discovered by a real production scan dropping records — typical cost $7-8 per failed scan. Aliases work but converge slowly and don't generalize: every new LLM model / prompt revision can produce new drift shapes we haven't seen.

The validator-as-tool flips the loop: drift is detected and corrected inside the agent session, not by SASTBot N hours later.

## Pre-work — orient in ≤ 3 tool calls

```bash
git log --oneline -10
tail -120 docs/PROGRESS.md
# CLAUDE.md auto-loads; project_pending_features memory has context
```

You are starting from `main` at **v0.12.4**, fully pushed to `origin/main`. The alias defenses for known drift shapes are all in place. Tests are green (367/367). The remaining drift surface is the unknown-unknowns.

## Read first — the drift shapes we know about

All seven aliases live in `backend/src/services/llmSastService.ts`. Skim the file from line 38 (`SeverityEnum`) through line 240 (end of `DetectionRecord` union). Note specifically:

- The four record schemas (`SastRecord`, `SastAbsenceRecord`, `ReachabilityRecord`, `CompleteRecord`).
- The shared `ConfidenceSchema` (string-label-to-number normalization).
- The discriminator-level alias on `ReachabilityRecord.kind`.
- The `.refine` calls (post-parse soft validation) and `.transform` calls (post-parse normalization).

The validator tool's job is to expose the **DetectionRecord** union's `.safeParse` behavior to the agent as a callable command-line tool.

## Design

### 1. The tool itself

Create `backend/src/cli/validate-detection-record.ts` — a tiny CLI:

```typescript
#!/usr/bin/env node
import { DetectionRecord } from "../services/llmSastService.js";

const raw = await new Response(process.stdin).text();
try {
  const json = JSON.parse(raw);
  const result = DetectionRecord.safeParse(json);
  if (result.success) {
    process.stdout.write("OK\n");
    process.exit(0);
  }
  const reason = result.error.errors
    .map((e) => `${e.path.join(".") || "(root)"}: ${e.message}`)
    .join("; ");
  process.stdout.write(`FAIL: ${reason}\n`);
  process.exit(1);
} catch (err) {
  process.stdout.write(`FAIL: not valid JSON — ${(err as Error).message}\n`);
  process.exit(1);
}
```

Register it as a `bin` entry in `backend/package.json` so it's runnable as `validate-detection-record` from `$PATH` in any container that has `node_modules/.bin` on `PATH`. The worker container already does (it runs `claude` from there).

### 2. Make it visible to claude-p

`claude -p` is already spawned with `--allowed-tools "Bash Read Glob Grep"` (see `spawnClaudeAndStream` in `llmSastService.ts`). `Bash` is broad — the agent can already shell out to anything. So no permission change is required.

The agent just needs to *know* the tool exists. That's a prompt-side change.

### 3. Prompt change

Append to `backend/prompts/sast_detection.md`, near the existing field-names pin in the "Output format (JSON-Lines)" section:

> **Self-validate every record before emitting it.** Run each candidate
> through `validate-detection-record` (reads JSON on stdin, prints `OK`
> or `FAIL: <reason>` to stdout, exit 0 on OK / 1 on FAIL):
>
> ```bash
> echo '{"kind":"sast", ...}' | validate-detection-record
> ```
>
> If the tool reports FAIL, fix the record per the reason and re-validate.
> Do not emit a record until it validates. Cap retries at 3 per record —
> if the third attempt still fails, skip the record and continue with the
> rest of the detection pass.

Note the **retries cap** — this is the runaway-prevention. Without it the agent could loop indefinitely on a malformed record.

### 4. Test the loop end-to-end before declaring done

`scripts/` doesn't have a way to dry-run the agent today. Two paths:

1. **Cheaper: simulated agent test.** Write a test that exercises the CLI directly with a few drift-shaped records and confirms FAIL reasons are intelligible. Doesn't prove the agent will heed the feedback, but proves the tool is usable.
2. **Real: trigger a scan and watch worker logs.** Run a GoPxL BE scan. Watch for `[llmSastService]` log lines that show the agent invoking the tool via Bash. If the agent runs the tool many times, that's the loop working. parseErrors count after the scan should be **lower** than the v0.12.4 baseline (zero in the ideal case).

Use the smaller FSS repo first — it's cheaper per scan ($3-4 vs $7-8) and exercises a similar drift surface.

## Decisions to lock in before coding

### Tool name + location

- Bin name: `validate-detection-record` (kebab-case, matches existing `bootstrap-admin`).
- Source location: `backend/src/cli/validate-detection-record.ts`.
- Register in `backend/package.json` `bin` field.

### What the validator returns on success

`OK` on stdout + exit 0. Don't return the parsed record — the agent already has it. Keeps the protocol minimal.

### What the validator returns on failure

`FAIL: <reason>` on stdout + exit 1. The reason string is Zod's per-path error message, joined by `; `. The agent reads it and chooses how to fix.

**Open question:** should `<reason>` include a "did you mean" hint for known drift aliases? E.g. on receiving `cwe_id`, return `FAIL: cwe: Required (did you mean to use 'cwe' instead of 'cwe_id'?)`. **Recommendation: don't.** Adds prompt-engineering complexity to a piece of infrastructure that should be policy-free. The schema's existing aliases would catch `cwe_id` and pass — so the FAIL message would only fire on truly novel drift, where we can't anticipate the right hint.

### Retry cap

3 retries per record, per the prompt. Implemented agent-side via the prompt instruction, not enforced by SASTBot. The agent is on the honor system here — if a model ignores the cap, we'd see it in token usage, not in correctness.

### Do we keep the alias defenses?

**Yes, both.** Two reasons:

1. The validator is best-effort. Some agent runs may forget to validate, or the worker may run on a different prompt that doesn't teach the workflow. Aliases are the safety net.
2. The dry-run CLI (`backend/src/cli/dry-run-llm-sast.ts`, if it still exists in M6+) and any other consumer of `DetectionRecord` benefits from the aliases. Removing them would break other paths.

The validator + alias defenses are belt + suspenders. Keep both.

### What about recheck records?

`runRecheck` parses `RecheckVerdictRecord`, not `DetectionRecord`. Recheck's parse-error counts have been zero across all four failed scans — drift hasn't been an issue there. **Recommendation:** ship the detection-side validator first, prove it works, then mirror it to recheck only if recheck drift shows up. Don't pre-build for a problem we don't have.

### What about SBOM augmentation?

Similar shape — `llmSbomService` parses `AddRecord` / `DropRecord` / `KeepRecord`. The 2026-05-25 GoPxL BE run had a separate `llm_sbom_augmentation_failed` event (exit 1, no records), and the 2026-05-26 v0.12.3 run self-healed. Worth wiring up the same validator pattern to `llm_sbom_augmentation` eventually, but it's a separate change — same shape, different prompt, different schemas. **Out of scope for M13.** Queue as M13.1 if M13 ships clean.

## What success looks like

1. Fresh GoPxL BE scan emits **zero parse errors** (or near-zero — say, < 3).
2. Worker logs show the agent invoking `validate-detection-record` many times via Bash (visible in `claude -p`'s tool-use events streamed to the JSONL output).
3. Backend test suite stays green.
4. PROGRESS.md entry: what shipped, what we learned (specifically, whether the model actually self-corrects or just ignores the tool).
5. Version bump 0.12.4 → 0.13.0 (MINOR — new feature, even though backwards-compatible).

## What failure looks like

- Agent doesn't invoke the tool. Add a stronger prompt directive (or add a watchdog in the worker that fails the scan if no validate-detection-record Bash calls appear in the stream).
- Agent invokes the tool, gets FAIL, but emits the record anyway. Same fix — prompt directive must explicitly say "do not emit until OK."
- Agent loops on a malformed record despite the 3-retry cap. Cap is honor-system; if violated, add a hard timeout via wall-clock cap (`CLAUDE_DETECTION_TIMEOUT_MS` already exists).

## Estimated effort

~half day for the basic loop (tool + prompt + smoke test).
~full day if you also want to add structured event logging for tool-call counts (useful for measuring whether the agent actually uses the tool — and for cost auditing).

Drop down to Sonnet for the implementation. The design is the judgment-heavy part and that's already done in this plan.

## Don'ts

- Don't bundle the SBOM-side validator. Separate change.
- Don't remove the existing schema aliases. They're the safety net.
- Don't expose the validator over HTTP — keep it a CLI invoked via Bash inside the claude-p sandbox. HTTP would mean another route, another auth surface, more attack area, for zero benefit.
- Don't push without explicit user approval, per CLAUDE.md.
- Don't burn Opus on mechanical work. Use Sonnet.
