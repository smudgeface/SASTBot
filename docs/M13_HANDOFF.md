# M13 Handoff — LLM record self-validation tool

Paste the section below verbatim into the new session's first message.

---

## Handoff: implement M13 LLM record self-validation tool

**Goal.** Replace the reactive schema-alias chase with a proactive self-correction loop: detection agent invokes a `validate-detection-record` CLI before emitting each record; on FAIL, agent fixes and retries. Plan lives at `docs/M13_PLAN.md` — read it first.

**Branch state.** Start from `main` at v0.12.4, fully pushed (most recent: `ae7d8da fix(sast): accept sca_reachability kind alias; bump 0.12.4`). Backend tests green (367/367, run `--no-file-parallelism`). No uncommitted state expected.

**Orient in ≤ 3 tool calls:**

```bash
git log --oneline -10
tail -120 docs/PROGRESS.md   # context for v0.12.0 → v0.12.4 + the drift-chase pattern
cat docs/M13_PLAN.md         # the plan, locked decisions, success criteria
```

CLAUDE.md auto-loads. The 🔖 versioning pin and 📖 manual-currency pin still apply.

**Read first:** `backend/src/services/llmSastService.ts` lines 38-240 (the four record schemas + ConfidenceSchema + the seven aliases we've shipped). The validator's job is exposing this union's `.safeParse` behavior to claude-p as a callable CLI.

**Build order (per M13_PLAN.md):**

1. **Create `backend/src/cli/validate-detection-record.ts`** — reads JSON on stdin, calls `DetectionRecord.safeParse`, writes `OK` (exit 0) or `FAIL: <reason>` (exit 1). Sample code in the plan.

2. **Register as a `bin` entry in `backend/package.json`** so it's on `$PATH` inside the worker container (claude-p runs from there). The worker already has Bash in `--allowed-tools`, so no permission change.

3. **Update `backend/prompts/sast_detection.md`** with the self-validation paragraph (sample text in the plan). Cap retries at 3 per record — the cap is honor-system, enforced by the prompt directive.

4. **Test the CLI directly first.** Write a vitest that exercises the tool with a few drift-shaped JSON inputs (including the GoPxL BE shapes: `cwe_id`, string confidence, `sca_reachability`, summary-less absence). Confirm reasons are intelligible.

5. **Smoke-test against a real scan.** Trigger an FSS scan (cheaper than GoPxL BE — $3-4 vs $7-8). Watch worker logs for the agent invoking `validate-detection-record` via Bash. Final parseError count should be **lower** than v0.12.4 baseline (target: zero).

6. **PROGRESS.md entry.** Honest: did the model actually self-correct, or did it ignore the tool? That's the headline.

7. **Version bump.** 0.12.4 → **0.13.0** (MINOR — new feature, backwards-compatible). Three files + lockfile per CLAUDE.md "⚠️ Versioning policy". After bump, `curl -s http://localhost:8000/version | jq .app` must show `0.13.0`.

8. **Restart worker after worker-side code changes** — `tsx src/worker.ts` doesn't auto-reload. `docker compose -f docker/compose/docker-compose.yml --env-file .env restart backend worker`. After restart, frontend container needs `stop && up -d` (not `restart`) to clear the Colima stuck-socket issue documented in CLAUDE.md.

9. **Commit.** Single commit, message describes intent. Don't push without user approval.

**Locked decisions (from M13_PLAN.md — don't re-litigate):**

- Keep the existing schema aliases. They're the safety net; the validator is best-effort.
- Validator returns `OK` / `FAIL: <reason>` only. No "did you mean" hints — schema aliases already catch the known drift.
- Detection-side only for M13. Recheck has zero parse errors historically; SBOM is a separate change (M13.1).
- Don't expose the validator over HTTP — CLI invoked via Bash inside the claude-p sandbox.

**Model selection:**

- Sonnet for implementation (mechanical).
- Stay on Opus only if you hit an unexpected design question that's not addressed in M13_PLAN.md.

**Open knobs for the user (ask before deciding):**

- Smoke-test repo — FSS (cheaper) or GoPxL BE (matches today's failure case)?
- If the agent ignores the tool: stronger prompt directive, or hard-fail the scan if no validate calls appear in the stream?

**What success looks like:** zero parse errors on a fresh detection run + worker log shows tool calls + tests green. The plan's "What success looks like" section enumerates this.

**What failure looks like (and how to recover):** see the M13_PLAN.md "What failure looks like" section. Three known failure modes, each with a fix.

**Pending queue you might encounter:** `project_pending_features` memory has a sizable list. Don't accidentally pull one of those into this PR.

**Don'ts:**

- Don't bundle the SBOM-side validator into this PR.
- Don't remove existing aliases.
- Don't push without user approval.
- Don't skip the version bump.
- Don't restart worker mid-scan if a user has one running — check the DB first.
