# SASTBot re-check pass

The previous scan detected the issues listed below. The latest detection pass
did NOT re-report them. Before we mark them as fixed, verify each one in place.

This is a low-budget, high-precision job. You are answering a yes/no question
per issue based on direct file inspection. No exploration, no extra scanning,
no new findings.

## Inputs

- **Scope path:** `{{SCOPE_PATH}}` (this is your working directory)
- **Token budget:** `{{TOKEN_BUDGET}}` (focused pass — should be a fraction of
  the detection budget)
- **Issues to verify** — read from this file:

      {{ISSUES_INPUT_PATH}}

  Format: JSON-Lines, one object per line with fields
  `{id, file_path, start_line, summary, snippet, cwe}`.

- **Duplicate targets** ({{DUPLICATE_TARGETS_COUNT}} rows) — other active SAST
  issues in this scope that a candidate could be a relocated / re-labeled
  variant of. Read from this file (may be empty):

      {{DUPLICATE_TARGETS_PATH}}

  Format: JSON-Lines, one object per line with fields
  `{id, file_path, start_line, cwe, summary}`. Use this list when deciding whether to
  emit a `duplicate_of` verdict (see below).

## What to do

For each issue in the input file, in the order it appears:

1. Try reading the file at the cited path, around the cited line (±10 lines for
   context).

2. **If the file exists at the cited path:**
   - If the same vulnerability is still present in any recognizable form
     (reformatted, renamed, but the same bug) → **`still_present`**.
   - If the vulnerability is materially gone (call removed, macro deleted,
     unsafe function replaced with a safe one, hardcoded value replaced with
     a config lookup, etc.) → **`fixed`**.

3. **If the file does NOT exist at the cited path:**
   - Search the rest of the codebase (Bash with `rg` or `grep -r`) for the
     distinctive content of the previous `snippet` — pick what's most likely
     to survive a refactor: the literal string value, the macro name, the
     unique function call, the rule identifier.
   - If found at a new location → **`still_present`**. Note the relocation
     in `reasoning` (e.g., "moved from src/old.c to src/new.c after
     refactor"). The worker will refresh the snippet from disk; you don't
     need to populate `current_snippet`.
   - If not found anywhere in the scope → **`file_deleted`**.

4. **Before finalizing a still_present verdict**, scan the duplicate-targets
   file for an existing active issue that describes the same underlying
   weakness. If you find one, emit **`duplicate_of`** instead of
   `still_present` and reference the target's id (see Duplicates below).

When uncertain, default to **`still_present`**. Marking something fixed
prematurely is the more harmful error here — a duplicate finding is recoverable,
a falsely-closed one is not. Marking something `duplicate_of` the wrong target
is similarly destructive (the candidate row is deleted); only emit
`duplicate_of` when you can point at the target's id and explain in
`reasoning` why the two are the same bug.

## Duplicates

The detection pass already consolidates CWE labels within one code region
(see `sast_detection.md`'s Consolidation section). Recheck catches the
cases the same-scope merger can't: a finding's location moved across scans
(file rename, function extracted into a new file, macro relocated to a
different header) and the new scan emits it at a different `file_path`.

Emit a `duplicate_of` verdict when **all** are true:

- The candidate's underlying weakness is the same code-level bug as the
  target's. Different CWE labels are fine if they belong to the same family
  (integrity, injection, path traversal, crypto, authentication — see
  `sast_detection.md`); different files / lines are exactly the case this
  verdict exists for.
- You can read both the candidate's prior `snippet` AND the target's
  current code, and they describe the same weakness.
- The target's id is in the duplicate-targets file.

Do NOT emit `duplicate_of` to consolidate findings whose CWEs are
unrelated, or to fold a candidate into a target that just happens to
share a file. When in doubt, prefer `still_present`.

## Output format (JSON-Lines)

Exactly one record per input issue, in the input order. No extras.

```json
{"id":"<issue-id>","verdict":"still_present","reasoning":"#define moved from GsHostProtocol.h to GsHostProtocolDefs.h:23; macro value is unchanged."}
{"id":"<issue-id>","verdict":"fixed","reasoning":"strcpy at line 42 replaced with strncpy with explicit length check at line 41."}
{"id":"<issue-id>","verdict":"file_deleted","reasoning":"src/legacy/auth.c is no longer present; grep for macro name across scope returned no matches."}
{"id":"<issue-id>","verdict":"duplicate_of","duplicate_of":"<target-issue-id>","reasoning":"Same firmware upgrade-without-verification weakness; the previous scan flagged it at Core/GsCoreUpgrade.cpp:210 (CWE-345), this scan emits the same bug at Core/Upgrade/GsUpgradeApply.cpp:88 (CWE-494) after the file split — both point at the same unsigned ApplyUpdate() call."}
```

You no longer need to emit `current_snippet`; the worker refreshes the
snippet from disk for any `still_present` verdict. (The field is still
accepted as fallback for older orchestrator versions.)

When done, emit a terminating record:

```json
{"kind":"complete","verified":N,"still_present":X,"fixed":Y,"file_deleted":Z,"duplicate_of":D}
```

Begin.
