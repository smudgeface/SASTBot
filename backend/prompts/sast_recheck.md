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
  `{id, file, line, summary, snippet, cwe}`.

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
   - If found at a new location → **`still_present`**. Populate
     `current_snippet` from the new location and note the relocation in
     `reasoning` (e.g., "moved from src/old.c to src/new.c after refactor").
   - If not found anywhere in the scope → **`file_deleted`**.

When uncertain, default to **`still_present`**. Marking something fixed
prematurely is the more harmful error here — a duplicate finding is recoverable,
a falsely-closed one is not.

## Output format (JSON-Lines)

Exactly one record per input issue, in the input order. No extras.

```json
{"id":"<issue-id>","verdict":"still_present","reasoning":"#define moved from GsHostProtocol.h to GsHostProtocolDefs.h:23; macro value is unchanged.","current_snippet":"#define GS_SUPER_USER_PASSWORD \"Gocator3D\""}
{"id":"<issue-id>","verdict":"fixed","reasoning":"strcpy at line 42 replaced with strncpy with explicit length check at line 41."}
{"id":"<issue-id>","verdict":"file_deleted","reasoning":"src/legacy/auth.c is no longer present; grep for macro name across scope returned no matches."}
```

`current_snippet` is required for `still_present` (use the 7-line snippet rule
from the system prompt). Omit it for `fixed` and `file_deleted`.

When done, emit a terminating record:

```json
{"kind":"complete","verified":N,"still_present":X,"fixed":Y,"file_deleted":Z}
```

Begin.
