# SBOM Component Recheck Task

## Working directory

Your working directory is the clone of the repository scoped to:

    {{SCOPE_PATH}}

All file paths you inspect are relative to this working directory. Use Glob,
Grep, Read, and Bash to explore freely.

## Task

The automated SBOM scanner ran successfully but did not surface the components
listed below. For each component, determine whether it is still present in the
codebase (scanner missed it) or genuinely removed.

**Token budget:** {{TOKEN_BUDGET}} tokens. Work through candidates in order.
Stop emitting verdicts if you approach the budget.

## Candidate components

The file at `{{CANDIDATES_PATH}}` contains the candidate components as
JSON-Lines. Each line has this shape:

```json
{"component_id":"<uuid>","name":"<name>","version":"<version or null>","evidence_path":"<path or null>","prior_reason":"<string or null>"}
```

- `component_id` — round-trip key; include it verbatim in your verdict.
- `name` + `version` — what to search for.
- `evidence_path` — the file where the component was previously found
  (repo-relative). May be null for manifest-discovered components.
- `prior_reason` — why the component was previously added to the inventory.
  Use this for context when searching.

## Search strategy

For each candidate:

1. If `evidence_path` is non-null: check whether the file exists and still
   references this component. A missing or changed file is a strong signal.
2. Grep for the component name (and version if available) across the codebase.
   Try `grep -r "<name>" .` from the scope working directory, focusing on:
   - Vendored directories (`extern/`, `vendor/`, `third-party/`, etc.)
   - CMakeLists.txt, vcxproj, csproj, package.json, pyproject.toml
   - Any file mentioned in `evidence_path`
3. If `prior_reason` describes a specific location, check there first.
4. Emit your verdict for this candidate before moving to the next.

## Output

One verdict per candidate line from the input file, in the same order.
Emit each verdict as a single JSON-Lines object:

```
{"component_id":"<id>","verdict":"present","rationale":"<one sentence>"}
{"component_id":"<id>","verdict":"present","new_evidence_path":"<new path>","rationale":"<one sentence>"}
{"component_id":"<id>","verdict":"removed","rationale":"<concrete evidence>"}
```

Only emit `"removed"` when you have clear evidence. Default to `"present"` when
uncertain. See the system prompt for details.
