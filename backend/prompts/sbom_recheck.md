# SBOM Component Recheck Task

## Working directory

Your working directory is the clone of the repository scoped to:

    {{SCOPE_PATH}}

All file paths you inspect are relative to this working directory. Use Glob,
Grep, Read, and Bash to explore freely.

## Tasks

You have two tasks in this session. Complete **Task 1 first**, then **Task 2**.

**Pacing:** No fixed token budget. Self-pace; a wall-clock cap is the backstop.
Work through candidates in order.

---

## Task 1 — Verify missing candidates

The automated SBOM scanner ran successfully but did not surface the components
listed in `{{CANDIDATES_PATH}}`. For each component, determine whether it is
still present in the codebase (scanner missed it) or genuinely removed.

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

**Important:** Only emit presence/absence verdicts for components in THIS file.
Do not emit verdicts for other components.

### Search strategy

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

---

## Task 2 — Identify duplicate components

The file at `{{ALL_COMPONENTS_PATH}}` lists ALL active components currently in
the scope inventory (not just the missing candidates). Each line has:

```json
{"id":"<uuid>","name":"<name>","version":"<version or null>","purl":"<purl>","cpe":"<cpe or null>","evidence_path":"<path or null>","llm_reason":"<string or null>"}
```

Review this list and identify groups of rows that refer to the same upstream
library. For each duplicate group, emit one `merge` verdict:

```json
{"type":"merge","keep_id":"<id>","drop_ids":["<id>","..."],"rationale":"<one sentence>"}
```

**Signals to look for:**

- Same CPE product family ignoring version (e.g. `cpe:2.3:a:xenomai:xenomai:*`
  and `cpe:2.3:a:xenomai:xenomai:3.1` → same library)
- Same `evidence_path` shared by two rows
- Rows under the same `extern/`, `vendor/`, or `third-party/` subdirectory
  with clearly related names ("Foo SDK" / "foo-sdk" / "foo-bar-lib")
- LLM alias variants where `llm_reason` describes the same vendored library

**Pick `keep_id` as the richest row:** prefer concrete version over wildcard,
prefer evidence_path present, prefer most-recent row as tiebreaker.

**Be conservative:** only emit a merge when highly confident. If uncertain,
skip — missed merges create noise that is easier to live with than lost data.

Merge verdicts may interleave freely with presence/absence verdicts.

---

## Output format

Emit all verdicts as JSON-Lines (one object per line) to stdout. No prose.
No markdown fences. See the system prompt for the full schema.
