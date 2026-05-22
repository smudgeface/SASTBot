# SASTBot detection pass

Scan the codebase rooted at `{{SCOPE_PATH}}` and report security-relevant
findings. This is the primary SAST pass; you replace Opengrep entirely.

## Inputs

- **Scope path:** `{{SCOPE_PATH}}` (this is your working directory)
- **Repo:** `{{REPO_NAME}}` on branch `{{REPO_BRANCH}}`
- **Ignore paths** (relative to scope; never report findings inside these):
{{IGNORE_PATHS}}
- **Token budget:** `{{TOKEN_BUDGET}}` total (input + output). Self-pace; stop
  early and emit a `complete` record if you sense you're approaching the limit.
- **Known dependency vulnerabilities** — high+critical entries from cdxgen +
  OSV.dev, already persisted in the SASTBot database. **Do NOT re-report
  these.** Use them only for reachability analysis (Goal 2 below). Read this
  file for the list:

      {{SCA_INPUT_PATH}}

  Format: JSON-Lines, one object per line with fields
  `{id, package, version, cve_id, osv_id, cvss_score, summary}`.

## Goals

Two concurrent goals. Don't serialize them — let your file reading inform both
at once.

### Goal 1: SAST findings

Find vulnerability classes such as (non-exhaustive — report anything else
relevant you encounter):

- **Memory safety**: unbounded `strcpy`, `sprintf`, `gets`, `scanf` on
  attacker-influenced data; integer overflow on packet/buffer sizes.
- **Hardcoded credentials**: passwords, API keys, private keys, tokens —
  including in `#define` macros, environment-default constants, and
  config-file defaults.
- **Authentication / authorization**: bypasses, "secure-by-default" violations,
  default-empty passwords, missing access-control checks.
- **Cryptography**: weak primitives (MD5, SHA-1, DES, Blowfish-ECB), missing
  signature verification on firmware/updates, hardcoded IVs/keys, ECB-mode
  ciphers.
- **Injection**: SQL, command, XSS (innerHTML/document.write/eval with user
  data), path traversal, SSRF, XXE.
- **Web**: missing CSRF, wildcard CORS, no TLS, missing security headers
  (CSP / HSTS / X-Frame-Options), postMessage without origin check, insecure
  cookie flags.
- **Protocol parsing**: trusted length fields from network input, missing
  bounds checks in industrial-protocol handlers (Modbus, EtherNet/IP, etc.).
- **Cross-cutting absences** (rare but high-value): findings like "no CSRF
  tokens anywhere in this codebase" or "no TLS implementation present" are
  legitimate even though they can't be pinned to one line. For these, use
  the `kind:"sast_absence"` record shape (see below). Only emit absence
  findings when you've verified the absence by inspecting the relevant
  surface — don't infer it from a single missed match.

### Goal 2: Reachability for known SCA issues

For each entry in the SCA input file, search the codebase for actual call
sites of the vulnerable component or its known-affected APIs. Emit a
`reachability` record per SCA id, including verdicts of "not reachable" — the
absence is useful signal too. Skip records only if you genuinely couldn't
assess (e.g., couldn't determine the affected APIs).

## Field-name discipline

Use EXACTLY these field names. Common drift the schema will reject:

- `file` → use `file_path` instead (applies to ALL record kinds including reachability `call_sites`)
- `title` → use `summary` instead
- `description` → use `reasoning` instead
- omitting `confidence` → always emit; use `0.5` if uncertain
- omitting `reasoning` → always emit; use a brief one-liner

**Reachability records specifically:** the output field is `sca_issue_id` and its value is the `id` field (UUID) from the SCA input file — **not** `cve_id`, `package`, or any other input column. The input columns are context for *your* analysis; the LLM-to-database link goes through the UUID alone. Records that say `"cve":"CVE-XXX"` or `"package":"foo"` instead of `"sca_issue_id":"<uuid>"` get rejected wholesale; the operator sees a parse error and no reachability verdict reaches the database.

If you cannot produce one of the required fields, omit the entire record. Partial records get dropped.

## Output framing — one object per line, no concatenation

Each record is its own line. Do **not** emit two JSON objects back-to-back without a newline between them (`{...}{...}` in a single chunk). The parser is tolerant of same-line concatenation but the rule keeps the stream debuggable for humans tailing logs. When you finish one record, end the line; start the next one fresh.

## Output format (JSON-Lines)

Emit one JSON object **per line** — the entire object on a single line, with
NO embedded newlines and NO pretty-printing. Each line must `JSON.parse`
on its own. Do NOT wrap output in markdown code fences. Do NOT prefix or
suffix records with prose. Stream records as you confirm them. Allowed
shapes (shown below; emit on one line):

### `kind: "sast"` — per-location finding

```
{"kind":"sast","cwe":"CWE-798","severity":"critical","cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","file_path":"GoSensor/GoSensor/Services/Host/GsHostProtocol.h","start_line":68,"end_line":69,"summary":"Hardcoded super-user password defined as macro","confidence":0.98,"reasoning":"Macro grants SuperAccess on any device per GsCore.cpp:2367-2372."}
```

`cvss_vector` is optional. `file_path` must be relative to the scope root.
**Do NOT emit a `snippet` field** — the worker reads the file and builds the
context window itself. See the system prompt's "Line range" section.

**`start_line` precision:** point at the exact line of code that *contains*
the vulnerability — the unsafe call, the unsafe assignment, the macro
definition with the secret. Do NOT point at surrounding scaffolding
(route declarations, function signatures, opening braces, comments).
`start_line` is used to fingerprint the issue across scans; pointing at
the wrong line creates duplicate findings on the next scan.

### `kind: "sast_absence"` — cross-cutting absence finding

```
{"kind":"sast_absence","cwe":"CWE-352","severity":"high","summary":"No CSRF protection on any state-changing endpoint","evidence_file":"GoSensor/GoSensor/Services/Http/GsHttpServer.cpp","evidence_line":193,"confidence":0.9,"reasoning":"Searched the entire HTTP server and all express routes; no csurf middleware, no SameSite cookie config, no CSRF token validation logic anywhere. evidence_file points to a representative state-changing endpoint."}
```

`evidence_file` and `evidence_line` should point at a representative location
(a single endpoint, a config file, etc.) that anchors the absence. They are not
"the bug" — there is no single bug — but they give a triager somewhere to land.

### `kind: "reachability"` — SCA reachability verdict

```
{"kind":"reachability","sca_issue_id":"abc123-...","reachable":true,"confidence":0.85,"call_sites":[{"file_path":"src/utils.js","line":42}],"reasoning":"lodash.template called with a user-controlled string in BuildManager."}
```

For `reachable: false`, omit `call_sites` (or pass an empty array) and explain
in `reasoning` what you searched for.

### `kind: "complete"` — terminating record

```
{"kind":"complete","sast_count":42,"sast_absence_count":3,"reachability_count":12,"summary":"Done. 3 critical, 14 high. 12 high+critical SCA issues had reachable call sites."}
```

Always emit this as your final line, even if all counts are zero.

## Consolidation — emit ONE finding per weakness, not one per CWE label

When several CWEs describe the *same underlying weakness* in the *same code
region* (a single function, or a contiguous range of ~50 lines or fewer),
emit **one** `sast` record using the **broadest** CWE from the family below.
Mention the related CWEs in `summary` so a triager still sees the full
context. Do not emit separate findings just because the same problem can be
labeled multiple ways — that produces three or four rows for what an
operator reads as one issue.

**CWE families** (broadest first; use the first one when consolidating):

- **Integrity / authenticity:** CWE-345 (broadest), CWE-346, CWE-347, CWE-353, CWE-494
- **Injection:** CWE-74 (broadest), CWE-77, CWE-78, CWE-89, CWE-94, CWE-917
- **Path / file traversal:** CWE-22 (broadest), CWE-23, CWE-36, CWE-73
- **Crypto weakness:** CWE-327 (broadest), CWE-326, CWE-328, CWE-330, CWE-338
- **Authentication / credentials:** CWE-287 (broadest), CWE-259, CWE-306, CWE-798

### Worked example

A firmware upgrade routine in `Core/GsCoreUpgrade.cpp` downloads a binary,
skips signature checks, and applies it. You could legitimately label this
finding as CWE-345 (insufficient authenticity verification), CWE-347
(improper signature verification), or CWE-494 (download without integrity
check). All three fit. Emit one record, not three:

```
{"kind":"sast","cwe":"CWE-345","severity":"critical","file_path":"Core/GsCoreUpgrade.cpp","start_line":246,"end_line":269,"summary":"Firmware update applied without authenticity verification. Related: CWE-347 (no signature check on the downloaded blob), CWE-494 (download-then-execute with no integrity check).","confidence":0.95,"reasoning":"GsCoreUpgrade::ApplyUpdate at L246-269 invokes the loader on the downloaded payload with no Verify*() call in between; no hash, no signature, no pinning."}
```

If two *unrelated* weaknesses happen to share a code region (e.g. hardcoded
credentials AND a path traversal in the same function), keep them as
separate findings — the consolidation rule applies only within one CWE
family.

### `sast` plus `sast_absence` redundancy

If you already emitted a per-line `sast` finding that covers a gap (e.g. a
`sast` with CWE-347 pointing at the line that should have had a signature
check), do NOT also emit a `sast_absence` with the same CWE pointing at
the same region. The per-line finding already captures the absence.
`sast_absence` is for cross-cutting absences that have *no* single
representative line — "no CSRF middleware anywhere", "no TLS implementation
present" — not for restating per-line findings in a different shape.

## Methodology

1. Start with `find . -type f` and a quick `ls` to map the project layout.
2. Run targeted `grep` / `rg` passes for known-dangerous identifiers
   (`strcpy`, `eval(`, `password\s*=`, `#define\s+\w*PASSWORD`, `innerHTML`,
   etc.). Read matching files in full when context warrants.
3. Cross-reference call sites against the SCA input file as you encounter
   them — don't do a separate dedicated reachability pass.
4. Emit findings as you confirm them. Don't buffer everything to the end; the
   orchestrator streams your output and persists incrementally.
5. When you've covered the major attack surfaces or you sense you're
   approaching the token budget, emit `kind: "complete"` and stop.

Begin.
