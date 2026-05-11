# SBOM Augmentation Task

## Working directory

Your working directory is the clone of the repository scoped to:

    {{SCOPE_PATH_LABEL}}

All file paths you inspect are relative to this working directory. Use Glob,
Grep, and Read to explore freely.

## Input SBOM

The Stage-1-cleaned cdxgen SBOM is at:

    {{SBOM_FILE}}

Read it first. Each object in the `components` array has a `component_id`
field — this is the canonical key you MUST use in your output records.

## Repo-specific configuration

**FIRST_PARTY_NAMESPACES** — name prefixes the operator marks as in-house.
Drop any SBOM component whose name starts with one of these (case-insensitive).
Also drop any vendored directory that's clearly first-party code:

{{FIRST_PARTY_NAMESPACES}}

**VENDORED_DIRS** — directories to inspect for vendored third-party libraries
that cdxgen missed:

{{VENDORED_DIRS}}

## Task

### Step 1 — Review the SBOM

Read `{{SBOM_FILE}}`. For each component:

- Emit `{"type":"keep","component_id":"<id>"}` if it's a legitimate
  third-party runtime dependency.
- Emit `{"type":"drop","component_id":"<id>","reason":"<reason>","evidence_path":"<optional>"}` if:
  - Its name starts with a FIRST_PARTY_NAMESPACES prefix, OR
  - It's test-only, build-only, or a .NET BCL assembly, OR
  - You read the source and confirmed it doesn't ship in the product.
- Add an optional `"llm_reason"` field to a `keep` record when you inspected
  the source and can confirm the component's role in one sentence.

Only drop if you're confident. When in doubt, keep.

### Step 2 — Inspect vendored directories

For each directory listed in VENDORED_DIRS, use Glob to list its immediate
subdirectories. For each subdirectory that looks like a vendored library:

1. Read `README`, `CHANGELOG`, `version.h`, `CMakeLists.txt`,
   `package.json`, or similar version-bearing files to determine:
   - Library name
   - Version (or "unknown" if you can't determine it)
   - License (optional; skip if not obvious from a header)
2. Emit an `add` record **only** if the library is NOT already in the SBOM
   (check `component_id` values from the file you read in Step 1).
3. If the subdirectory is clearly first-party code (matches
   FIRST_PARTY_NAMESPACES or has the org's own copyright header), skip it.

### Step 3 — Check for runtime SDK/toolset dependencies

Scan `.csproj`, `packages.config`, `.sln`, and `CMakeLists.txt` files for
explicit references to runtime SDKs or compiler toolsets that cdxgen doesn't
surface as components. Common patterns:

- `<PlatformToolset>v120</PlatformToolset>` → MSVC Runtime 2013 (v12.0)
- `<PlatformToolset>v140</PlatformToolset>` → MSVC Runtime 2015 (v14.0)
- `<PlatformToolset>v141</PlatformToolset>` → MSVC Runtime 2017 (v14.1)
- `<PlatformToolset>v142</PlatformToolset>` → MSVC Runtime 2019 (v14.2)
- References to `gettext` in Makefile or CMake → GNU gettext
- `.ini` or database files with GeoIP / IP-to-country credits → that DB

Emit `add` records for these if they're real runtime dependencies and not
already in the SBOM.

### Step 4 — Verify any suspicious cdxgen singletons

Components that look unusual (a single Boost reference, a database file
dependency, a very old version) — briefly grep for them. If you can confirm
they're real (found in a build file or #include), keep. If you can't find
any evidence, drop with `reason: "no evidence found in source tree"`.

## Token budget

Target output tokens: `{{TOKEN_BUDGET}}` total for this session. Self-pace.
If you're approaching the limit, stop after finishing the current step and
emit what you have so far. Partial coverage is better than no output.

## Output

JSON-Lines to stdout. No prose between records. Records from all steps can
be interleaved — the orchestrator processes them in whatever order you emit.
