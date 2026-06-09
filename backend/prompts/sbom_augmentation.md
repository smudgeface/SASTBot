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

Read `{{SBOM_FILE}}`. **Silence means keep** — components you don't emit a
record for are kept as-is. Do NOT emit a bare `keep` record for every
component; only emit records when you have something to say:

- Emit `{"type":"drop","component_id":"<id>","reason":"<reason>"}` if:
  - Its name starts with a FIRST_PARTY_NAMESPACES prefix, OR
  - It's test-only, build-only, or a .NET BCL assembly, OR
  - You read the source and confirmed it doesn't ship in the product.

  **Do not drop a component whose origin is cdxgen `manifest` discovery
  unless you can point to disconfirming evidence in the source tree.**
  cdxgen sourced it from a real package manifest (package.json, .csproj,
  .vcxproj, etc.) — that's stronger evidence than your guess. If you're
  unsure whether a manifest-sourced component is "really" used, keep.
- Emit `{"type":"keep","component_id":"<id>","llm_reason":"<one-sentence rationale>"}`
  **only** when you inspected the source and can confirm the component's
  role in one sentence (this becomes the evidence tooltip in the UI). A
  `keep` without `llm_reason` is wasted output — skip it.

Only drop if you're confident. When in doubt, stay silent (= keep).

### Step 2 — Inspect vendored directories

Inspect each directory listed in VENDORED_DIRS. **Additionally**, do a quick
Glob check at the repo root for common vendored-dir conventions even if they
weren't listed: `libs/`, `extlib/`, `third_party/`, `externals/`, `ext/`,
`deps/`, `lib/external/`. If any exist, treat them the same as
VENDORED_DIRS entries.

For each subdirectory that looks like a vendored library:

1. Read `README`, `CHANGELOG`, `version.h`, `CMakeLists.txt`,
   `package.json`, or similar version-bearing files to determine:
   - Library name
   - Version (or "unknown" if you can't determine it)
   - License (optional; skip if not obvious from a header)
2. **Then list the directory's top-level files.** Vendored directories
   often ship bundled binaries from multiple upstream projects — e.g.,
   `extern/gettext/` typically contains `libexpat-*.dll`, `libiconv-*.dll`,
   `WinSparkle.dll` etc. alongside the main `gettext` binaries. Each
   bundled `.dll` / `.js` / `.so` / standalone tool is its own component;
   emit a separate `add` record for each one you can name.
3. Emit an `add` record **only** if the library is NOT already in the SBOM
   (check `component_id` values from the file you read in Step 1).
4. If the subdirectory is clearly first-party code (matches
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
they're real (found in a build file or #include), stay silent (= keep). If
you can't find any evidence, emit a drop with
`reason: "no evidence found in source tree"`.

### Step 5 — CPE enrichment (labeling-only)

This step is **purely additive labeling**. It does NOT change which
components you keep, drop, or add — those decisions are governed entirely
by Steps 1–4. Whatever vendored libraries Steps 2–3 surfaced from
VENDORED_DIRS, runtime-SDK references, etc. — add them ALL, regardless
of CPE availability.

When emitting a `keep` or `add` record for a `pkg:generic/...` component
or any C/C++ library, optionally include a `cpe` field with the canonical
**CPE 2.3** string IF you happen to know it. If you don't know the
canonical CPE — especially for vendor-specific hardware/SDK libraries
(FTDI, Thorlabs, Zaber, Heidenhain, Moxa, National Instruments, LabJack,
MCC, Nerian, Adimec, …) — just omit the field. Vendor SDKs typically have
no published CPE; that's expected, and they MUST still be added/kept.

A wrong CPE is worse than no CPE, so when in doubt, omit.

Why: SASTBot queries NVD using CPE for precise CVE matching when the
field is present, and falls back to a keyword search when it's not. So
omitting the CPE doesn't hide the component — it just makes the NVD
query a bit less precise.

Examples of well-known CPE strings:
- `zlib` → `cpe:2.3:a:zlib:zlib:<version>:*:*:*:*:*:*:*`
- `libgit2` → `cpe:2.3:a:libgit2_project:libgit2:<version>:*:*:*:*:*:*:*`
- `OpenSSL` → `cpe:2.3:a:openssl:openssl:<version>:*:*:*:*:*:*:*`
- `freetype` / `FreeType` → `cpe:2.3:a:freetype:freetype:<version>:*:*:*:*:*:*:*`
- `libpng` → `cpe:2.3:a:libpng:libpng:<version>:*:*:*:*:*:*:*`
- `curl` → `cpe:2.3:a:haxx:curl:<version>:*:*:*:*:*:*:*`
- `expat` / `libexpat` → `cpe:2.3:a:libexpat_project:libexpat:<version>:*:*:*:*:*:*:*`
- `sqlite` → `cpe:2.3:a:sqlite:sqlite:<version>:*:*:*:*:*:*:*`
- `libjpeg-turbo` → `cpe:2.3:a:libjpeg-turbo:libjpeg-turbo:<version>:*:*:*:*:*:*:*`

If the component has a known version, fill it in; otherwise use `*`.
Omit the `cpe` field entirely for npm/pypi/maven/nuget components and for
any C/C++ library whose canonical CPE you don't already know.

## Pacing

No fixed token budget. Self-pace; a wall-clock cap is the backstop.
If you must stop early, finish the current step and emit what you have so far.
Partial coverage is better than no output.

## Output

JSON-Lines to stdout. No prose between records. Records from all steps can
be interleaved — the orchestrator processes them in whatever order you emit.
