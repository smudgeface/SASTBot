import { execFile } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { toRepoRelative } from "./scopePath.js";
import { extractOccurrences, resolveManifestLines, ScopeFileIndex } from "./sbomOccurrences.js";
import type { ComponentOccurrence } from "./sbomOccurrences.js";

import { Prisma } from "@prisma/client";
import type { PrismaClient, SbomComponent } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import { prisma } from "../db.js";

const execFileAsync = promisify(execFile);
const logger = pino({ level: loadConfig().logLevel, name: "sbomService" });

// ---------------------------------------------------------------------------
// CycloneDX 1.7 shape (subset we care about)
// ---------------------------------------------------------------------------

interface CdxLicenseEntry {
  license?: { id?: string; name?: string };
  expression?: string;
}

interface CdxIdentityMethod {
  technique?: string; // e.g. "manifest-analysis"
  value?: string;     // path on disk where the dep was discovered
}

interface CdxIdentity {
  field?: string;
  methods?: CdxIdentityMethod[];
}

interface CdxEvidence {
  identity?: CdxIdentity[] | CdxIdentity;
  occurrences?: { location?: string }[];
}

interface CdxProperty {
  name?: string;
  value?: string;
}

export interface CdxComponent {
  type?: string;
  group?: string;
  name?: string;
  version?: string;
  purl?: string;
  licenses?: CdxLicenseEntry[];
  evidence?: CdxEvidence;
  properties?: CdxProperty[];
  scope?: string;
}

export interface CycloneDxDocument {
  bomFormat?: string;
  specVersion?: string;
  components?: CdxComponent[];
  [k: string]: unknown;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function extractEcosystem(purl: string | undefined): string | null {
  if (!purl) return null;
  const m = purl.match(/^pkg:([^/]+)\//);
  return m ? m[1] : null;
}

/**
 * Build the canonical package name from cdxgen's `group` + `name` fields.
 * cdxgen splits scoped/namespaced packages: e.g. `@types/node` arrives as
 * group=`@types`, name=`node`. The bare name alone collides with unrelated
 * packages — most notably `@types/node` was matching the eolService slug
 * map for the Node.js runtime, producing bogus EOL alerts.
 *
 * Per-ecosystem joiner:
 *   - npm:    `@scope/name` (slash, matches OSV.dev's npm package format)
 *   - maven:  `groupId:artifactId` (colon, matches OSV.dev's Maven format)
 *   - other:  fall back to slash; revisit when those ecosystems land
 */
export function canonicalPackageName(c: CdxComponent, ecosystem: string | null): string {
  const name = c.name ?? "unknown";
  if (!c.group) return name;
  const sep = ecosystem === "maven" ? ":" : "/";
  return `${c.group}${sep}${name}`;
}

export function extractLicenses(entries: CdxLicenseEntry[] | undefined): string[] {
  if (!entries) return [];
  return entries
    .map((e) => e.license?.id ?? e.license?.name ?? e.expression ?? null)
    .filter((l): l is string => l !== null);
}

/**
 * Read cdxgen's npm dev-only marker. cdxgen 12.2+ emits
 * `cdx:npm:package:development=true` as a property on components whose npm
 * lockfile entry has `dev: true`. npm-only signal today; absent ⇒ treat as
 * not-known-dev (conservative — keeps the component in scans).
 *
 * Caveat: cdxgen issue #3927 — `devOptional: true` lockfile entries miss the
 * marker. A small fraction of dev-only packages will read as false. v1
 * accepts this; revisit if it bites.
 */
export function extractIsDevOnly(c: CdxComponent): boolean {
  return c.properties?.some(
    (p) => p.name === "cdx:npm:package:development" && p.value === "true",
  ) ?? false;
}

/**
 * Extract the manifest file path that cdxgen attributed this component to,
 * relative to the scope's working directory. cdxgen exposes it twice:
 *   1. `properties[].name === "SrcFile"` (universal across project types)
 *   2. `evidence.identity[].methods[].technique === "manifest-analysis"`
 * We try (1) first, falling back to (2). Returns null if neither is present.
 */
export function extractManifestFile(c: CdxComponent, scopeDir: string): string | null {
  const srcFile = c.properties?.find((p) => p.name === "SrcFile")?.value;
  let abs: string | undefined = srcFile;
  if (!abs && c.evidence?.identity) {
    const identities = Array.isArray(c.evidence.identity) ? c.evidence.identity : [c.evidence.identity];
    for (const ident of identities) {
      for (const m of ident.methods ?? []) {
        if (m.technique === "manifest-analysis" && m.value) {
          abs = m.value;
          break;
        }
      }
      if (abs) break;
    }
  }
  if (!abs) return null;
  return normalizeManifestPath(abs, scopeDir);
}

/**
 * Normalize a cdxgen-emitted path to a scope-relative form (no leading slash,
 * no clone-root prefix). Callers feed this into `toRepoRelative(scopePath, …)`
 * to get a repo-rooted path for storage.
 *
 * cdxgen 12.x emits paths in several inconsistent shapes depending on the
 * project type and how it bootstraps its tmp working tree:
 *   - absolute under scopeDir            (`/app/clones/<uuid>/foo/pkg.lock`)
 *   - relative under /app                (`clones/<uuid>/foo/pkg.lock`)
 *   - parent-relative                    (`../clones/<uuid>/foo/pkg.lock`)
 *   - tmp ephemeral working tree         (`/tmp/sastbot-repo-<uuid>/foo/pkg.lock`)
 *   - already repo-relative              (`foo/pkg.lock`)
 *
 * Strategy: try strict scopeDir prefix first; otherwise look for the canonical
 * `clones/<UUID>/` segment (or its tmp-root analog) and strip up to and
 * including it. Falls back to basename as a last resort so the operator never
 * sees a leaked clone path on the "Declared in" link.
 */
export function normalizeManifestPath(abs: string, scopeDir: string): string {
  if (abs.startsWith(scopeDir + "/")) return abs.slice(scopeDir.length + 1);

  // /…/clones/<UUID>/<rest>  or  …/clones/<UUID>/<rest>
  const cloneMatch = abs.match(
    /(?:^|\/)clones\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(.+)$/i,
  );
  if (cloneMatch) {
    const afterClone = cloneMatch[1]!;
    // For sub-scopes, scopeDir basename is the scope segment (e.g. "GoWeb");
    // strip it so the result is scope-relative, mirroring the prefix-strip
    // branch above.
    const scopeBase = scopeDir.split("/").pop();
    if (scopeBase && afterClone.startsWith(scopeBase + "/")) {
      return afterClone.slice(scopeBase.length + 1);
    }
    return afterClone;
  }

  // …/sastbot-repo-<UUID>/<rest> — cdxgen ephemeral tmp tree.
  const tmpMatch = abs.match(
    /(?:^|\/)sastbot-repo-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/(.+)$/i,
  );
  if (tmpMatch) return tmpMatch[1]!;

  // M6q cdxgen-cwd fix: cdxgen now emits paths already scope-relative
  // (e.g. "kJs/package-lock.json"). If `abs` has no leading slash and
  // doesn't look like a tmp/clone leak we missed, trust it verbatim —
  // basename-truncation here loses the subdirectory and yields wrong
  // links like "GoWeb/package-lock.json" pointing at a nonexistent file.
  if (!abs.startsWith("/") && !abs.startsWith("..") && !/\/(?:clones|tmp|sastbot-repo-)/.test(abs)) {
    return abs;
  }

  // Last resort: just the basename. Only reached now if `abs` looked
  // tmp/clone-rooted but the regex above failed to strip a recognisable
  // prefix — still better than leaking a tmp/clone path into source URLs.
  const lastSlash = abs.lastIndexOf("/");
  return lastSlash >= 0 ? abs.slice(lastSlash + 1) : abs;
}

// ---------------------------------------------------------------------------
// Stage 1 — Mechanical post-processing (M6p)
//
// A pure function over the raw cdxgen CdxComponent array. No I/O, no DB,
// no LLM calls. Called from `persistComponents` (and optionally from the
// Stage-2 service) before any writes. Each rule is a separate function so
// they can be unit-tested in isolation.
// ---------------------------------------------------------------------------

/**
 * (a) CMake-internal / MSBuild pseudo-packages that appear as find_package()
 * results but are not real third-party components. Match on `name` exactly
 * (case-insensitive), ecosystem = "generic" or null.
 *
 * M6p — extend this list when new pseudo-packages appear; each entry has a
 * one-line comment so future maintainers know why it's here.
 */
const CMAKE_INTERNAL_BLOCKLIST = new Set([
  "threads",          // CMake built-in: pthread / win32 threads abstraction
  "pythoninterp",     // CMake FindPythonInterp.cmake — build-tool dep, not shipped
  "python",           // bare "Python" from FindPython.cmake (not python3-* packages)
  "sanitizers",       // CMake sanitizer helper — compile-time, not shipped
  "packagetest",      // CMake CTest package entry — test runner, not a dep
  "googletest-distribution", // CMake FetchContent entry for googletest — test-only
]);

/**
 * (b) .NET BCL assemblies that ship with the .NET Framework runtime, not as
 * separate NuGet packages. They show up in old-style .csproj files but are
 * part of the runtime install, not third-party deps.
 *
 * Allowlist exceptions live in BCL_ALLOWLIST_EXCEPTIONS below.
 */
const BCL_BLOCKLIST = new Set([
  "system",                     // System.dll — BCL core
  "system.core",                // System.Core.dll — LINQ etc.
  "system.xml",                 // System.Xml.dll
  "system.xml.linq",            // System.Xml.Linq.dll
  "system.data",                // System.Data.dll — ADO.NET
  "system.data.datasetextensions", // System.Data.DataSetExtensions.dll
  "system.deployment",          // ClickOnce deployment — BCL
  "system.drawing",             // System.Drawing.dll — GDI+, BCL
  "system.windows.forms",       // WinForms BCL
  "system.xaml",                // System.Xaml.dll — WPF BCL
  "system.configuration",       // System.Configuration.dll — BCL
  "presentationcore",           // PresentationCore.dll — WPF BCL
  "presentationframework",      // PresentationFramework.dll — WPF BCL
  "windowsbase",                // WindowsBase.dll — WPF BCL
  "microsoft.csharp",           // Microsoft.CSharp.dll — dynamic/runtime BCL
]);

/**
 * BCL names that look like BCL but ARE separately distributed as NuGet packages
 * and should not be dropped. These override BCL_BLOCKLIST when present.
 */
const BCL_ALLOWLIST_EXCEPTIONS = new Set([
  "system.net.http",      // Separate NuGet pre-.NET 4.5; Gocator targets .NET 4.0
  "system.data.sqlclient", // Separate NuGet for SQL client
  "system.memory",        // Separate NuGet (Memory/Span backport for older targets)
]);

/**
 * (c) Test-only frameworks — not shipped in the product binary.
 */
const TEST_FRAMEWORK_BLOCKLIST = new Set([
  "microsoft.visualstudio.qualitytools.unittestframework", // VS MSTest framework
  "gtest",    // GoogleTest C++ — test-only
  "gmock",    // GoogleMock C++ — test-only
  "googletest", // googletest friendly-name variant
  "nunit",    // NUnit test framework
  "xunit",    // xUnit test framework
  "mstest.testframework", // MSTest v2
]);

/**
 * (d) Naming alias map for rule (g): when cdxgen emits both a "friendly name"
 * and a "package id" for the same component, prefer the package id (the
 * dotted/hyphen NuGet/npm id) and drop the friendly name variant.
 *
 * Key: lowercase friendly name → canonical package id (will be looked up
 * case-insensitively against the component's name).
 */
const NAMING_ALIAS_MAP: Record<string, string> = {
  // WPF notification tray icon — friendly vs NuGet id
  "hardcodet wpf notifyicon": "Hardcodet.Wpf.TaskbarNotification",
  // Xceed WPF toolkit — friendly vs NuGet id
  "xceed extended wpf toolkit": "Xceed.Wpf.Toolkit",
  // cli11 / CLI11 — different word-casing of the exact same name; handled by
  // rule (f) normalisation, not here (the alias map is for genuinely different
  // name strings, not pure capitalisation variants).
};

// ---- helpers ----------------------------------------------------------------

function isGenericOrNull(ecosystem: string | null | undefined): boolean {
  return ecosystem === "generic" || ecosystem == null || ecosystem === "";
}

// ---- rules ------------------------------------------------------------------

/** Rule (a): drop entries with placeholder version strings. */
function dropPlaceholderVersions(components: CdxComponent[]): CdxComponent[] {
  return components.filter((c) => {
    if (!c.version) return true; // no version → not a placeholder
    const v = c.version.trim();
    // CMake ${VAR} and MSBuild @{VAR} unresolved placeholders
    return !/^\$\{[^}]+\}$/.test(v) && !/^@\{[^}]+\}$/.test(v);
  });
}

/** Rule (b): drop CMake-internal pseudo-packages (exact name, generic/null ecosystem). */
function dropCmakeInternals(components: CdxComponent[]): CdxComponent[] {
  return components.filter((c) => {
    const name = (c.name ?? "").trim().toLowerCase();
    if (!CMAKE_INTERNAL_BLOCKLIST.has(name)) return true;
    // Only drop if ecosystem is generic or null — a real "python3-dev" rpm package
    // would have ecosystem="rpm" and should pass through.
    return !isGenericOrNull(extractEcosystem(c.purl));
  });
}

/** Rule (c): drop .NET BCL / runtime assemblies (nuget ecosystem), with allowlist. */
function dropBclAssemblies(components: CdxComponent[]): CdxComponent[] {
  return components.filter((c) => {
    const eco = extractEcosystem(c.purl);
    if (eco !== "nuget") return true; // only applies to NuGet entries
    const name = (c.name ?? "").trim().toLowerCase();
    if (BCL_ALLOWLIST_EXCEPTIONS.has(name)) return true; // explicit keep
    if (!BCL_BLOCKLIST.has(name)) return true;
    // Extra check: if the version looks like a -preview suffix, keep it
    // (separately-distributed preview package, not an in-box assembly).
    if (c.version?.includes("-preview")) return true;
    return false;
  });
}

/** Rule (d): drop test-only frameworks. */
function dropTestFrameworks(components: CdxComponent[]): CdxComponent[] {
  return components.filter((c) => {
    const name = (c.name ?? "").trim().toLowerCase();
    // Exact match
    if (TEST_FRAMEWORK_BLOCKLIST.has(name)) return false;
    // Prefix matches for xunit.*, nunit.*, mstest.*
    if (name.startsWith("xunit.") || name.startsWith("nunit.") || name.startsWith("mstest.")) return false;
    return true;
  });
}

/** Rule (e): coalesce versionless + versioned pairs — drop the versionless rows. */
function coalesceVersionlessPairs(components: CdxComponent[]): CdxComponent[] {
  // Group by (lowercase name, ecosystem)
  const groups = new Map<string, CdxComponent[]>();
  for (const c of components) {
    const eco = extractEcosystem(c.purl) ?? "";
    const key = `${(c.name ?? "").toLowerCase()}::${eco}`;
    const group = groups.get(key);
    if (group) group.push(c);
    else groups.set(key, [c]);
  }

  const result: CdxComponent[] = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      result.push(group[0]!);
      continue;
    }
    const hasVersioned = group.some((c) => c.version && c.version.trim() !== "");
    if (!hasVersioned) {
      // All versionless — keep them all (nothing to collapse)
      result.push(...group);
    } else {
      // Drop versionless; keep all versioned (multiple versioned = different
      // Visual Studio projects pinning different versions — all real).
      result.push(...group.filter((c) => c.version && c.version.trim() !== ""));
    }
  }
  return result;
}

/**
 * Rule (f): normalize name capitalization within a canonical-key group.
 * When multiple capitalization variants of the same name exist, prefer
 * the one that appears in the NAMING_ALIAS_MAP canonical form, then the
 * one that matches the purl package segment, then the first occurrence.
 *
 * Rule (g): apply NAMING_ALIAS_MAP — drop "friendly name" variants when a
 * "package id" variant exists for the same component.
 *
 * Both rules operate on the same grouping pass, so they're combined here.
 */
function normalizeNamesAndAliases(components: CdxComponent[]): CdxComponent[] {
  // First pass: resolve alias map entries.
  // If any component's lowercase name is in NAMING_ALIAS_MAP and the
  // canonical-id variant exists, drop the alias entry.
  const canonicalNamesPresent = new Set(
    components.map((c) => (c.name ?? "").toLowerCase()),
  );

  const afterAlias = components.filter((c) => {
    const lower = (c.name ?? "").toLowerCase();
    const canonical = NAMING_ALIAS_MAP[lower];
    if (!canonical) return true; // not an alias → keep
    // If the canonical package-id variant is present (by lowercase), drop this
    // friendly-name entry. If the canonical doesn't exist yet, keep the alias
    // (avoid losing the component entirely).
    return !canonicalNamesPresent.has(canonical.toLowerCase());
  });

  // Second pass: within groups sharing the same lowercase name, pick one
  // canonical casing (purl-derived if possible, else first occurrence).
  const groups = new Map<string, CdxComponent[]>();
  for (const c of afterAlias) {
    const key = (c.name ?? "").toLowerCase();
    const group = groups.get(key);
    if (group) group.push(c);
    else groups.set(key, [c]);
  }

  const result: CdxComponent[] = [];
  for (const group of groups.values()) {
    if (group.length === 1) {
      result.push(group[0]!);
      continue;
    }
    // All share the same lowercase name but differ in casing.
    // Pick the "best" representative: prefer the one with a real purl package
    // segment (non-generic), else the one matching the alias map's casing, else
    // first occurrence.
    const canonical = NAMING_ALIAS_MAP[(group[0]!.name ?? "").toLowerCase()];
    const best =
      group.find((c) => {
        const eco = extractEcosystem(c.purl);
        return eco && eco !== "generic";
      }) ??
      (canonical ? group.find((c) => c.name === canonical) : undefined) ??
      group[0]!;

    // Re-emit each component but with the canonical name attached (simple reassign).
    result.push(...group.map((c) => ({ ...c, name: best!.name })));
  }

  // De-duplicate by purl after name normalization (two entries may now share
  // the same purl after renaming).
  const seen = new Set<string>();
  return result.filter((c) => {
    const key = c.purl ?? `${c.name}::${c.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * Top-level post-processing pipeline. Call this on the raw cdxgen
 * `doc.components` array before persisting to the database. Each rule
 * is applied in the order specified in the M6p plan (§1.1).
 *
 * Returns a new array; input is not mutated.
 */
export function postProcessComponents(components: CdxComponent[]): CdxComponent[] {
  let result = components;
  result = dropPlaceholderVersions(result);   // (a)
  result = dropCmakeInternals(result);         // (b)
  result = dropBclAssemblies(result);          // (c)
  result = dropTestFrameworks(result);         // (d)
  result = coalesceVersionlessPairs(result);   // (e)
  result = normalizeNamesAndAliases(result);   // (f) + (g)
  return result;
}

// ---------------------------------------------------------------------------
// cdxgen invocation
// ---------------------------------------------------------------------------

export interface CdxgenResult {
  doc: CycloneDxDocument;
  /** True if cdxgen wrote a parseable output file. False if cdxgen exited
   *  non-zero AND failed to write any output — in that case `doc` is an
   *  empty SBOM placeholder and callers should NOT treat the scan as a
   *  successful zero-component result. */
  ok: boolean;
  /** When `ok` is false, a short reason string for warnings/logs. */
  failureReason?: string;
}

/**
 * Run cdxgen against `workingDir` and return the parsed CycloneDX JSON,
 * along with an explicit success flag so callers can distinguish a
 * legitimate zero-component scan (no manifest in the repo) from a hard
 * failure (timeout, cdxgen crash, missing output).
 *
 * cdxgen is installed as a package dep; its binary is in node_modules/.bin.
 */
export async function runCdxgen(workingDir: string, excludes: string[] = []): Promise<CdxgenResult> {
  // Write the SBOM to a temp file so we don't have to parse stdout noise.
  const tmpDir = await mkdtemp(join(tmpdir(), "cdxgen-"));
  const outputPath = join(tmpDir, "sbom.json");

  try {
    // `cdxgen` detects the project type automatically when -t is omitted.
    // --no-recurse keeps it focused on the root manifest.
    const cdxgenBin = join(process.cwd(), "node_modules", ".bin", "cdxgen");
    // Each --exclude takes a path; we pass a glob ending in /** so any file
    // inside that subtree is dropped.
    const excludeArgs = excludes.flatMap((p) => ["--exclude", `${p}/**`]);
    logger.info({ workingDir, outputPath, excludes }, "[sbomService] running cdxgen");

    let execError: unknown = null;
    try {
      // Phase 1.1 (M6q): set cwd to workingDir so cdxgen emits repo-relative
      // paths in evidence.identity.methods[].value and properties.SrcFile —
      // no more "../clones/<uuid>/..." prefix leaking into stored paths.
      // Pass "." as the scan root (since cwd is already the scope dir).
      // Do NOT pass --evidence: cdxgen 12.2.1 silently fails (exit 0, no
      // output file) on this codebase when --evidence is passed explicitly.
      // The evidence section + occurrences[] are emitted anyway for the
      // project types we care about (npm, nuget, .csproj, .vcxproj, etc.).
      // Verified empirically on Gocator Classic / scope (M6q follow-up).
      //
      // --exclude-type bazel: vendored libraries (e.g. googletest) often
      // ship BUILD.bazel + WORKSPACE files. cdxgen treats those as project
      // markers and tries to invoke the `bazel` binary, which fails because
      // the worker container doesn't have bazel installed. Excluding the
      // bazel project type from auto-detection avoids the false positive
      // without losing real first-party SBOM data — cdxgen continues to
      // analyse npm / nuget / etc. as before.
      await execFileAsync(
        cdxgenBin,
        ["-o", outputPath, "--exclude-type", "bazel", ...excludeArgs, "."],
        {
          cwd: workingDir,           // ← M6q: scope dir is the process root
          timeout: 5 * 60 * 1000, // 5-minute hard cap
          env: {
            ...process.env,
            CDXGEN_DEBUG_MODE: "false",
            FETCH_LICENSE: "true",
          },
        },
      );
    } catch (err) {
      // cdxgen exits non-zero for some project types even when it succeeds.
      // Check whether the output file was written before giving up.
      execError = err;
      logger.warn({ err }, "[sbomService] cdxgen exited non-zero — checking for output");
    }

    const fileExists = await access(outputPath).then(() => true).catch(() => false);
    const empty: CycloneDxDocument = { bomFormat: "CycloneDX", specVersion: "1.7", components: [] };

    if (!fileExists) {
      // No output AND cdxgen errored → treat as a hard failure so the
      // worker knows not to trust the result for auto-fix purposes.
      // (No output but cdxgen exited 0 is theoretically possible — also
      // treat as failure, since cdxgen normally writes the file.)
      const reason = execError instanceof Error
        ? execError.message.slice(0, 200)
        : "cdxgen produced no output file";
      logger.warn({ workingDir, reason }, "[sbomService] cdxgen failed");
      return { doc: empty, ok: false, failureReason: reason };
    }

    try {
      const raw = await readFile(outputPath, "utf8");
      return { doc: JSON.parse(raw) as CycloneDxDocument, ok: true };
    } catch (err) {
      const reason = err instanceof Error ? err.message.slice(0, 200) : "could not parse cdxgen output";
      logger.warn({ err }, "[sbomService] cdxgen output unparseable");
      return { doc: empty, ok: false, failureReason: reason };
    }
  } finally {
    await rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

type Tx = PrismaClient | Prisma.TransactionClient;

/**
 * Persist CycloneDX components for a scan run. Returns the inserted rows.
 * Deduplicates by purl within the same scan run so re-entrant calls are safe.
 *
 * `scopePath` is the repo-rooted path of the scope being scanned ("/" for
 * root, "/GoWeb" etc. for sub-scopes). It's used to translate scope-
 * relative manifest paths from cdxgen into repo-rooted paths so file
 * links work consistently across scopes.
 */
export async function persistComponents(
  scanRunId: string,
  doc: CycloneDxDocument,
  client: Tx,
  scopeDir = "",
  scopePath = "/",
): Promise<SbomComponent[]> {
  // Stage 1: mechanical post-processing (M6p §1.1) — runs before any DB
  // writes so the stored component list is already cleaned.
  const rawComponents = doc.components ?? [];
  const cleaned = postProcessComponents(rawComponents);
  logger.info(
    { raw: rawComponents.length, cleaned: cleaned.length },
    "[sbomService] Stage-1 post-processing complete",
  );

  const unique = new Map<string, CdxComponent>();

  for (const c of cleaned) {
    if (c.purl && !unique.has(c.purl)) unique.set(c.purl, c);
  }

  if (unique.size === 0) {
    logger.warn({ scanRunId }, "[sbomService] cdxgen produced 0 components");
    return [];
  }

  // Pre-build per-component records so we can enrich `occurrences` with
  // manifest line numbers (resolveManifestLines is async + uses a shared
  // cache so each lockfile is read once). Createmany takes the result.
  type Row = {
    scanRunId: string;
    name: string;
    version: string | null;
    purl: string;
    ecosystem: string | null;
    licenses: string[];
    componentType: string;
    scope: string | null;
    isDevOnly: boolean;
    manifestFile: string | null;
    occurrences: ComponentOccurrence[];
  };
  const lockfileCache = new Map<string, string[] | null>();
  const scopeIndex = scopeDir ? new ScopeFileIndex(scopeDir, scopePath) : undefined;
  const rows: Row[] = [];
  for (const c of unique.values()) {
    const ecosystem = extractEcosystem(c.purl);
    const name = canonicalPackageName(c, ecosystem);
    const sr = extractManifestFile(c, scopeDir);
    const occurrences = extractOccurrences(c, null, false, scopePath);
    // Resolve missing/phantom paths (e.g. cdxgen jar-deps basenames) +
    // grep manifest-shaped occurrences for line numbers so transitive
    // lockfile-only entries match the direct-import case in shape.
    // Caches shared across components in this batch.
    await resolveManifestLines(occurrences, name, scopeDir || null, scopePath, lockfileCache, scopeIndex);
    rows.push({
      scanRunId,
      name,
      version: c.version ?? null,
      purl: c.purl!,
      ecosystem,
      licenses: extractLicenses(c.licenses),
      componentType: c.type ?? "library",
      scope: c.scope ?? null,
      isDevOnly: extractIsDevOnly(c),
      manifestFile: sr ? toRepoRelative(scopePath, sr) : null,
      occurrences,
    });
  }

  // Batch-insert; skip duplicates silently (skipDuplicates=true relies on
  // the unique index; Prisma createMany doesn't return records so we refetch).
  await (client as PrismaClient).sbomComponent.createMany({
    data: rows.map((r) => ({
      ...r,
      occurrences: r.occurrences as unknown as Prisma.InputJsonValue,
    })),
    skipDuplicates: true,
  });

  return (client as PrismaClient).sbomComponent.findMany({
    where: { scanRunId },
  });
}

// ---------------------------------------------------------------------------
// M6p Stage 2 helpers
// ---------------------------------------------------------------------------

/**
 * Run Stage-1 post-processing on a CycloneDX document and return the cleaned
 * CdxComponent list WITHOUT persisting to the database. Used by the worker so
 * it can pass the cleaned list to the LLM augmentation pass before writing to
 * the DB.
 */
export function extractCleanedComponents(doc: CycloneDxDocument): CdxComponent[] {
  return postProcessComponents(doc.components ?? []);
}



