/**
 * sbomOccurrences.ts — M6q
 *
 * Extracts the full "where is this component used" occurrence list from a
 * CycloneDX component record and persists it into sbom_components.occurrences.
 *
 * Design decisions (see M6q_PLAN.md §1.3):
 *  - evidence.occurrences[].location is the gold source: repo-relative, has line numbers.
 *  - Fallback: evidence.identity[].methods[].value / concludedValue (no line numbers).
 *  - properties[].name === "SrcFile" is always redundant with the fallback — skipped.
 *  - After M6q CWD fix, no path-prefix stripping is needed for new scans. Backfill
 *    applies a one-time defensive strip for pre-M6q rows.
 *  - LLM-augmented components also get llm_evidence.path as a guaranteed occurrence.
 */

import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import { pino } from "pino";
import { loadConfig } from "../config.js";
import { prisma } from "../db.js";
import { toRepoRelative, toScopeRelative } from "./scopePath.js";
import type { CdxComponent, CycloneDxDocument } from "./sbomService.js";
import type { Prisma } from "@prisma/client";

const logger = pino({ level: loadConfig().logLevel, name: "sbomOccurrences" });

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ComponentOccurrence {
  path: string;
  line: number | null;
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/** Regex that matches the clone-root prefix cdxgen used to emit before the
 *  M6q CWD fix: `../clones/<uuid>/` or `/…/clones/<uuid>/`. Used by backfill
 *  to clean pre-M6q rows; new rows should never trigger this. */
const CLONE_PREFIX_RE =
  /(?:^|\/)clones\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\//i;

/**
 * Strip the clone-root prefix from a path, if present.
 * Returns the path unchanged if no prefix is found.
 * Logs a warning (regression signal) when stripping is needed on non-backfill paths.
 */
function stripClonePrefix(raw: string, warnIfFound: boolean): string {
  const match = raw.match(CLONE_PREFIX_RE);
  if (!match) return raw;
  const idx = raw.indexOf(match[0]!) + match[0]!.length;
  const stripped = raw.slice(idx);
  if (warnIfFound) {
    logger.warn({ raw, stripped }, "[sbomOccurrences] clone-path prefix found — check cdxgen CWD setting (M6q regression)");
  }
  return stripped;
}

// ---------------------------------------------------------------------------
// Core extraction
// ---------------------------------------------------------------------------

/**
 * Extract the occurrence list for a single CdxComponent.
 *
 * Priority:
 *   1. evidence.occurrences[].location  (repo-relative, "path#line")
 *   2. evidence.identity[].methods[].value / concludedValue  (repo-relative after M6q)
 *   3. llm_evidence.path from the stored llmEvidence blob (LLM-augmented only)
 *
 * SrcFile properties are always skipped (redundant with step 2).
 *
 * @param c - CdxComponent from the SBOM JSON
 * @param llmEvidencePath - optional path from the stored llmEvidence blob
 *        (already repo-rooted by the caller; not re-prefixed)
 * @param stripPrefix - when true (backfill mode), strip clone-root prefixes
 * @param scopePath - the scope's path on the repo (e.g. "/" or "/GoWeb").
 *        When the scope is not "/", cdxgen ran with cwd = scope dir, so the
 *        paths it emitted are scope-relative ("kJs/foo.js" rather than
 *        "GoWeb/kJs/foo.js"). Prefixing here makes the persisted paths
 *        repo-rooted, which is what <FileLink> + source_url_template expect.
 *        Defaults to "/" for backwards compat with existing callers/tests.
 */
export function extractOccurrences(
  c: CdxComponent,
  llmEvidencePath?: string | null,
  stripPrefix = false,
  scopePath = "/",
): ComponentOccurrence[] {
  const raw: ComponentOccurrence[] = [];

  // Step 1: evidence.occurrences[].location — "path#line" or just "path"
  const occurrences = c.evidence?.occurrences ?? [];
  if (occurrences.length > 0) {
    for (const occ of occurrences) {
      if (!occ.location) continue;
      const hashIdx = occ.location.lastIndexOf("#");
      let path: string;
      let line: number | null = null;
      if (hashIdx > 0) {
        path = occ.location.slice(0, hashIdx);
        const lineStr = occ.location.slice(hashIdx + 1);
        const parsed = parseInt(lineStr, 10);
        line = Number.isFinite(parsed) && parsed > 0 ? parsed : null;
      } else {
        path = occ.location;
      }
      if (stripPrefix) path = stripClonePrefix(path, false);
      else path = stripClonePrefix(path, true); // defensive check on new scans
      if (path) raw.push({ path: toRepoRelative(scopePath, path), line });
    }
  } else {
    // Step 2: evidence.identity[].methods[].value or concludedValue
    const identities = c.evidence?.identity
      ? Array.isArray(c.evidence.identity)
        ? c.evidence.identity
        : [c.evidence.identity]
      : [];
    for (const ident of identities) {
      const methods = ident.methods ?? [];
      if (methods.length > 0) {
        for (const m of methods) {
          if (m.value) {
            let path = m.value;
            if (stripPrefix) path = stripClonePrefix(path, false);
            else path = stripClonePrefix(path, true);
            if (path) raw.push({ path: toRepoRelative(scopePath, path), line: null });
          }
        }
      } else if ((ident as { concludedValue?: string }).concludedValue) {
        let path = (ident as { concludedValue: string }).concludedValue;
        if (stripPrefix) path = stripClonePrefix(path, false);
        else path = stripClonePrefix(path, true);
        if (path) raw.push({ path: toRepoRelative(scopePath, path), line: null });
      }
    }
  }

  // Step 3: llm_evidence.path — guaranteed first occurrence for LLM-augmented rows.
  // The caller already stored this as a repo-rooted path (see persistAugmentedComponents),
  // so do not re-prefix; just dedupe.
  if (llmEvidencePath) {
    let path = llmEvidencePath;
    if (stripPrefix) path = stripClonePrefix(path, false);
    if (path && !raw.some((o) => o.path === path)) {
      raw.push({ path, line: null });
    }
  }

  // Dedupe by (path, line)
  const seen = new Set<string>();
  return raw.filter((o) => {
    const key = `${o.path}::${o.line ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

// ---------------------------------------------------------------------------
// Extraction from a full CycloneDX document (keyed by purl)
// ---------------------------------------------------------------------------

/**
 * Build a map of purl → ComponentOccurrence[] from a raw SBOM JSON document.
 * Used by backfillSbomOccurrences to extract from the stored sbom_json.
 * `scopePath` is the scope's repo path ("/", "/GoWeb", etc.) so the
 * persisted occurrences are repo-rooted.
 */
export function extractOccurrenceMap(
  doc: CycloneDxDocument,
  stripPrefix: boolean,
  scopePath = "/",
): Map<string, ComponentOccurrence[]> {
  const result = new Map<string, ComponentOccurrence[]>();
  for (const c of doc.components ?? []) {
    if (!c.purl) continue;
    const occs = extractOccurrences(c, null, stripPrefix, scopePath);
    result.set(c.purl, occs);
  }
  return result;
}

// ---------------------------------------------------------------------------
// Manifest line resolution
//
// cdxgen attaches `evidence.occurrences[]` with line numbers when a
// component is `require()`/`import`-ed from source. For transitive
// lockfile-only dependencies, the only path it knows is the lockfile
// itself, with no line. That creates visual inconsistency in the
// "Found in" panel: some rows have file:line, others just file.
//
// resolveManifestLines() backfills those missing line numbers by
// grepping each manifest-looking file for the package name (same
// pattern set as osvService.readManifestSnippet uses for SCA issues).
// Reads are cached per (scopeDir, repoPath) so we never read the
// same lockfile twice.
// ---------------------------------------------------------------------------

const MANIFEST_FILENAMES = new Set([
  "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
  "requirements.txt", "pyproject.toml", "poetry.lock", "Pipfile.lock",
  "go.mod", "go.sum", "Cargo.toml", "Cargo.lock", "Gemfile.lock",
  "composer.json", "composer.lock", "packages.config", "csproj.lock.json",
]);

function looksLikeManifest(repoPath: string): boolean {
  const base = repoPath.split("/").pop() ?? "";
  if (MANIFEST_FILENAMES.has(base)) return true;
  // Project files (.csproj, .vbproj, .vcxproj, etc.)
  if (/\.(csproj|vbproj|vcxproj|fsproj)$/i.test(base)) return true;
  return false;
}

async function readManifestLines(
  scopeDir: string,
  repoPath: string,
  scopePath: string,
  cache: Map<string, string[] | null>,
): Promise<string[] | null> {
  if (cache.has(repoPath)) return cache.get(repoPath)!;
  // repoPath is repo-rooted ("GoWeb/foo/package-lock.json"); scopeDir is
  // already the scope dir on disk, so strip the scope prefix to get the
  // path relative to scopeDir.
  const scopeRel = toScopeRelative(scopePath, repoPath);
  try {
    const content = await readFile(path.join(scopeDir, scopeRel), "utf8");
    const lines = content.split("\n");
    cache.set(repoPath, lines);
    return lines;
  } catch {
    cache.set(repoPath, null);
    return null;
  }
}

/**
 * Lazy recursive index of every file basename → repo-relative paths in
 * a scope dir. Built only on first lookup so the common case (every
 * occurrence path already correct) costs nothing.
 *
 * Skips common heavy/uninteresting trees so we don't get killed on big
 * monorepos: node_modules, .git, vendor caches, build outputs, etc.
 */
class ScopeFileIndex {
  private byBasename: Map<string, string[]> | null = null;
  constructor(private scopeDir: string, private scopePath: string) {}

  private static SKIP_DIRS = new Set([
    ".git", "node_modules", "dist", "build", "out", "target", "bin", "obj",
    ".venv", "venv", "__pycache__", ".cache", ".next", ".nuxt", ".turbo",
    "coverage", ".pytest_cache",
  ]);

  private async build(): Promise<void> {
    const idx = new Map<string, string[]>();
    const walk = async (dir: string, rel: string): Promise<void> => {
      let entries: import("node:fs").Dirent[];
      try { entries = await readdir(dir, { withFileTypes: true }); }
      catch { return; }
      for (const e of entries) {
        if (e.name.startsWith(".") && e.name !== ".env" && e.name !== ".gitignore") continue;
        const childRel = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) {
          if (ScopeFileIndex.SKIP_DIRS.has(e.name)) continue;
          await walk(path.join(dir, e.name), childRel);
        } else if (e.isFile()) {
          const list = idx.get(e.name);
          if (list) list.push(childRel);
          else idx.set(e.name, [childRel]);
        }
      }
    };
    await walk(this.scopeDir, "");
    this.byBasename = idx;
  }

  /** Returns the repo-rooted path when exactly one file matches the
   *  basename; null when 0 or >1 matches (ambiguous). */
  async resolveBasename(basename: string): Promise<string | null> {
    if (!this.byBasename) await this.build();
    const matches = this.byBasename!.get(basename);
    if (!matches || matches.length !== 1) return null;
    return toRepoRelative(this.scopePath, matches[0]!);
  }
}

/**
 * For each `line: null` occurrence pointing at a manifest-shaped file,
 * grep the file for the package name and fill in the line number. The
 * cache is caller-owned so a batch of components persisted together
 * shares one read per lockfile.
 *
 * Also resolves "phantom" paths — when cdxgen extracted a component
 * from a packed jar/zip its identity value is just the basename (e.g.
 * "compiler.jar"), with no repo location. We walk the scope dir once
 * and replace the path with the real location when there's exactly
 * one match. Ambiguous (≥2 matches) and missing files are left as-is.
 *
 * Mutates and returns the same array. No-op when scopeDir is missing.
 */
export async function resolveManifestLines(
  occurrences: ComponentOccurrence[],
  packageName: string,
  scopeDir: string | null,
  scopePath: string,
  cache: Map<string, string[] | null>,
  scopeIndex?: ScopeFileIndex,
): Promise<ComponentOccurrence[]> {
  if (!scopeDir) return occurrences;
  const patterns = [
    `"${packageName}"`,
    `'${packageName}'`,
    `${packageName}==`,
    `${packageName}~=`,
  ];
  for (const occ of occurrences) {
    // Step 1: try to resolve the path when the on-disk file doesn't exist
    // (cdxgen jar-deps case: identity is the bare jar basename, no path).
    // Cheap stat first; only walk the index on a miss.
    if (scopeIndex) {
      const scopeRel = toScopeRelative(scopePath, occ.path);
      const onDisk = path.join(scopeDir, scopeRel);
      let exists = false;
      try { await (await import("node:fs/promises")).access(onDisk); exists = true; } catch { /* miss */ }
      if (!exists) {
        const basename = occ.path.split("/").pop() ?? "";
        if (basename) {
          const resolved = await scopeIndex.resolveBasename(basename);
          if (resolved) occ.path = resolved;
        }
      }
    }
    // Step 2: line-number lookup for manifest-shaped files. Skip when the
    // occurrence already has a line.
    if (occ.line != null) continue;
    if (!looksLikeManifest(occ.path)) continue;
    const lines = await readManifestLines(scopeDir, occ.path, scopePath, cache);
    if (!lines) continue;
    let idx = -1;
    for (const p of patterns) {
      idx = lines.findIndex((l) => l.includes(p));
      if (idx !== -1) break;
    }
    if (idx !== -1) occ.line = idx + 1;
  }
  return occurrences;
}

export { ScopeFileIndex };

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/**
 * Write occurrences into a component row.
 */
export async function setComponentOccurrences(
  componentId: string,
  occurrences: ComponentOccurrence[],
): Promise<void> {
  await prisma.sbomComponent.update({
    where: { id: componentId },
    data: { occurrences: occurrences as unknown as Prisma.InputJsonValue },
  });
}

// ---------------------------------------------------------------------------
// Worker boot hook: backfillSbomOccurrences
// ---------------------------------------------------------------------------

/**
 * Backfill sbom_components.occurrences for rows with occurrences = [].
 *
 * Runs once per component row (filtered on occurrences = []), so it's safe
 * to re-run on every worker boot without duplicating work.
 *
 * Pre-M6q rows may have clone-prefixed identity paths — stripPrefix=true
 * cleans them as a one-time data migration.
 */
export async function backfillSbomOccurrences(): Promise<void> {
  // Pick up:
  //   a) rows with empty occurrences (initial backfill case), AND
  //   b) rows belonging to a sub-scope (scope.path != "/") — they may have
  //      occurrences that pre-date the scopePath prefix fix and therefore
  //      miss the scope prefix. Re-extracting is cheap and idempotent.
  const candidates = await prisma.sbomComponent.findMany({
    where: {
      OR: [
        { occurrences: { equals: [] as unknown as Prisma.InputJsonValue } },
        { scanRun: { scope: { NOT: { path: "/" } } } },
      ],
    },
    select: {
      id: true,
      name: true,
      purl: true,
      llmEvidence: true,
      scanRunId: true,
      occurrences: true,
    },
  });

  if (candidates.length === 0) {
    logger.info("[sbomOccurrences] backfill: no rows need occurrences — skipping");
    return;
  }

  logger.info({ count: candidates.length }, "[sbomOccurrences] backfill: starting");

  // Group by scanRunId so we fetch sbom_json once per scan run.
  const byScanRun = new Map<string, typeof candidates>();
  for (const row of candidates) {
    const existing = byScanRun.get(row.scanRunId) ?? [];
    existing.push(row);
    byScanRun.set(row.scanRunId, existing);
  }

  let filled = 0;
  let skipped = 0;

  // Lazy import to avoid pulling fs / repoCache into the always-loaded
  // module graph when this backfill never runs.
  const { repoCachePath } = await import("./repoCache.js");
  const { stat } = await import("node:fs/promises");

  for (const [scanRunId, rows] of byScanRun) {
    // Fetch sbom_json + scope.path + repo info so we can:
    //   - persist repo-rooted paths (scope.path)
    //   - resolve manifest line numbers (need scopeDir on disk via
    //     repoCachePath + scope.path; only viable when retainClone=true)
    const scanRun = await prisma.scanRun.findUnique({
      where: { id: scanRunId },
      select: {
        sbomJson: true,
        scope: {
          select: {
            path: true,
            repoId: true,
            repo: { select: { retainClone: true } },
          },
        },
      },
    });

    if (!scanRun?.sbomJson) {
      logger.debug({ scanRunId }, "[sbomOccurrences] backfill: no sbom_json — skipping run");
      skipped += rows.length;
      continue;
    }

    const scopePath = scanRun.scope?.path ?? "/";
    const doc = scanRun.sbomJson as unknown as CycloneDxDocument;
    // Build purl → occurrences map. stripPrefix=true for backfill (pre-M6q rows
    // have clone-prefixed paths; one-time strip as data migration).
    const occMap = extractOccurrenceMap(doc, /* stripPrefix */ true, scopePath);

    // Compute on-disk scopeDir for manifest-line resolution. Only available
    // when the clone is retained; otherwise we still persist the file path,
    // just without line numbers.
    let scopeDir: string | null = null;
    if (scanRun.scope?.repo?.retainClone && scanRun.scope.repoId) {
      const cacheDir = repoCachePath(scanRun.scope.repoId);
      try {
        await stat(cacheDir);
        scopeDir = scopePath === "/" || scopePath === ""
          ? cacheDir
          : path.join(cacheDir, scopePath);
      } catch {
        scopeDir = null;
      }
    }
    const lockfileCache = new Map<string, string[] | null>();
    const scopeIndex = scopeDir ? new ScopeFileIndex(scopeDir, scopePath) : undefined;

    for (const row of rows) {
      const occs = occMap.get(row.purl) ?? [];

      // Also include llm_evidence.path if present.
      let llmPath: string | null = null;
      if (row.llmEvidence && typeof row.llmEvidence === "object") {
        const ev = row.llmEvidence as Record<string, unknown>;
        if (typeof ev.path === "string") llmPath = ev.path;
      }
      if (llmPath && !occs.some((o) => o.path === llmPath)) {
        occs.push({ path: llmPath, line: null });
      }

      // Resolve missing paths (cdxgen jar-deps basenames) + manifest line
      // numbers so the FE doesn't render an awkward mix of "file:N",
      // "file", and "file-that-doesn't-exist" entries.
      await resolveManifestLines(occs, row.name, scopeDir, scopePath, lockfileCache, scopeIndex);

      await setComponentOccurrences(row.id, occs);
      filled++;
    }
  }

  logger.info({ filled, skipped }, "[sbomOccurrences] backfill complete");
}
