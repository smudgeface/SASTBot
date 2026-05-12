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

import { pino } from "pino";
import { loadConfig } from "../config.js";
import { prisma } from "../db.js";
import { toRepoRelative } from "./scopePath.js";
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

  for (const [scanRunId, rows] of byScanRun) {
    // Fetch the sbom_json + the scope's path for this scan run. We need
    // scope.path so paths persisted for sub-scopes (e.g. /GoWeb) come out
    // repo-rooted, not scope-relative.
    const scanRun = await prisma.scanRun.findUnique({
      where: { id: scanRunId },
      select: { sbomJson: true, scope: { select: { path: true } } },
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

      await setComponentOccurrences(row.id, occs);
      filled++;
    }
  }

  logger.info({ filled, skipped }, "[sbomOccurrences] backfill complete");
}
