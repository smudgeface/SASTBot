import { join } from "node:path";

import type { Prisma, PrismaClient, SbomComponent, ScanFinding } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import type { Severity } from "../schemas.js";
import { upsertScaIssueFromDetection } from "./issueService.js";
import { computeCvss40BaseScore } from "./cvss4.js";
import { toRepoRelative, toScopeRelative } from "./scopePath.js";
import { normalizeManifestPath } from "./sbomService.js";
import { readManifestSnippet } from "./manifestSnippet.js";

const logger = pino({ level: loadConfig().logLevel, name: "osvService" });

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
// Max concurrent requests to OSV.dev — be a polite client.
const OSV_CONCURRENCY = 10;

// ---------------------------------------------------------------------------
// OSV.dev response types (subset)
// ---------------------------------------------------------------------------

interface OsvSeverityEntry {
  type: string; // "CVSS_V3" | "CVSS_V2" | ...
  score: string;
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  severity?: OsvSeverityEntry[];
  database_specific?: {
    severity?: string; // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    [k: string]: unknown;
  };
  [k: string]: unknown;
}

// ---------------------------------------------------------------------------
// Severity mapping
// ---------------------------------------------------------------------------

function mapSeverity(vuln: OsvVuln): Severity {
  const dbSev = vuln.database_specific?.severity?.toUpperCase();
  if (dbSev === "CRITICAL") return "critical";
  if (dbSev === "HIGH") return "high";
  if (dbSev === "MODERATE" || dbSev === "MEDIUM") return "medium";
  if (dbSev === "LOW") return "low";

  // Fall back to CVSS v3 base score
  const cvss3 = vuln.severity?.find((s) => s.type === "CVSS_V3");
  if (cvss3) {
    const score = parseCvssScore(cvss3.score);
    if (score !== null) {
      if (score >= 9.0) return "critical";
      if (score >= 7.0) return "high";
      if (score >= 4.0) return "medium";
      return "low";
    }
  }
  return "unknown";
}

/**
 * Extract the numeric base score from an OSV severity entry. The string can
 * be either a plain float ("7.5") or a CVSS v3 vector ("CVSS:3.1/AV:N/..."),
 * depending on how the upstream advisory chose to encode it. Vectors are
 * passed through computeCvss31BaseScore.
 */
function parseCvssScore(scoreOrVector: string): number | null {
  const n = parseFloat(scoreOrVector);
  if (!Number.isNaN(n) && n >= 0 && n <= 10) return n;
  if (scoreOrVector.startsWith("CVSS:3")) return computeCvss31BaseScore(scoreOrVector);
  if (scoreOrVector.startsWith("CVSS:4")) return computeCvss40BaseScore(scoreOrVector);
  return null;
}

/**
 * Choose a CVSS vector + numeric score from an OSV `severity[]` array.
 * Preference order: V3.1/V3.0 (we can compute a numeric score) → V4.0 (we
 * keep the vector but score is null until we ship a 4.0 calculator) → V2.
 * OSV records sometimes include only one type — most modern GitHub-reviewed
 * advisories only ship CVSS_V4 now, so falling back is essential.
 */
function pickCvss(entries: OsvSeverityEntry[]): { vector: string | null; score: number | null } {
  const v4 = entries.find((s) => s.type === "CVSS_V4");
  if (v4) return { vector: v4.score, score: parseCvssScore(v4.score) };
  const v3 = entries.find((s) => s.type === "CVSS_V3");
  if (v3) return { vector: v3.score, score: parseCvssScore(v3.score) };
  const v2 = entries.find((s) => s.type === "CVSS_V2");
  if (v2) return { vector: v2.score, score: parseCvssScore(v2.score) };
  return { vector: null, score: null };
}

// ---------------------------------------------------------------------------
// CVSS v3.1 base-score calculator
//
// Implements the formulas from FIRST.org's CVSS 3.1 specification:
//   https://www.first.org/cvss/v3.1/specification-document (sections 7-8)
//
// Each base metric maps to a fixed numeric weight; the score is a
// deterministic function of those weights. We ignore temporal/environmental
// metrics — only the eight base metrics affect the base score.
// ---------------------------------------------------------------------------

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
// PR depends on Scope; first key is S=U (Unchanged), second is S=C (Changed)
const PR: Record<string, [number, number]> = {
  N: [0.85, 0.85],
  L: [0.62, 0.68],
  H: [0.27, 0.50],
};
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0.00 };

/** Round up to one decimal place, per the CVSS spec. */
function roundUp1(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function computeCvss31BaseScore(vector: string): number | null {
  // Parse "CVSS:3.x/AV:N/AC:L/..." into a metric map
  const parts = vector.split("/");
  if (parts.length < 9 || !parts[0]?.startsWith("CVSS:3")) return null;
  const m: Record<string, string> = {};
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(":");
    if (k && v) m[k] = v;
  }

  const av = AV[m.AV ?? ""];
  const ac = AC[m.AC ?? ""];
  const ui = UI[m.UI ?? ""];
  const scope = m.S; // "U" or "C"
  const pr = PR[m.PR ?? ""]?.[scope === "C" ? 1 : 0];
  const c = CIA[m.C ?? ""];
  const i = CIA[m.I ?? ""];
  const a = CIA[m.A ?? ""];
  if ([av, ac, ui, pr, c, i, a].some((v) => v === undefined) || (scope !== "U" && scope !== "C")) return null;

  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact =
    scope === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const exploitability = 8.22 * av! * ac! * pr! * ui!;
  if (impact <= 0) return 0;
  const raw = scope === "U" ? impact + exploitability : 1.08 * (impact + exploitability);
  return roundUp1(Math.min(raw, 10));
}

/** Extract canonical CVE id from the aliases list (first CVE-* string wins). */
function extractCveId(vuln: OsvVuln): string | null {
  for (const alias of [vuln.id, ...(vuln.aliases ?? [])]) {
    if (alias.startsWith("CVE-")) return alias;
  }
  return null;
}

// ---------------------------------------------------------------------------
// OSV.dev query
// ---------------------------------------------------------------------------

interface OsvQueryResponse {
  vulns?: OsvVuln[];
}

/**
 * Strip the `@version` suffix from a purl, preserving qualifiers (`?…`) and
 * subpath (`#…`). cdxgen sometimes emits bare purls (especially for NuGet);
 * the version we know to use is on the SbomComponent. We always pass that
 * version explicitly to OSV — but OSV rejects requests where the purl ALSO
 * carries a version (`code: 3, "version specified in params and PURL query"`),
 * so the canonical request shape is `{ version, package: { purl: bare } }`.
 *
 * The version delimiter is the LAST literal `@` before any `?` or `#`. A
 * literal `@` cannot appear inside a name — scoped npm packages encode it as
 * `%40` (e.g. `pkg:npm/%40types/node@1.0.0`) — so a single linear scan is safe.
 */
export function purlWithoutVersion(purl: string): string {
  const hashIdx = purl.indexOf("#");
  const subpath = hashIdx >= 0 ? purl.slice(hashIdx) : "";
  const beforeHash = hashIdx >= 0 ? purl.slice(0, hashIdx) : purl;

  const qIdx = beforeHash.indexOf("?");
  const qualifiers = qIdx >= 0 ? beforeHash.slice(qIdx) : "";
  const head = qIdx >= 0 ? beforeHash.slice(0, qIdx) : beforeHash;

  const atIdx = head.lastIndexOf("@");
  if (atIdx <= "pkg:".length) return purl;
  return head.slice(0, atIdx) + qualifiers + subpath;
}

export function buildOsvQueryBody(
  purl: string,
  version: string | null,
): { version?: string; package: { purl: string } } {
  const barePurl = version ? purlWithoutVersion(purl) : purl;
  return version
    ? { version, package: { purl: barePurl } }
    : { package: { purl: barePurl } };
}

async function queryOsvForPurl(purl: string, version: string | null): Promise<OsvVuln[]> {
  const response = await fetch(OSV_QUERY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(buildOsvQueryBody(purl, version)),
  });
  if (!response.ok) {
    logger.warn({ purl, version, status: response.status }, "[osvService] OSV query failed — skipping");
    return [];
  }
  const data = (await response.json()) as OsvQueryResponse;
  return data.vulns ?? [];
}

/** Query OSV.dev for each (purl, version), throttled to OSV_CONCURRENCY parallel requests. */
async function queryOsvForPurls(
  queries: { purl: string; version: string | null }[],
): Promise<OsvVuln[][]> {
  const results: OsvVuln[][] = new Array(queries.length);
  // Process in windows of OSV_CONCURRENCY to avoid hammering OSV.dev.
  for (let i = 0; i < queries.length; i += OSV_CONCURRENCY) {
    const chunk = queries.slice(i, i + OSV_CONCURRENCY);
    const chunkResults = await Promise.all(chunk.map((q) => queryOsvForPurl(q.purl, q.version)));
    for (let j = 0; j < chunk.length; j++) {
      results[i + j] = chunkResults[j];
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

type Tx = PrismaClient | Prisma.TransactionClient;

export interface OsvResult {
  component: SbomComponent;
  vulns: OsvVuln[];
}

/**
 * Query OSV.dev for all components that have a purl, upsert ScaIssue rows,
 * then persist ScanFinding detection rows. Returns the inserted ScanFinding rows.
 */
export async function queryAndPersistFindings(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  components: SbomComponent[],
  client: Tx,
  scopeDir = "",
  scopePath = "/",
  includeDevDeps = true,
): Promise<ScanFinding[]> {
  let queried = components;
  if (!includeDevDeps) {
    const before = queried.length;
    queried = queried.filter((c) => !c.isDevOnly);
    const filtered = before - queried.length;
    if (filtered > 0) {
      logger.info({ filtered }, "[osvService] excluded dev-only components from OSV query");
    }
  }
  const withPurl = queried.filter((c) => c.purl);
  if (withPurl.length === 0) return [];

  logger.info({ scanRunId, count: withPurl.length }, "[osvService] querying OSV.dev");
  const queries = withPurl.map((c) => ({ purl: c.purl, version: c.version || null }));
  const results = await queryOsvForPurls(queries);

  // Deduplicate by (componentId, osvId) then upsert issues + create detections.
  const seen = new Set<string>();

  for (let i = 0; i < withPurl.length; i++) {
    const component = withPurl[i];
    const vulns = results[i] ?? [];
    for (const vuln of vulns) {
      const key = `${component.id}:${vuln.id}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const severity = mapSeverity(vuln);
      const { vector, score } = pickCvss(vuln.severity ?? []);
      const aliases = [vuln.id, ...(vuln.aliases ?? [])].filter(
        (a, idx, arr) => arr.indexOf(a) === idx,
      );

      // Resolve manifest origin (e.g. package-lock.json) and grab a ±3-line
      // snippet around the package declaration so the SCA detail can mirror
      // SAST's code-context view. component.manifestFile is repo-rooted;
      // strip the scope prefix before reading from disk (the file lives at
      // scopeDir + scope-relative-path).
      const manifestFields = scopeDir && component.manifestFile
        ? await readManifestSnippet(
            scopeDir,
            toScopeRelative(scopePath, component.manifestFile),
            component.name,
          )
        : { line: null, snippet: null };

      // Detect the "two records, same underlying vuln" case: another issue in
      // the same scope+package whose aliases overlap ours but whose osv_id
      // differs. We currently don't dedup these — flag it so we'd notice if
      // OSV starts emitting both GHSA + NVD records (or similar) for one vuln.
      const aliasOverlap = await (client as PrismaClient).scaIssue.findFirst({
        where: {
          scopeId,
          packageName: component.name,
          osvId: { not: vuln.id },
          latestAliases: { hasSome: aliases },
        },
        select: { osvId: true, latestCvssScore: true, latestAliases: true },
      });
      if (aliasOverlap) {
        const overlap = aliasOverlap.latestAliases.filter((a) => aliases.includes(a));
        logger.warn(
          {
            package: component.name,
            existing: { osv_id: aliasOverlap.osvId, cvss: aliasOverlap.latestCvssScore },
            incoming: { osv_id: vuln.id, cvss: score },
            overlapping_aliases: overlap,
          },
          "[osvService] alias overlap — two OSV records for the same vuln; review needed",
        );
      }

      const { issue } = await upsertScaIssueFromDetection(
        client,
        scanRunId,
        scopeId,
        orgId,
        { name: component.name, version: component.version, ecosystem: component.ecosystem, scope: component.scope, isDevOnly: component.isDevOnly },
        {
          osvId: vuln.id,
          cveId: extractCveId(vuln),
          findingType: "cve",
          severity,
          cvssScore: score,
          cvssVector: vector,
          summary: vuln.summary ?? null,
          aliases,
          activelyExploited: false,
          eolDate: null,
          detailJson: vuln,
          manifestFile: component.manifestFile ?? null,
          manifestLine: manifestFields.line,
          manifestSnippet: manifestFields.snippet,
        },
      );

      await (client as PrismaClient).scanFinding.create({
        data: {
          scanRunId,
          componentId: component.id,
          issueId: issue.id,
          findingType: "cve",
          osvId: vuln.id,
          cveId: extractCveId(vuln),
          severity,
          cvssScore: score,
          cvssVector: vector,
          summary: vuln.summary ?? null,
          aliases,
          activelyExploited: false,
          detailJson: vuln as Prisma.InputJsonValue,
        },
      });
    }
  }

  logger.info({ scanRunId }, "[osvService] CVE findings persisted");
  return (client as PrismaClient).scanFinding.findMany({
    where: { scanRunId, findingType: "cve" },
  });
}

// ---------------------------------------------------------------------------
// Backfill latestCvssScore / latestCvssVector for existing rows
// ---------------------------------------------------------------------------

export async function backfillCvssScores(db: PrismaClient): Promise<void> {
  // Pass 1: fill in score from existing vector (cheap; no network).
  // Uses the unified parseCvssScore so it picks up both v3.x and v4.0 vectors.
  const rowsWithVector = await db.scaIssue.findMany({
    where: { latestCvssScore: null, latestCvssVector: { not: null } },
    select: { id: true, latestCvssVector: true },
  });
  let scoredFromVector = 0;
  for (const r of rowsWithVector) {
    const score = r.latestCvssVector ? parseCvssScore(r.latestCvssVector) : null;
    if (score !== null) {
      await db.scaIssue.update({ where: { id: r.id }, data: { latestCvssScore: score } });
      scoredFromVector++;
    }
  }
  if (scoredFromVector > 0) {
    logger.info({ updated: scoredFromVector, total: rowsWithVector.length }, "[osvService] backfilled CVSS scores from vector");
  }

  // Pass 2: re-query OSV for rows missing both vector and score. Some
  // advisories ship only CVSS_V4 — earlier ingestion code dropped those.
  const rowsNoVector = await db.scaIssue.findMany({
    where: { latestCvssVector: null, latestFindingType: "cve" },
    select: { id: true, osvId: true },
  });
  if (rowsNoVector.length === 0) return;
  let fromOsv = 0;
  for (const r of rowsNoVector) {
    try {
      const resp = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(r.osvId)}`);
      if (!resp.ok) continue;
      const vuln = (await resp.json()) as OsvVuln;
      const { vector, score } = pickCvss(vuln.severity ?? []);
      if (vector) {
        await db.scaIssue.update({
          where: { id: r.id },
          data: { latestCvssVector: vector, latestCvssScore: score ?? undefined },
        });
        fromOsv++;
      }
    } catch (err) {
      logger.warn({ osvId: r.osvId, err }, "[osvService] OSV re-query failed during backfill");
    }
  }
  logger.info({ updated: fromOsv, total: rowsNoVector.length }, "[osvService] backfilled CVSS vectors from OSV");
}

// ---------------------------------------------------------------------------
// Backfill manifest origin (file + line + snippet) for existing SCA issues.
//
// Reads sbom_components rows keyed on the scope's lastScanRunId to find each
// issue's component and its manifestFile (cdxgen evidence), then reads the
// snippet from the retained clone. Skips scopes whose repo isn't retained.
// ---------------------------------------------------------------------------

export async function backfillManifestOrigin(db: PrismaClient): Promise<void> {
  const { repoCachePath } = await import("./repoCache.js");
  const { stat, access } = await import("node:fs/promises");
  const { ScopeFileIndex } = await import("./sbomOccurrences.js");

  const scopes = await db.scanScope.findMany({
    where: { lastScanRunId: { not: null } },
    select: { id: true, path: true, repoId: true, lastScanRunId: true, repo: { select: { retainClone: true } } },
  });

  let totalUpdated = 0;
  for (const scope of scopes) {
    if (!scope.repo?.retainClone || !scope.lastScanRunId) continue;
    const cacheDir = repoCachePath(scope.repoId);
    try { await stat(cacheDir); } catch { continue; }
    const scopeDir = scope.path === "/" || scope.path === "" ? cacheDir : join(cacheDir, scope.path);

    // Read sbom_components directly — its `name` column is the canonical
    // package name (group:artifact for maven, group/name for npm-scoped),
    // which matches sca_issues.package_name. An older version of this
    // backfill re-parsed the raw cdxgen SBOM and keyed by cdxgen's raw `c.name`,
    // missing maven rows whose canonical name has a group prefix.
    // Its `manifest_file` column is already the repo-rooted path,
    // so we strip the scope prefix back off for the snippet read.
    const sbomRows = await db.sbomComponent.findMany({
      where: { scanRunId: scope.lastScanRunId },
      select: { name: true, manifestFile: true },
    });
    const manifestByName = new Map<string, string>();
    for (const r of sbomRows) {
      if (!r.manifestFile) continue;
      const { toScopeRelative } = await import("./scopePath.js");
      manifestByName.set(r.name, toScopeRelative(scope.path, r.manifestFile));
    }

    // Lazy scope file index — only built (and walked) if we hit a path
    // that doesn't exist on disk (cdxgen jar-deps basenames, etc.).
    const scopeIndex = new ScopeFileIndex(scopeDir, scope.path);

    // Process any issue that's missing the manifest LINE (or both file and
    // line). Filtering on `latestManifestFile: null` alone skipped rows whose
    // file path was set to a leaked-clone path — it wasn't null, so the
    // line/snippet never got filled. Now that the path-prefix backfill
    // cleans the file value, this filter catches both cases.
    const issues = await db.scaIssue.findMany({
      where: { scopeId: scope.id, latestManifestLine: null },
      select: { id: true, packageName: true },
    });
    for (const issue of issues) {
      let manifestFile = manifestByName.get(issue.packageName);
      if (!manifestFile) continue;

      // If the file doesn't actually exist at the expected location
      // (cdxgen jar-deps case: identity was just the jar basename), look
      // up the basename in the scope index. Exactly-one match → swap in
      // the real path; otherwise leave the file value alone.
      let onDisk = join(scopeDir, manifestFile);
      let exists = false;
      try { await access(onDisk); exists = true; } catch { /* miss */ }
      if (!exists) {
        const basename = manifestFile.split("/").pop() ?? "";
        if (basename) {
          const resolvedRepoRooted = await scopeIndex.resolveBasename(basename);
          if (resolvedRepoRooted) {
            // resolveBasename returns a repo-rooted path; readManifestSnippet
            // wants scope-relative, so strip the scope prefix back off.
            const { toScopeRelative } = await import("./scopePath.js");
            manifestFile = toScopeRelative(scope.path, resolvedRepoRooted);
            onDisk = join(scopeDir, manifestFile);
          }
        }
      }

      const { line, snippet } = await readManifestSnippet(scopeDir, manifestFile, issue.packageName);
      await db.scaIssue.update({
        where: { id: issue.id },
        data: {
          // Persist repo-rooted so the FE link works across scopes.
          latestManifestFile: toRepoRelative(scope.path, manifestFile),
          latestManifestLine: line,
          latestManifestSnippet: snippet,
        },
      });
      totalUpdated++;
    }
  }
  if (totalUpdated > 0) {
    logger.info({ updated: totalUpdated }, "[osvService] backfilled SCA manifest origin");
  }
}
