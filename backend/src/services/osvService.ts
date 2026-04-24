import type { Prisma, PrismaClient, SbomComponent, ScanFinding } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import type { Severity } from "../schemas.js";
import { upsertScaIssueFromDetection } from "./issueService.js";

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
  return null;
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

async function queryOsvForPurl(purl: string): Promise<OsvVuln[]> {
  const response = await fetch(OSV_QUERY_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ package: { purl } }),
  });
  if (!response.ok) {
    logger.warn({ purl, status: response.status }, "[osvService] OSV query failed — skipping");
    return [];
  }
  const data = (await response.json()) as OsvQueryResponse;
  return data.vulns ?? [];
}

/** Query OSV.dev for each PURL, throttled to OSV_CONCURRENCY parallel requests. */
async function queryOsvForPurls(purls: string[]): Promise<OsvVuln[][]> {
  const results: OsvVuln[][] = new Array(purls.length);
  // Process in windows of OSV_CONCURRENCY to avoid hammering OSV.dev.
  for (let i = 0; i < purls.length; i += OSV_CONCURRENCY) {
    const chunk = purls.slice(i, i + OSV_CONCURRENCY);
    const chunkResults = await Promise.all(chunk.map(queryOsvForPurl));
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
): Promise<ScanFinding[]> {
  const withPurl = components.filter((c) => c.purl);
  if (withPurl.length === 0) return [];

  logger.info({ scanRunId, count: withPurl.length }, "[osvService] querying OSV.dev");
  const purls = withPurl.map((c) => c.purl);
  const results = await queryOsvForPurls(purls);

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
      const cvss3 = vuln.severity?.find((s: OsvSeverityEntry) => s.type === "CVSS_V3");
      const aliases = [vuln.id, ...(vuln.aliases ?? [])].filter(
        (a, idx, arr) => arr.indexOf(a) === idx,
      );

      const { issue } = await upsertScaIssueFromDetection(
        client,
        scanRunId,
        scopeId,
        orgId,
        { name: component.name, version: component.version, ecosystem: component.ecosystem, scope: component.scope },
        {
          osvId: vuln.id,
          cveId: extractCveId(vuln),
          findingType: "cve",
          severity,
          cvssScore: cvss3 ? parseCvssScore(cvss3.score) : null,
          cvssVector: cvss3 ? cvss3.score : null,
          summary: vuln.summary ?? null,
          aliases,
          activelyExploited: false,
          eolDate: null,
          detailJson: vuln,
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
          cvssScore: cvss3 ? parseCvssScore(cvss3.score) : null,
          cvssVector: cvss3 ? cvss3.score : null,
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
// Backfill latestCvssScore for existing rows that have a vector but no score
// ---------------------------------------------------------------------------

export async function backfillCvssScores(db: PrismaClient): Promise<void> {
  const rows = await db.scaIssue.findMany({
    where: { latestCvssScore: null, latestCvssVector: { not: null } },
    select: { id: true, latestCvssVector: true },
  });
  if (rows.length === 0) return;
  let updated = 0;
  for (const r of rows) {
    const score = r.latestCvssVector ? computeCvss31BaseScore(r.latestCvssVector) : null;
    if (score !== null) {
      await db.scaIssue.update({ where: { id: r.id }, data: { latestCvssScore: score } });
      updated++;
    }
  }
  logger.info({ updated, total: rows.length }, "[osvService] backfilled CVSS scores");
}
