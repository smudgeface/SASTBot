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
 * Extract the numeric base score from a CVSS vector string like
 * "CVSS:3.1/AV:N/AC:L/..." — the score is NOT embedded in the vector itself;
 * OSV sometimes returns just the vector. When the field is a plain float
 * string ("7.5") we parse it directly.
 */
function parseCvssScore(scoreOrVector: string): number | null {
  const n = parseFloat(scoreOrVector);
  if (!Number.isNaN(n) && n >= 0 && n <= 10) return n;
  return null;
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
