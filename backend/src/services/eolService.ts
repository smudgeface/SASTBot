/**
 * EOL / deprecation detection.
 *
 * Two data sources:
 *   1. npm registry — per-version `deprecated` field (any npm package)
 *   2. endoflife.date — structured EOL cycle dates for well-known products
 *
 * Results are persisted as ScanFinding rows with findingType "deprecated"
 * or "eol" alongside the CVE findings produced by osvService.
 */
import type { Prisma, PrismaClient, SbomComponent, ScanFinding } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import type { Severity } from "../schemas.js";
import { upsertScaIssueFromDetection } from "./issueService.js";

const logger = pino({ level: loadConfig().logLevel, name: "eolService" });

// ---------------------------------------------------------------------------
// endoflife.date — product slug mapping
// ---------------------------------------------------------------------------
// Maps lowercase package names (as they appear in PURLs) to endoflife.date
// product slugs. Extend this as more packages are tracked by the API.

const EOL_DATE_SLUG: Record<string, string> = {
  // JavaScript runtimes / frameworks
  node: "nodejs",
  nodejs: "nodejs",
  react: "react",
  vue: "vue",
  angular: "angular",
  "next.js": "nextjs",
  nuxt: "nuxt",
  // Python
  python: "python",
  django: "django",
  flask: "flask",
  // Java
  "spring-boot": "spring-boot",
  // Ruby
  rails: "rails",
  ruby: "ruby",
  // PHP
  symfony: "symfony",
  laravel: "laravel",
  // Databases / infra (if surfaced via cdxgen)
  postgresql: "postgresql",
  mysql: "mysql",
  redis: "redis",
  mongodb: "mongodb",
  // .NET
  dotnet: "dotnet",
};

// ---------------------------------------------------------------------------
// Severity from EOL proximity
// ---------------------------------------------------------------------------

function eolSeverity(eolDate: Date): Severity {
  const daysLeft = Math.ceil(
    (eolDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24),
  );
  if (daysLeft <= 0) return "critical"; // already past EOL
  if (daysLeft <= 90) return "high"; // within 3 months
  if (daysLeft <= 180) return "medium"; // within 6 months
  return "low"; // within 1 year (caller only creates finding if < 1 year)
}

// ---------------------------------------------------------------------------
// npm registry — deprecation check
// ---------------------------------------------------------------------------

interface NpmVersionMeta {
  deprecated?: string;
  [k: string]: unknown;
}

async function fetchNpmDeprecation(
  name: string,
  version: string,
): Promise<string | null> {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return null;
    const data = (await resp.json()) as NpmVersionMeta;
    return typeof data.deprecated === "string" ? data.deprecated : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// endoflife.date — cycle lookup
// ---------------------------------------------------------------------------

interface EolCycle {
  cycle: string;
  eol: string | boolean; // ISO date string, or false if no EOL set, or true if already EOL
  lts?: boolean;
  [k: string]: unknown;
}

async function fetchEolCycles(slug: string): Promise<EolCycle[]> {
  try {
    const url = `https://endoflife.date/api/${slug}.json`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) return [];
    return (await resp.json()) as EolCycle[];
  } catch {
    return [];
  }
}

/**
 * Find the best-matching cycle for a given version string.
 * endoflife.date cycles are like "20", "3.11", "4.2" etc.
 * We try: full version → major.minor → major.
 */
function matchCycle(cycles: EolCycle[], version: string): EolCycle | null {
  const parts = version.replace(/[^0-9.]/g, "").split(".");
  const candidates = [
    version,
    parts.slice(0, 3).join("."),
    parts.slice(0, 2).join("."),
    parts[0],
  ].filter((v) => v.length > 0);

  for (const candidate of candidates) {
    const match = cycles.find((c) => c.cycle === candidate);
    if (match) return match;
  }
  return null;
}

function parseEolDate(eol: string | boolean): Date | null {
  if (typeof eol === "boolean") return eol ? new Date(0) : null; // true = already EOL (epoch), false = no date
  const d = new Date(eol);
  return Number.isNaN(d.getTime()) ? null : d;
}

// ---------------------------------------------------------------------------
// Main entrypoint
// ---------------------------------------------------------------------------

type Tx = PrismaClient | Prisma.TransactionClient;

const ONE_YEAR_MS = 365 * 24 * 60 * 60 * 1000;

export async function checkAndPersistEolFindings(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  components: SbomComponent[],
  client: Tx,
): Promise<ScanFinding[]> {
  type ComponentFinding = { component: SbomComponent; row: FindingRow };
  const found: ComponentFinding[] = [];

  const CONCURRENCY = 10;
  for (let i = 0; i < components.length; i += CONCURRENCY) {
    const chunk = components.slice(i, i + CONCURRENCY);
    await Promise.all(
      chunk.map(async (component) => {
        const result = await checkComponent(component);
        if (result) found.push({ component, row: result });
      }),
    );
  }

  if (found.length === 0) return [];

  logger.info(
    { scanRunId, count: found.length },
    "[eolService] persisting EOL/deprecated findings",
  );

  for (const { component, row } of found) {
    const { issue } = await upsertScaIssueFromDetection(
      client,
      scanRunId,
      scopeId,
      orgId,
      { name: component.name, version: component.version, ecosystem: component.ecosystem, scope: component.scope },
      {
        osvId: row.osvId,
        cveId: row.cveId ?? null,
        findingType: row.findingType ?? "eol",
        severity: (row.severity ?? "unknown") as string,
        cvssScore: row.cvssScore ?? null,
        cvssVector: row.cvssVector ?? null,
        summary: row.summary ?? null,
        aliases: (row.aliases as string[]) ?? [],
        activelyExploited: row.activelyExploited ?? false,
        eolDate: row.eolDate instanceof Date ? row.eolDate : null,
      },
    );

    await (client as PrismaClient).scanFinding.create({
      data: { ...row, scanRunId, componentId: component.id, issueId: issue.id },
    });
  }

  return (client as PrismaClient).scanFinding.findMany({
    where: { scanRunId, findingType: { in: ["eol", "deprecated"] } },
  });
}

// ---------------------------------------------------------------------------
// Per-component check
// ---------------------------------------------------------------------------

type FindingRow = Omit<Prisma.ScanFindingCreateManyInput, "scanRunId" | "componentId" | "issueId">;

async function checkComponent(c: SbomComponent): Promise<FindingRow | null> {
  const { name, version, ecosystem } = c;
  if (!version) return null;

  const eco = (ecosystem ?? "").toLowerCase();

  // 1. endoflife.date — for products we have a slug mapping for.
  const slug = EOL_DATE_SLUG[name.toLowerCase()];
  if (slug) {
    const finding = await checkEolDate(name, version, slug);
    if (finding) return finding;
  }

  // 2. npm registry deprecation for npm packages.
  if (eco === "npm") {
    const finding = await checkNpmDeprecation(name, version);
    if (finding) return finding;
  }

  return null;
}

async function checkEolDate(
  name: string,
  version: string,
  slug: string,
): Promise<FindingRow | null> {
  const cycles = await fetchEolCycles(slug);
  if (cycles.length === 0) return null;

  const cycle = matchCycle(cycles, version);
  if (!cycle) return null;

  const eolDate = parseEolDate(cycle.eol);
  if (!eolDate) return null;

  // Only surface as a finding if EOL is within 1 year (or already past).
  const msUntilEol = eolDate.getTime() - Date.now();
  if (msUntilEol > ONE_YEAR_MS) return null;

  const severity = eolSeverity(eolDate);
  const isPast = msUntilEol <= 0;
  const summary = isPast
    ? `${name} ${version} (cycle ${cycle.cycle}) reached end-of-life on ${eolDate.toISOString().slice(0, 10)}`
    : `${name} ${version} (cycle ${cycle.cycle}) reaches end-of-life on ${eolDate.toISOString().slice(0, 10)}`;

  return {
    findingType: "eol",
    osvId: `EOL-${slug}-${cycle.cycle}`,
    cveId: null,
    severity,
    cvssScore: null,
    cvssVector: null,
    summary,
    aliases: [],
    activelyExploited: false,
    eolDate,
    detailJson: { slug, cycle: cycle.cycle, eol: cycle.eol, lts: cycle.lts ?? null } as Prisma.InputJsonValue,
  };
}

async function checkNpmDeprecation(
  name: string,
  version: string,
): Promise<FindingRow | null> {
  const reason = await fetchNpmDeprecation(name, version);
  if (!reason) return null;

  return {
    findingType: "deprecated",
    osvId: `DEPRECATED-npm-${name}@${version}`,
    cveId: null,
    severity: "medium",
    cvssScore: null,
    cvssVector: null,
    summary: reason,
    aliases: [],
    activelyExploited: false,
    eolDate: null,
    detailJson: { registry: "npm", name, version, deprecated: reason } as Prisma.InputJsonValue,
  };
}
