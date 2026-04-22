import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import type { Prisma, PrismaClient, SbomComponent } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";

const execFileAsync = promisify(execFile);
const logger = pino({ level: loadConfig().logLevel, name: "sbomService" });

// ---------------------------------------------------------------------------
// CycloneDX 1.7 shape (subset we care about)
// ---------------------------------------------------------------------------

interface CdxLicenseEntry {
  license?: { id?: string; name?: string };
  expression?: string;
}

interface CdxComponent {
  type?: string;
  name?: string;
  version?: string;
  purl?: string;
  licenses?: CdxLicenseEntry[];
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

function extractEcosystem(purl: string | undefined): string | null {
  if (!purl) return null;
  const m = purl.match(/^pkg:([^/]+)\//);
  return m ? m[1] : null;
}

function extractLicenses(entries: CdxLicenseEntry[] | undefined): string[] {
  if (!entries) return [];
  return entries
    .map((e) => e.license?.id ?? e.license?.name ?? e.expression ?? null)
    .filter((l): l is string => l !== null);
}

// ---------------------------------------------------------------------------
// cdxgen invocation
// ---------------------------------------------------------------------------

/**
 * Run cdxgen against `workingDir` and return the parsed CycloneDX JSON.
 * cdxgen is installed as a package dep; its binary is in node_modules/.bin.
 */
export async function runCdxgen(workingDir: string): Promise<CycloneDxDocument> {
  // Write the SBOM to a temp file so we don't have to parse stdout noise.
  const tmpDir = await mkdtemp(join(tmpdir(), "cdxgen-"));
  const outputPath = join(tmpDir, "sbom.json");

  try {
    // `cdxgen` detects the project type automatically when -t is omitted.
    // --no-recurse keeps it focused on the root manifest.
    const cdxgenBin = join(process.cwd(), "node_modules", ".bin", "cdxgen");
    logger.info({ workingDir, outputPath }, "[sbomService] running cdxgen");

    await execFileAsync(
      cdxgenBin,
      ["-o", outputPath, "--no-recurse", workingDir],
      {
        timeout: 5 * 60 * 1000, // 5-minute hard cap
        env: {
          ...process.env,
          // Suppress cdxgen's own update-check noise
          CDXGEN_DEBUG_MODE: "false",
          FETCH_LICENSE: "true",
        },
      },
    );

    const raw = await readFile(outputPath, "utf8");
    return JSON.parse(raw) as CycloneDxDocument;
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
 */
export async function persistComponents(
  scanRunId: string,
  doc: CycloneDxDocument,
  client: Tx,
): Promise<SbomComponent[]> {
  const components = doc.components ?? [];
  const unique = new Map<string, CdxComponent>();

  for (const c of components) {
    if (c.purl && !unique.has(c.purl)) unique.set(c.purl, c);
  }

  if (unique.size === 0) {
    logger.warn({ scanRunId }, "[sbomService] cdxgen produced 0 components");
    return [];
  }

  // Batch-insert; skip duplicates silently (skipDuplicates=true relies on
  // the unique index; Prisma createMany doesn't return records so we refetch).
  await (client as PrismaClient).sbomComponent.createMany({
    data: Array.from(unique.values()).map((c) => ({
      scanRunId,
      name: c.name ?? "unknown",
      version: c.version ?? null,
      purl: c.purl!,
      ecosystem: extractEcosystem(c.purl),
      licenses: extractLicenses(c.licenses),
      componentType: c.type ?? "library",
    })),
    skipDuplicates: true,
  });

  return (client as PrismaClient).sbomComponent.findMany({
    where: { scanRunId },
  });
}
