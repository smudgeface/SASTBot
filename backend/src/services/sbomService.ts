import { execFile } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { toRepoRelative } from "./scopePath.js";

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

interface CdxComponent {
  type?: string;
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

/**
 * Extract the manifest file path that cdxgen attributed this component to,
 * relative to the scope's working directory. cdxgen exposes it twice:
 *   1. `properties[].name === "SrcFile"` (universal across project types)
 *   2. `evidence.identity[].methods[].technique === "manifest-analysis"`
 * We try (1) first, falling back to (2). Returns null if neither is present.
 */
function extractManifestFile(c: CdxComponent, scopeDir: string): string | null {
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
  // Strip absolute clone prefix if present so paths are repo-relative.
  if (abs.startsWith(scopeDir + "/")) return abs.slice(scopeDir.length + 1);
  // cdxgen sometimes emits paths under /tmp/sastbot-repo-<uuid>/... (the
  // ephemeral cdxgen working tree). Strip everything up to the first known
  // manifest filename so we return e.g. "package-lock.json".
  const m = abs.match(/\/((?:[^/]+\/)*[^/]+\.(?:json|toml|lock|xml|gradle|kts|txt|yaml|yml|cfg|in|pip|mod|sum|csproj|fsproj|vbproj|sln|gemspec|gemfile))$/i);
  return m ? m[1]! : abs;
}

// ---------------------------------------------------------------------------
// cdxgen invocation
// ---------------------------------------------------------------------------

/**
 * Run cdxgen against `workingDir` and return the parsed CycloneDX JSON.
 * cdxgen is installed as a package dep; its binary is in node_modules/.bin.
 */
export async function runCdxgen(workingDir: string, excludes: string[] = []): Promise<CycloneDxDocument> {
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

    try {
      await execFileAsync(
        cdxgenBin,
        ["-o", outputPath, ...excludeArgs, workingDir],
        {
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
      logger.warn({ err }, "[sbomService] cdxgen exited non-zero — checking for output");
    }

    // If cdxgen didn't write the file (unrecognised project type), return an
    // empty SBOM so the scan succeeds with 0 components rather than failing.
    const fileExists = await access(outputPath).then(() => true).catch(() => false);
    if (!fileExists) {
      logger.warn({ workingDir }, "[sbomService] cdxgen produced no output — returning empty SBOM");
      return { bomFormat: "CycloneDX", specVersion: "1.7", components: [] };
    }

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
      // CycloneDX scope: "required" | "optional" | "excluded"
      // npm devDependencies → scope="optional"
      scope: c.scope ?? null,
      manifestFile: (() => {
        const sr = extractManifestFile(c, scopeDir);
        return sr ? toRepoRelative(scopePath, sr) : null;
      })(),
    })),
    skipDuplicates: true,
  });

  return (client as PrismaClient).sbomComponent.findMany({
    where: { scanRunId },
  });
}
