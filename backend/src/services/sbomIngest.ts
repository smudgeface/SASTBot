/**
 * sbomIngest.ts — E1 file-first SBOM pipeline ingest.
 *
 * Reads ${ARTIFACT_DIR}/sbom/<scanRunId>.json and populates sbom_components
 * rows from the CycloneDX document. Idempotent: clears existing rows for this
 * scanRunId before inserting so re-runs on the same file produce identical
 * row sets.
 *
 * Used by:
 *   source='cdxgen' — after buildAugmentationSbom + writeArtifact in the
 *                     sbom_emit phase, ingest produces the DB rows.
 *   source='upload' — operator-uploaded SBOM; same path, file is authored
 *                     externally (Stream B7 future work uses this same function).
 *
 * After E1, sbom_components is written ONLY here. No other code path may
 * write to sbom_components for a given scan_run_id.
 */

import { Prisma } from "@prisma/client";
import { pino } from "pino";

import { prisma } from "../db.js";
import { loadConfig } from "../config.js";
import { sbomPathFor, tryReadArtifact } from "./artifactStore.js";
import type { CuratedSbomDoc } from "./sbomCurated.js";
import type { CdxComponent } from "./sbomService.js";
import {
  extractEcosystem,
  canonicalPackageName,
  extractLicenses,
  extractIsDevOnly,
  extractManifestFile,
} from "./sbomService.js";
import { toRepoRelative } from "./scopePath.js";
import {
  extractOccurrences,
  resolveManifestLines,
  ScopeFileIndex,
} from "./sbomOccurrences.js";
import { readManifestSnippet } from "./manifestSnippet.js";

const logger = pino({ level: loadConfig().logLevel, name: "sbomIngest" });

/**
 * Read ${ARTIFACT_DIR}/sbom/<scanRunId>.json and populate sbom_components rows.
 * Idempotent: deletes any existing rows for this scanRunId before insert.
 * Writes scan_runs.componentCount = doc.components.length.
 *
 * Throws when:
 *   - no artifact file found on disk
 *   - the artifact is not valid JSON
 */
export async function ingestSbomFromArtifact(scanRunId: string): Promise<void> {
  const body = await tryReadArtifact(sbomPathFor(scanRunId));
  if (!body) {
    throw new Error(`sbom_ingest: no SBOM artifact found for scan ${scanRunId}`);
  }

  let doc: CuratedSbomDoc;
  try {
    doc = JSON.parse(body.toString("utf8")) as CuratedSbomDoc;
  } catch (e) {
    throw new Error(
      `sbom_ingest: SBOM artifact for scan ${scanRunId} is not valid JSON: ${(e as Error).message}`,
    );
  }

  const cdxComponents = doc.components ?? [];

  // Build Prisma rows by reading back sastbot:* properties from the file.
  const rows = cdxComponents.map((comp) => {
    // Build a property lookup map for O(1) access.
    const propMap = new Map<string, string>();
    for (const p of comp.properties ?? []) {
      if (p.name && p.value !== undefined) propMap.set(p.name, p.value);
    }

    const isDevOnly = propMap.get("cdx:npm:package:development") === "true";
    const discoveryMethod = propMap.get("sastbot:discovery_method") ?? "manifest";
    const componentRoot = propMap.get("sastbot:component_root") ?? null;
    const cpe = propMap.get("sastbot:cpe") ?? null;
    const ecosystem = propMap.get("sastbot:ecosystem") ?? null;
    const manifestFile = propMap.get("sastbot:manifest_file") ?? null;
    const componentType = propMap.get("sastbot:component_type") ?? comp.type ?? "library";
    const rawScope = propMap.get("sastbot:scope") ?? comp.scope ?? null;

    // Parse JSON round-trip properties.
    let llmEvidence: Prisma.InputJsonValue | undefined;
    const rawLlmEvidence = propMap.get("sastbot:llm_evidence");
    if (rawLlmEvidence) {
      try { llmEvidence = JSON.parse(rawLlmEvidence) as Prisma.InputJsonValue; } catch { /* leave undefined */ }
    }

    let occurrences: Prisma.InputJsonValue = [];
    const rawOccurrences = propMap.get("sastbot:occurrences");
    if (rawOccurrences) {
      try { occurrences = JSON.parse(rawOccurrences) as Prisma.InputJsonValue; } catch { occurrences = []; }
    }

    let evidence: Prisma.InputJsonValue = [];
    const rawEvidence = propMap.get("sastbot:identity_evidence");
    if (rawEvidence) {
      try { evidence = JSON.parse(rawEvidence) as Prisma.InputJsonValue; } catch { evidence = []; }
    }

    // Licenses from the CycloneDX licenses array (not a property).
    const licenses: string[] = (comp.licenses ?? [])
      .map((l) => l.license?.id)
      .filter((id): id is string => typeof id === "string" && id.length > 0);

    return {
      scanRunId,
      name: comp.name,
      version: comp.version ?? null,
      purl: comp.purl,
      ecosystem,
      licenses,
      componentType,
      scope: rawScope,
      isDevOnly,
      manifestFile,
      discoveryMethod,
      llmEvidence,
      occurrences,
      evidence,
      cpe,
      componentRoot,
    };
  });

  // Transactionally: clear existing rows → insert fresh → update componentCount.
  await prisma.$transaction(async (tx) => {
    await tx.sbomComponent.deleteMany({ where: { scanRunId } });
    if (rows.length > 0) {
      await tx.sbomComponent.createMany({
        data: rows,
        skipDuplicates: true,
      });
    }
    await tx.scanRun.update({
      where: { id: scanRunId },
      data: { componentCount: cdxComponents.length },
    });
  });

  logger.info(
    { scanRunId, inserted: rows.length },
    "[sbomIngest] sbom_components populated from artifact file",
  );
}

/**
 * Persist sbom_components rows from the in-memory post-augmentation component
 * list — no file round-trip needed. Called by the worker's `sbom_persist` phase
 * (M11), which runs right after `llm_sbom` so that osv/nvd/eol phases can read
 * DB rows while the artifact file is deferred to after those phases.
 *
 * Produces the same rows that `ingestSbomFromArtifact` would produce for the
 * same component set, using the same helper chain.
 *
 * Idempotent: clears existing sbom_components rows for this scanRunId before insert.
 */
export async function persistComponentsFromMemory(input: {
  scanRunId: string;
  scanDir: string;
  scopePath: string;
  components: CdxComponent[];
  sbomEvidenceMap: Map<string, { path: string; excerpt: string | null; llmReason: string }>;
  sbomCpeMap: Map<string, string>;
  sbomIdentityMap: Map<string, { componentRoot: string | null; evidence: Array<{ path: string; line: number | null }> }>;
}): Promise<{ inserted: number }> {
  const { scanRunId, scanDir, scopePath, components, sbomEvidenceMap, sbomCpeMap, sbomIdentityMap } = input;

  // Dedup by purl (same logic as buildAugmentationSbom / persistAugmentedComponents).
  const unique = new Map<string, CdxComponent>();
  for (const c of components) {
    const purl =
      c.purl ??
      `pkg:generic/${encodeURIComponent(c.name ?? "unknown")}${c.version ? `@${encodeURIComponent(c.version)}` : ""}`;
    if (!unique.has(purl)) unique.set(purl, { ...c, purl });
  }

  const lockfileCache = new Map<string, string[] | null>();
  const scopeIndex = scanDir ? new ScopeFileIndex(scanDir, scopePath) : undefined;
  const rows: Array<{
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
    discoveryMethod: string;
    llmEvidence?: Prisma.InputJsonValue;
    occurrences: Prisma.InputJsonValue;
    evidence: Prisma.InputJsonValue;
    cpe: string | null;
    componentRoot: string | null;
  }> = [];

  for (const c of unique.values()) {
    const ecosystem = extractEcosystem(c.purl);
    const canonicalName = canonicalPackageName(c, ecosystem);
    const evidence = sbomEvidenceMap.get(canonicalName) ?? null;
    const identity = sbomIdentityMap.get(canonicalName) ?? null;
    const cpe = sbomCpeMap.get(canonicalName) ?? null;

    const sr = extractManifestFile(c, scanDir);
    const manifestFile = sr ? toRepoRelative(scopePath, sr) : null;

    // Occurrences: mirror buildAugmentationSbom's priority chain.
    const occurrences = extractOccurrences(c, evidence?.path ?? null, false, scopePath);
    await resolveManifestLines(
      occurrences,
      canonicalName,
      scanDir || null,
      scopePath,
      lockfileCache,
      scopeIndex,
    );

    // Identity evidence: mirror buildAugmentationSbom's priority chain.
    let identityEvidence: Array<{ path: string; line?: number | null; snippet?: string | null }> | undefined;
    if (identity?.evidence && identity.evidence.length > 0) {
      identityEvidence = identity.evidence.map((e) => ({
        path: e.path,
        ...(e.line != null ? { line: e.line } : {}),
      }));
    } else if (manifestFile && scanDir) {
      const scopeRelative = manifestFile.startsWith(`${scopePath.replace(/^\//, "")}/`)
        ? manifestFile.slice(scopePath.replace(/^\//, "").length + 1)
        : manifestFile;
      const ms = await readManifestSnippet(scanDir, scopeRelative, canonicalName);
      identityEvidence = [{ path: manifestFile, line: ms.line, snippet: ms.snippet }];
    }

    const llmEvidence: Prisma.InputJsonValue | undefined = evidence
      ? ({ path: evidence.path, excerpt: evidence.excerpt, llmReason: evidence.llmReason } as Prisma.InputJsonValue)
      : undefined;

    rows.push({
      scanRunId,
      name: canonicalName,
      version: c.version ?? null,
      purl: c.purl!,
      ecosystem,
      licenses: extractLicenses(c.licenses),
      componentType: c.type ?? "library",
      scope: c.scope ?? null,
      isDevOnly: extractIsDevOnly(c),
      manifestFile,
      discoveryMethod: (c as CdxComponent & { discoveryMethod?: string }).discoveryMethod ?? "manifest",
      llmEvidence,
      occurrences: occurrences as unknown as Prisma.InputJsonValue,
      evidence: (identityEvidence ?? []) as unknown as Prisma.InputJsonValue,
      cpe,
      componentRoot: identity?.componentRoot ?? null,
    });
  }

  await prisma.$transaction(async (tx) => {
    await tx.sbomComponent.deleteMany({ where: { scanRunId } });
    if (rows.length > 0) {
      await tx.sbomComponent.createMany({ data: rows, skipDuplicates: true });
    }
    await tx.scanRun.update({
      where: { id: scanRunId },
      data: { componentCount: rows.length },
    });
  });

  logger.info(
    { scanRunId, inserted: rows.length },
    "[sbomIngest] sbom_components populated from in-memory components",
  );

  return { inserted: rows.length };
}
