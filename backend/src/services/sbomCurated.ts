/**
 * sbomCurated.ts — M6q follow-up
 *
 * Builds a CycloneDX 1.7 document from the curated `sbom_components` rows
 * for a given scan run. This is what operators want when they click
 * "Download SBOM" — the post-augmentation, path-cleaned, dev-tree-aware
 * artifact that matches the Components tab.
 *
 * The raw cdxgen output stays in `scan_runs.sbom_json` for audit/debug,
 * but is no longer the user-facing surface. It's full of CMake
 * `find_package` probes (StandardMathLibrary, GoogleHash, ...) and
 * absolute "Filename /app/clones/<uuid>/..." paths that cdxgen's CMake
 * parser emits regardless of the process CWD.
 */

import { prisma } from "../db.js";

interface ComponentOccurrence {
  path: string;
  line: number | null;
}

interface LlmEvidence {
  path: string;
  excerpt: string | null;
  llmReason: string;
}

interface CycloneDxLicenseEntry {
  license?: { id: string };
}

interface CycloneDxEvidence {
  identity?: Array<{
    field: string;
    concludedValue?: string;
    methods?: Array<{ technique: string; value: string; confidence: number }>;
    confidence?: number;
  }>;
  occurrences?: Array<{ location: string }>;
}

interface CycloneDxComponent {
  type: string;
  name: string;
  version?: string;
  purl: string;
  "bom-ref": string;
  group?: string;
  scope?: string;
  licenses?: CycloneDxLicenseEntry[];
  evidence?: CycloneDxEvidence;
  properties?: Array<{ name: string; value: string }>;
}

export interface CuratedSbomDoc {
  bomFormat: "CycloneDX";
  specVersion: "1.7";
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: { components: Array<{ name: string; version?: string; type: string }> };
    component?: {
      type: "application";
      name: string;
      version?: string;
    };
  };
  components: CycloneDxComponent[];
}

// Module-level constant so both builders share the same tools array without
// duplicating the literal.
const SBOM_TOOLS_COMPONENTS: Array<{ name: string; version?: string; type: string }> = [
  { type: "application", name: "SASTBot", version: "M6q" },
  { type: "application", name: "cdxgen", version: "12.2" },
];

/**
 * Build a CycloneDX 1.7 doc from the persisted sbom_components rows for
 * `scanRunId`. Returns null when the scan run doesn't exist or has no
 * components yet (caller maps to 404).
 */
export async function buildCuratedSbomJson(
  scanRunId: string,
): Promise<CuratedSbomDoc | null> {
  const run = await prisma.scanRun.findUnique({
    where: { id: scanRunId },
    select: {
      id: true,
      finishedAt: true,
      createdAt: true,
      repo: { select: { name: true, defaultBranch: true } },
      scope: { select: { path: true } },
    },
  });
  if (!run) return null;

  const rows = await prisma.sbomComponent.findMany({
    where: { scanRunId },
    orderBy: [{ ecosystem: "asc" }, { name: "asc" }],
  });
  if (rows.length === 0) return null;

  const components: CycloneDxComponent[] = rows.map((r) => {
    const c: CycloneDxComponent = {
      type: r.componentType ?? "library",
      name: r.name,
      purl: r.purl,
      "bom-ref": r.purl,
    };
    if (r.version) c.version = r.version;
    if (r.scope) c.scope = r.scope;
    if (r.licenses && r.licenses.length > 0) {
      c.licenses = r.licenses.map((id) => ({ license: { id } }));
    }

    // Evidence: identity (manifest) + occurrences (where used).
    const evidence: CycloneDxEvidence = {};
    if (r.manifestFile) {
      evidence.identity = [{
        field: "purl",
        concludedValue: r.manifestFile,
        methods: [{
          technique: "manifest-analysis",
          value: r.manifestFile,
          confidence: 0.8,
        }],
        confidence: 0.8,
      }];
    }
    const occurrences = (r.occurrences ?? []) as unknown as ComponentOccurrence[];
    if (Array.isArray(occurrences) && occurrences.length > 0) {
      evidence.occurrences = occurrences.map((o) => ({
        location: o.line != null ? `${o.path}#${o.line}` : o.path,
      }));
    }
    if (evidence.identity || evidence.occurrences) c.evidence = evidence;

    // Properties: discovery method + LLM augmentation rationale where present.
    const properties: Array<{ name: string; value: string }> = [];
    if (r.discoveryMethod) {
      properties.push({ name: "sastbot:discovery_method", value: r.discoveryMethod });
    }
    if (r.isDevOnly) {
      properties.push({ name: "cdx:npm:package:development", value: "true" });
    }
    const evidenceBlob = r.llmEvidence as unknown as LlmEvidence | null;
    if (evidenceBlob && typeof evidenceBlob === "object" && evidenceBlob.llmReason) {
      properties.push({ name: "sastbot:llm_rationale", value: evidenceBlob.llmReason });
      if (evidenceBlob.path) {
        properties.push({ name: "sastbot:llm_evidence_path", value: evidenceBlob.path });
      }
    }
    if (properties.length > 0) c.properties = properties;

    return c;
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: `urn:uuid:${run.id}`,
    version: 1,
    metadata: {
      timestamp: (run.finishedAt ?? run.createdAt).toISOString(),
      tools: {
        components: SBOM_TOOLS_COMPONENTS,
      },
      component: {
        type: "application",
        name: `${run.repo.name}${run.scope.path === "/" ? "" : run.scope.path}`,
        version: run.repo.defaultBranch ?? undefined,
      },
    },
    components,
  };
}

/**
 * Build a CycloneDX 1.7 doc from the durable `scope_components` rows for
 * `scopeId`. This is the operator-facing artifact for the scope page — it
 * reflects operator edits (renames, manual evidence) because it reads
 * scope_components, not the per-scan sbom_components audit table.
 *
 * Returns null when the scope doesn't exist or has no active components
 * (caller maps to 404).
 *
 * Identity:
 *   serialNumber  = urn:uuid:<scopeId>   (stable, identifies this scope's SBOM)
 *   metadata.timestamp = max(scope_components.updatedAt) for active rows
 *   metadata.component.version = scope.lastScanRunId ("what scan last touched this")
 */
export async function buildCuratedSbomJsonForScope(
  scopeId: string,
): Promise<CuratedSbomDoc | null> {
  const scope = await prisma.scanScope.findUnique({
    where: { id: scopeId },
    select: {
      id: true,
      path: true,
      lastScanRunId: true,
      lastScanCompletedAt: true,
      createdAt: true,
      repo: { select: { name: true, defaultBranch: true } },
    },
  });
  if (!scope) return null;

  const scopeComponents = await prisma.scopeComponent.findMany({
    where: { scopeId, dismissedStatus: "active" },
    orderBy: [{ ecosystem: "asc" }, { name: "asc" }],
  });
  if (scopeComponents.length === 0) return null;

  // Compute metadata.timestamp = max(scope_components.updatedAt) across active
  // rows. Falls back to scope.lastScanCompletedAt or scope.createdAt if for
  // some reason no components have updatedAt (shouldn't happen given step above).
  const fallbackDate = scope.lastScanCompletedAt ?? scope.createdAt;
  const maxUpdatedAt = scopeComponents.reduce<Date>((max, sc) => {
    return sc.updatedAt > max ? sc.updatedAt : max;
  }, fallbackDate);
  const timestamp = maxUpdatedAt.toISOString();

  const components: CycloneDxComponent[] = scopeComponents.map((sc) => {
    const c: CycloneDxComponent = {
      type: sc.latestComponentType ?? sc.componentType ?? "library",
      name: sc.name,
      purl: sc.purl,
      "bom-ref": sc.purl,
    };
    if (sc.version) c.version = sc.version;
    if (sc.scope) c.scope = sc.scope;

    const licenses = sc.latestLicenses.length > 0 ? sc.latestLicenses : sc.licenses;
    if (licenses && licenses.length > 0) {
      c.licenses = licenses.map((id) => ({ license: { id } }));
    }

    // Evidence: identity (componentRoot or manifest) + occurrences (usage).
    const evidence: CycloneDxEvidence = {};

    // identity block: prefer componentRoot (vendored), fall back to manifest file.
    const componentRoot = sc.componentRoot;
    if (componentRoot) {
      evidence.identity = [{
        field: "purl",
        concludedValue: componentRoot,
        methods: [{
          technique: "filename",
          value: componentRoot,
          confidence: 0.9,
        }],
        confidence: 0.9,
      }];
    } else if (sc.manifestFile) {
      evidence.identity = [{
        field: "purl",
        concludedValue: sc.manifestFile,
        methods: [{
          technique: "manifest-analysis",
          value: sc.manifestFile,
          confidence: 0.8,
        }],
        confidence: 0.8,
      }];
    }

    // occurrences: use the operator-curated evidence[] array (identity
    // evidence), then usage[] for usage locations.
    const evidenceArr = (sc.evidence ?? []) as unknown as Array<{ path: string; line?: number | null }>;
    const usageArr = (sc.usage ?? []) as unknown as ComponentOccurrence[];
    // Combine: evidence entries first (identity), then usage locations.
    const allOccurrences: Array<{ path: string; line?: number | null }> = [
      ...evidenceArr,
      ...usageArr,
    ];
    if (allOccurrences.length > 0) {
      evidence.occurrences = allOccurrences.map((o) => ({
        location: o.line != null ? `${o.path}#${o.line}` : o.path,
      }));
    }

    if (evidence.identity || evidence.occurrences) c.evidence = evidence;

    // Properties.
    const properties: Array<{ name: string; value: string }> = [];
    const discoveryMethod = sc.latestDiscoveryMethod ?? sc.discoveryMethod;
    if (discoveryMethod) {
      properties.push({ name: "sastbot:discovery_method", value: discoveryMethod });
    }
    if (sc.isDevOnly) {
      properties.push({ name: "cdx:npm:package:development", value: "true" });
    }
    const llmEvidenceBlob = (sc.latestLlmEvidence ?? sc.llmEvidence) as unknown as LlmEvidence | null;
    if (llmEvidenceBlob && typeof llmEvidenceBlob === "object" && llmEvidenceBlob.llmReason) {
      properties.push({ name: "sastbot:llm_rationale", value: llmEvidenceBlob.llmReason });
      if (llmEvidenceBlob.path) {
        properties.push({ name: "sastbot:llm_evidence_path", value: llmEvidenceBlob.path });
      }
    }
    if (properties.length > 0) c.properties = properties;

    return c;
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: `urn:uuid:${scope.id}`,
    version: 1,
    metadata: {
      timestamp,
      tools: {
        components: SBOM_TOOLS_COMPONENTS,
      },
      component: {
        type: "application",
        name: `${scope.repo.name}${scope.path === "/" ? "" : scope.path}`,
        version: scope.lastScanRunId ?? undefined,
      },
    },
    components,
  };
}
