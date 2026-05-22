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
import { sbomPathFor, writeArtifact } from "./artifactStore.js";

// ---------------------------------------------------------------------------
// D5 — Key-stable JSON serializer
//
// Produces output byte-for-byte identical to JSON.stringify(value, null, indent)
// except that object keys are emitted in ascending lexicographic order at
// every depth. Arrays preserve their element order (callers are responsible
// for sorting arrays before passing them in).
//
// Edge cases:
//   undefined values → omitted from objects (same as JSON.stringify)
//   NaN / Infinity  → serialised as null (same as JSON.stringify)
//   Date objects    → serialised as ISO string via .toJSON() (same as
//                     JSON.stringify, which calls toJSON on objects that
//                     expose it)
//   Circular refs   → throws (same as JSON.stringify)
// ---------------------------------------------------------------------------
export function stableStringify(value: unknown, indent?: number): string {
  return _stableNode(value, indent ?? 0, 0);
}

function _stableNode(value: unknown, indent: number, depth: number): string {
  // Let JSON.stringify handle primitives, null, and toJSON() protocol.
  if (value === null) return "null";
  if (typeof value === "boolean" || typeof value === "number") {
    // NaN / Infinity → null, matching JSON.stringify behaviour.
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "undefined" || typeof value === "function" || typeof value === "symbol") {
    // At the top level JSON.stringify returns undefined (not a string).
    // Inside arrays it returns "null". Inside objects the key is omitted.
    // The caller never hits top-level undefined in our routes, so returning
    // "null" is the safest default (matches array behaviour).
    return "null";
  }
  // Objects with a toJSON method (e.g. Date) — delegate, then recurse.
  if (typeof value === "object" && value !== null && typeof (value as Record<string, unknown>).toJSON === "function") {
    return _stableNode((value as { toJSON(): unknown }).toJSON(), indent, depth);
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const gap = indent > 0 ? " ".repeat(indent * (depth + 1)) : "";
    const closingGap = indent > 0 ? " ".repeat(indent * depth) : "";
    const sep = indent > 0 ? "\n" : "";
    const itemSep = indent > 0 ? ",\n" : ",";
    const items = value.map((item) => `${sep}${gap}${_stableNode(item, indent, depth + 1)}`);
    return `[${items.join(itemSep)}${sep}${closingGap}]`;
  }
  // Plain object — sort keys lexicographically.
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  const definedKeys = keys.filter((k) => obj[k] !== undefined && typeof obj[k] !== "function" && typeof obj[k] !== "symbol");
  if (definedKeys.length === 0) return "{}";
  const gap = indent > 0 ? " ".repeat(indent * (depth + 1)) : "";
  const closingGap = indent > 0 ? " ".repeat(indent * depth) : "";
  const sep = indent > 0 ? "\n" : "";
  const itemSep = indent > 0 ? ",\n" : ",";
  const pairs = definedKeys.map(
    (k) => `${sep}${gap}${JSON.stringify(k)}: ${_stableNode(obj[k], indent, depth + 1)}`,
  );
  return `{${pairs.join(itemSep)}${sep}${closingGap}}`;
}

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
 * B1: serialize the canonical CycloneDX 1.7 SBOM for `scanRunId` and write it
 * to ${ARTIFACT_DIR}/sbom/${scanRunId}.json. Idempotent — overwrites the file
 * atomically (via artifactStore.writeArtifact). Returns { written, path }.
 *
 * `written: false` means the scan had no components and no file was emitted —
 * caller (worker.ts) treats this as a warning condition.
 */
export async function emitSbomArtifact(
  scanRunId: string,
): Promise<{ written: boolean; path: string }> {
  const doc = await buildCuratedSbomJson(scanRunId);
  const filePath = sbomPathFor(scanRunId);
  if (!doc) return { written: false, path: filePath };
  const body = stableStringify(doc, 2);
  await writeArtifact(filePath, body);
  return { written: true, path: filePath };
}

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
    // D1: full tiebreaker chain — (ecosystem, name, purl, id) — ensures a
    // deterministic row order even when two components share name + ecosystem.
    orderBy: [{ ecosystem: "asc" }, { name: "asc" }, { purl: "asc" }, { id: "asc" }],
  });
  if (rows.length === 0) return null;

  // D2 comparator: sort occurrences by (path asc, line asc nulls-first).
  function sortOccurrences(arr: ComponentOccurrence[]): ComponentOccurrence[] {
    return [...arr].sort((a, b) => {
      const pathCmp = a.path.localeCompare(b.path);
      if (pathCmp !== 0) return pathCmp;
      return (a.line ?? -Infinity) - (b.line ?? -Infinity);
    });
  }

  const components: CycloneDxComponent[] = rows.map((r) => {
    const c: CycloneDxComponent = {
      type: r.componentType ?? "library",
      name: r.name,
      purl: r.purl,
      "bom-ref": r.purl,
    };
    if (r.version) c.version = r.version;
    if (r.scope) c.scope = r.scope;
    // D3: sort licenses lexicographically before mapping.
    if (r.licenses && r.licenses.length > 0) {
      c.licenses = [...r.licenses].sort().map((id) => ({ license: { id } }));
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
      // D2: sort occurrences deterministically.
      evidence.occurrences = sortOccurrences(occurrences).map((o) => ({
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
    // D4: sort properties by (name asc, value asc) — eliminates "stable by
    // source-code accident" fragility without reorganising the conditional blocks.
    if (properties.length > 0) {
      properties.sort((a, b) => {
        const nameCmp = a.name.localeCompare(b.name);
        return nameCmp !== 0 ? nameCmp : a.value.localeCompare(b.value);
      });
      c.properties = properties;
    }

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
    // D1: full tiebreaker chain — (ecosystem, name, purl, id).
    orderBy: [{ ecosystem: "asc" }, { name: "asc" }, { purl: "asc" }, { id: "asc" }],
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

  // D2 comparator (shared with scan-level builder): sort occurrences by
  // (path asc, line asc nulls-first).
  function sortOccurrencesScope(arr: Array<{ path: string; line?: number | null }>): typeof arr {
    return [...arr].sort((a, b) => {
      const pathCmp = a.path.localeCompare(b.path);
      if (pathCmp !== 0) return pathCmp;
      return ((a.line ?? -Infinity) as number) - ((b.line ?? -Infinity) as number);
    });
  }

  const components: CycloneDxComponent[] = scopeComponents.map((sc) => {
    const c: CycloneDxComponent = {
      type: sc.latestComponentType ?? sc.componentType ?? "library",
      name: sc.name,
      purl: sc.purl,
      "bom-ref": sc.purl,
    };
    if (sc.version) c.version = sc.version;
    if (sc.scope) c.scope = sc.scope;

    // D3: sort latestLicenses (or fallback licenses) lexicographically.
    const licenses = sc.latestLicenses.length > 0 ? sc.latestLicenses : sc.licenses;
    if (licenses && licenses.length > 0) {
      c.licenses = [...licenses].sort().map((id) => ({ license: { id } }));
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

    // occurrences: combine evidence entries (identity) + usage locations, then
    // D2-sort before mapping to CycloneDX location strings.
    const evidenceArr = (sc.evidence ?? []) as unknown as Array<{ path: string; line?: number | null }>;
    const usageArr = (sc.usage ?? []) as unknown as ComponentOccurrence[];
    const allOccurrences: Array<{ path: string; line?: number | null }> = [
      ...evidenceArr,
      ...usageArr,
    ];
    if (allOccurrences.length > 0) {
      // D2: sort before mapping so output is independent of insertion order.
      evidence.occurrences = sortOccurrencesScope(allOccurrences).map((o) => ({
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
    // D4: sort properties by (name asc, value asc) — eliminates "stable by
    // source-code accident" fragility without reorganising the conditional blocks.
    if (properties.length > 0) {
      properties.sort((a, b) => {
        const nameCmp = a.name.localeCompare(b.name);
        return nameCmp !== 0 ? nameCmp : a.value.localeCompare(b.value);
      });
      c.properties = properties;
    }

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
