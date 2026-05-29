/**
 * sbomCurated.ts — M6q follow-up
 *
 * Builds curated CycloneDX 1.7 documents. Two builders, two scopes:
 *
 *  1. Per-scan (`buildCuratedSbomJson` / the `sbom_emit` path): reads the
 *     immutable per-scan `sbom_components` rows for a given scan run. Written to
 *     the artifact store (`${ARTIFACT_DIR}/sbom/<scanRunId>.json`) by the
 *     `sbom_emit` worker phase (M9 Stream B1) and served by `GET /scans/:id/sbom`.
 *     The raw cdxgen output is no longer stored — legacy scans (run before M9
 *     Stream B) have no artifact file and that endpoint returns 404 with a re-run hint.
 *
 *  2. Scope-level (`buildCuratedSbomJsonForScope`): reads the durable,
 *     operator-edited `scope_components` rows, built on demand and served by
 *     `GET /api/scopes/:id/sbom-json`. This is the primary CRA-compliance artifact
 *     and reflects operator edits (renames, ignores). Same content shape as (1),
 *     different scope: per-run snapshot vs per-scope durable state.
 *
 * Both produce the post-augmentation, path-cleaned, dev-tree-aware component set
 * that matches the Components tab.
 */

import { prisma } from "../db.js";
import { APP_VERSION } from "../routes/version.js";
import { sbomPathFor, writeArtifact } from "./artifactStore.js";
import {
  type CdxComponent,
  canonicalPackageName,
  extractEcosystem,
  extractIsDevOnly,
  extractLicenses,
  extractManifestFile,
} from "./sbomService.js";
import { extractOccurrences, resolveManifestLines, ScopeFileIndex } from "./sbomOccurrences.js";
import { readManifestSnippet } from "./manifestSnippet.js";
import { toRepoRelative } from "./scopePath.js";

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

interface CycloneDxVulnerabilitySource {
  name: string;
  url: string;
}

interface CycloneDxRating {
  source: { name: string };
  score?: number;
  severity?: string;
  method?: string;
  vector?: string;
}

interface CycloneDxReference {
  id: string;
  source: { name: string };
}

interface CycloneDxAdvisory {
  url: string;
}

interface CycloneDxAffect {
  ref: string;
}

interface CycloneDxAnalysis {
  state: string;
  detail?: string;
  response?: string[];
  firstIssued: string;
  lastUpdated: string;
}

interface CycloneDxVulnerability {
  "bom-ref": string;
  id: string;
  source: CycloneDxVulnerabilitySource;
  ratings?: CycloneDxRating[];
  cwes?: number[];
  description?: string;
  advisories?: CycloneDxAdvisory[];
  references?: CycloneDxReference[];
  affects: CycloneDxAffect[];
  analysis: CycloneDxAnalysis;
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
  vulnerabilities?: CycloneDxVulnerability[];
}

// Module-level constant so both builders share the same tools array without
// duplicating the literal.
const SBOM_TOOLS_COMPONENTS: Array<{ name: string; version?: string; type: string }> = [
  { type: "application", name: "SASTBot", version: APP_VERSION },
  { type: "application", name: "cdxgen", version: "12.2" },
];

// ---------------------------------------------------------------------------
// Vulnerability helpers
// ---------------------------------------------------------------------------

/**
 * Infer the CycloneDX CVSS method string from a CVSS vector prefix.
 */
function cvssMethod(vector: string | null | undefined): string {
  if (!vector) return "other";
  if (vector.startsWith("CVSS:4.0")) return "CVSSv4";
  if (vector.startsWith("CVSS:3.1")) return "CVSSv31";
  if (vector.startsWith("CVSS:3.0")) return "CVSSv3";
  if (vector.startsWith("CVSS:2")) return "CVSSv2";
  // CVSS v2 vectors per FIRST.org spec carry no "CVSS:" prefix — they begin
  // with the AV metric: "AV:N/AC:L/Au:N/C:P/I:N/A:N". Detect that case.
  if (/^AV:[NALP]\/AC:[LMH]\/Au:[MSN]\//.test(vector)) return "CVSSv2";
  return "other";
}

/**
 * Map a dismissedStatus value to CycloneDX `analysis.state`.
 */
function analysisState(dismissedStatus: string): string {
  switch (dismissedStatus) {
    case "fixed": return "resolved";
    case "suppressed": return "not_affected";
    case "false_positive": return "false_positive";
    // pending, confirmed, planned → in_triage
    default: return "in_triage";
  }
}

/**
 * Infer a source name for a CVE/GHSA alias id prefix.
 */
function aliasSourceName(id: string): string {
  if (id.startsWith("GHSA-")) return "GitHub";
  if (id.startsWith("GO-")) return "Go";
  if (id.startsWith("RUSTSEC-")) return "RustSec";
  if (id.startsWith("PYSEC-")) return "PyPI";
  if (id.startsWith("DSA-")) return "Debian";
  return "Other";
}

/**
 * Build a CycloneDX 1.7 `vulnerabilities[]` entry from a ScaIssue row.
 *
 * `purlByKey` maps `"name@version"` (or `"name@"` for null version) to the
 * component's PURL (= bom-ref in these SBOM docs).
 */
function buildVulnerabilityFromIssue(
  // Minimal ScaIssue shape (both builders use the same Prisma select)
  issue: {
    id: string;
    osvId: string;
    latestCveId: string | null;
    source: string;
    latestCvssScore: number | null;
    latestCvssVector: string | null;
    latestSeverity: string;
    latestSummary: string | null;
    latestAliases: string[];
    dismissedStatus: string;
    dismissedReason: string | null;
    notes: string | null;
    firstSeenAt: Date;
    updatedAt: Date;
    packageName: string;
    latestPackageVersion: string | null;
  },
  purlByKey: Map<string, string>,
): CycloneDxVulnerability {
  const vuln: CycloneDxVulnerability = {
    "bom-ref": issue.latestCveId ?? issue.osvId,
    id: issue.latestCveId ?? issue.osvId,
    source: buildVulnSource(issue),
    affects: buildAffects(issue, purlByKey),
    analysis: buildAnalysis(issue),
  };

  // ratings[]
  const method = cvssMethod(issue.latestCvssVector);
  const sourceName = issue.source === "nvd" ? "NVD" : "OSV.dev";
  const rating: CycloneDxRating = {
    source: { name: sourceName },
    method,
  };
  if (issue.latestCvssScore != null) rating.score = issue.latestCvssScore;
  if (issue.latestSeverity && issue.latestSeverity !== "unknown") {
    rating.severity = issue.latestSeverity.toLowerCase();
  }
  if (issue.latestCvssVector) rating.vector = issue.latestCvssVector;
  // Only emit ratings when we have at least a score or severity.
  if (rating.score != null || rating.severity != null) {
    vuln.ratings = [rating];
    // Sort by (source.name, method, score)
    vuln.ratings.sort((a, b) => {
      const snCmp = a.source.name.localeCompare(b.source.name);
      if (snCmp !== 0) return snCmp;
      const mCmp = (a.method ?? "").localeCompare(b.method ?? "");
      if (mCmp !== 0) return mCmp;
      return (a.score ?? 0) - (b.score ?? 0);
    });
  }

  // description
  if (issue.latestSummary) vuln.description = issue.latestSummary;

  // advisories[] — deduplicate and sort by url
  const advisoryUrls = new Set<string>();
  if (issue.source === "nvd" && issue.latestCveId) {
    advisoryUrls.add(`https://nvd.nist.gov/vuln/detail/${issue.latestCveId}`);
  }
  // Always include OSV url when osvId is a real OSV id (starts with known prefix or is CVE id)
  advisoryUrls.add(`https://osv.dev/vulnerability/${issue.osvId}`);
  if (advisoryUrls.size > 0) {
    vuln.advisories = [...advisoryUrls].sort().map((url) => ({ url }));
  }

  // references[] — aliases sorted by id
  if (issue.latestAliases.length > 0) {
    vuln.references = [...issue.latestAliases]
      .sort()
      .map((alias) => ({
        id: alias,
        source: { name: aliasSourceName(alias) },
      }));
  }

  return vuln;
}

function buildVulnSource(issue: {
  source: string;
  latestCveId: string | null;
  osvId: string;
}): CycloneDxVulnerabilitySource {
  if (issue.source === "nvd") {
    const id = issue.latestCveId ?? issue.osvId;
    return {
      name: "NVD",
      url: `https://nvd.nist.gov/vuln/detail/${id}`,
    };
  }
  return {
    name: "OSV.dev",
    url: `https://osv.dev/vulnerability/${issue.osvId}`,
  };
}

function buildAffects(
  issue: { packageName: string; latestPackageVersion: string | null },
  purlByKey: Map<string, string>,
): CycloneDxAffect[] {
  const key = `${issue.packageName}@${issue.latestPackageVersion ?? ""}`;
  const purl = purlByKey.get(key);
  const affects: CycloneDxAffect[] = purl ? [{ ref: purl }] : [];
  // Sort by ref ascending
  affects.sort((a, b) => a.ref.localeCompare(b.ref));
  return affects;
}

function buildAnalysis(issue: {
  dismissedStatus: string;
  dismissedReason: string | null;
  notes: string | null;
  firstSeenAt: Date;
  updatedAt: Date;
}): CycloneDxAnalysis {
  const state = analysisState(issue.dismissedStatus);
  const analysis: CycloneDxAnalysis = {
    state,
    firstIssued: issue.firstSeenAt.toISOString(),
    lastUpdated: issue.updatedAt.toISOString(),
  };
  const detail = issue.notes ?? issue.dismissedReason;
  if (detail) analysis.detail = detail;
  if (issue.dismissedStatus === "planned") analysis.response = ["update"];
  return analysis;
}

/**
 * Shared ScaIssue select shape for both builders.
 */
const SCA_ISSUE_SELECT = {
  id: true,
  osvId: true,
  latestCveId: true,
  source: true,
  latestCvssScore: true,
  latestCvssVector: true,
  latestSeverity: true,
  latestSummary: true,
  latestAliases: true,
  dismissedStatus: true,
  dismissedReason: true,
  notes: true,
  firstSeenAt: true,
  updatedAt: true,
  packageName: true,
  latestPackageVersion: true,
  latestEolDate: true,
  latestFindingType: true,
} as const;

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
      repo: { select: { name: true, defaultBranch: true, includeDevDeps: true } },
      scope: { select: { path: true } },
    },
  });
  if (!run) return null;

  const rows = await prisma.sbomComponent.findMany({
    // Exclude dev-only components unless the repo opts them into scope — the
    // SBOM mirrors what's visible on the Components tab. npm-only signal; non-npm
    // components have isDevOnly=false and are always included.
    where: { scanRunId, ...(run.repo.includeDevDeps ? {} : { isDevOnly: false }) },
    // D1: full tiebreaker chain — (ecosystem, name, purl, id) — ensures a
    // deterministic row order even when two components share name + ecosystem.
    orderBy: [{ ecosystem: "asc" }, { name: "asc" }, { purl: "asc" }, { id: "asc" }],
  });
  if (rows.length === 0) return null;

  // Fetch sca_issues detected by THIS scan only (lastSeenScanRunId == scanRunId).
  // The per-scan SBOM is a snapshot of what this run found; issues from prior
  // scans that weren't re-detected this run belong on the scope-level SBOM, not
  // here. Includes dismissed issues per A1 — disposition is surfaced via
  // analysis.state, not used as a filter.
  const scaIssues = await prisma.scaIssue.findMany({
    where: { lastSeenScanRunId: scanRunId },
    select: SCA_ISSUE_SELECT,
  });

  // Build component key → purl side-map for A3 linkage.
  const purlByKey = new Map<string, string>();
  for (const r of rows) {
    purlByKey.set(`${r.name}@${r.version ?? ""}`, r.purl);
  }

  // Build EOL map: "name@version" → issue (only EOL-class issues).
  const eolByKey = new Map<string, typeof scaIssues[number]>();
  for (const issue of scaIssues) {
    const isEol = issue.latestEolDate != null
      || issue.latestFindingType === "eol"
      || issue.latestFindingType === "deprecated";
    if (isEol) {
      eolByKey.set(`${issue.packageName}@${issue.latestPackageVersion ?? ""}`, issue);
    }
  }

  // D2 comparator: sort occurrences by (path asc, line asc nulls-first).
  function sortOccurrences(arr: ComponentOccurrence[]): ComponentOccurrence[] {
    return [...arr].sort((a, b) => {
      const pathCmp = a.path.localeCompare(b.path);
      if (pathCmp !== 0) return pathCmp;
      return (a.line ?? -Infinity) - (b.line ?? -Infinity);
    });
  }

  const now = new Date();
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
    // A5: EOL / lifecycle properties — appended before D4 sort.
    const eolIssue = eolByKey.get(`${r.name}@${r.version ?? ""}`);
    if (eolIssue) {
      if (eolIssue.latestEolDate) {
        properties.push({
          name: "sastbot:eol_date",
          value: eolIssue.latestEolDate.toISOString().slice(0, 10),
        });
        properties.push({
          name: "sastbot:lifecycle_state",
          value: eolIssue.latestEolDate < now ? "eol" : "active",
        });
      } else if (eolIssue.latestFindingType === "deprecated") {
        properties.push({ name: "sastbot:lifecycle_state", value: "deprecated" });
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

  // Build vulnerabilities[] — all sca_issues for this scope, sorted by id.
  const vulnerabilities: CycloneDxVulnerability[] = scaIssues
    .map((issue) => buildVulnerabilityFromIssue(issue, purlByKey))
    .sort((a, b) => a.id.localeCompare(b.id));

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
    ...(vulnerabilities.length > 0 ? { vulnerabilities } : {}),
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
      repo: { select: { name: true, defaultBranch: true, includeDevDeps: true } },
    },
  });
  if (!scope) return null;

  const scopeComponents = await prisma.scopeComponent.findMany({
    // Exclude dev-only components unless the repo opts them into scope — the
    // SBOM mirrors what's visible on the Components tab. npm-only signal; non-npm
    // components have isDevOnly=false and are always included.
    where: { scopeId, dismissedStatus: "active", ...(scope.repo.includeDevDeps ? {} : { isDevOnly: false }) },
    // D1: full tiebreaker chain — (ecosystem, name, purl, id).
    orderBy: [{ ecosystem: "asc" }, { name: "asc" }, { purl: "asc" }, { id: "asc" }],
  });
  if (scopeComponents.length === 0) return null;

  // Fetch names of excluded (ignored/not_found) components so their
  // vulnerabilities can be filtered out of the scope-level SBOM export.
  // The components themselves are already excluded (query above filters
  // dismissedStatus = 'active'). Only the sca_issues need explicit filtering.
  const excludedComponentRows = await prisma.scopeComponent.findMany({
    where: { scopeId, dismissedStatus: { in: ["ignored", "not_found"] } },
    select: { name: true },
  });
  const excludedComponentNames = new Set(excludedComponentRows.map((r) => r.name));

  // Fetch all sca_issues for this scope.
  let scaIssues = await prisma.scaIssue.findMany({
    where: { scopeId },
    select: SCA_ISSUE_SELECT,
  });

  // Filter out issues for ignored/not_found components.
  if (excludedComponentNames.size > 0) {
    scaIssues = scaIssues.filter((i) => !excludedComponentNames.has(i.packageName));
  }

  // Build component key → purl side-map for A3 linkage (scope-level).
  const purlByKey = new Map<string, string>();
  for (const sc of scopeComponents) {
    purlByKey.set(`${sc.name}@${sc.version ?? ""}`, sc.purl);
  }

  // Build EOL map: "name@version" → issue (only EOL-class issues).
  const now = new Date();
  const eolByKey = new Map<string, typeof scaIssues[number]>();
  for (const issue of scaIssues) {
    const isEol = issue.latestEolDate != null
      || issue.latestFindingType === "eol"
      || issue.latestFindingType === "deprecated";
    if (isEol) {
      eolByKey.set(`${issue.packageName}@${issue.latestPackageVersion ?? ""}`, issue);
    }
  }

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
    // A5: EOL / lifecycle properties — appended before D4 sort.
    const eolIssue = eolByKey.get(`${sc.name}@${sc.version ?? ""}`);
    if (eolIssue) {
      if (eolIssue.latestEolDate) {
        properties.push({
          name: "sastbot:eol_date",
          value: eolIssue.latestEolDate.toISOString().slice(0, 10),
        });
        properties.push({
          name: "sastbot:lifecycle_state",
          value: eolIssue.latestEolDate < now ? "eol" : "active",
        });
      } else if (eolIssue.latestFindingType === "deprecated") {
        properties.push({ name: "sastbot:lifecycle_state", value: "deprecated" });
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

  // Build vulnerabilities[] — all sca_issues for this scope, sorted by id.
  const vulnerabilities: CycloneDxVulnerability[] = scaIssues
    .map((issue) => buildVulnerabilityFromIssue(issue, purlByKey))
    .sort((a, b) => a.id.localeCompare(b.id));

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
    ...(vulnerabilities.length > 0 ? { vulnerabilities } : {}),
  };
}

// ---------------------------------------------------------------------------
// E1: Build the canonical CycloneDX 1.7 document from the in-memory
// post-augmentation component list, WITHOUT touching the DB.
// ---------------------------------------------------------------------------

interface LlmEvidenceInput {
  path: string;
  excerpt: string | null;
  llmReason: string;
}

interface IdentityMetadata {
  componentRoot: string | null;
  evidence: Array<{ path: string; line: number | null }>;
}

/**
 * Build a CycloneDX 1.7 document from the in-memory post-augmentation
 * component list (the worker's `finalComponents`), WITHOUT touching the DB.
 *
 * Output includes `sastbot:*` properties that round-trip every typed column
 * so `ingestSbomFromArtifact` can reconstruct the DB rows from the file.
 * Only "manifest" and "llm_augmentation" appear as discoveryMethod at this
 * point — "recheck_recovery" is scope-level and never enters this path.
 */
export async function buildAugmentationSbom(input: {
  scanRunId: string;
  scopeId: string;
  scopePath: string;
  scanDir: string;
  components: CdxComponent[];
  sbomEvidenceMap: Map<string, LlmEvidenceInput>;
  sbomCpeMap: Map<string, string>;
  sbomIdentityMap: Map<string, IdentityMetadata>;
  startedAt?: Date | null;
  finishedAt?: Date | null;
  repoName: string;
  repoDefaultBranch: string | null;
}): Promise<CuratedSbomDoc> {
  const {
    scanRunId, scopePath, scanDir,
    components: rawComponents,
    sbomEvidenceMap, sbomCpeMap, sbomIdentityMap,
    startedAt, finishedAt,
    repoName, repoDefaultBranch,
  } = input;

  // D2 comparator: sort occurrences by (path asc, line asc nulls-first).
  function sortOccurrences(arr: ComponentOccurrence[]): ComponentOccurrence[] {
    return [...arr].sort((a, b) => {
      const pathCmp = a.path.localeCompare(b.path);
      if (pathCmp !== 0) return pathCmp;
      return (a.line ?? -Infinity) - (b.line ?? -Infinity);
    });
  }

  // Dedup by purl (same logic as persistAugmentedComponents).
  const unique = new Map<string, CdxComponent>();
  for (const c of rawComponents) {
    const purl = c.purl ?? `pkg:generic/${encodeURIComponent(c.name ?? "unknown")}${c.version ? `@${encodeURIComponent(c.version)}` : ""}`;
    if (!unique.has(purl)) unique.set(purl, { ...c, purl });
  }

  const lockfileCache = new Map<string, string[] | null>();
  const scopeIndex = scanDir ? new ScopeFileIndex(scanDir, scopePath) : undefined;
  const cdxComponents: CycloneDxComponent[] = [];

  for (const c of unique.values()) {
    const ecosystem = extractEcosystem(c.purl);
    const canonicalName = canonicalPackageName(c, ecosystem);
    const evidence = sbomEvidenceMap.get(canonicalName) ?? null;
    const identity = sbomIdentityMap.get(canonicalName) ?? null;
    const cpe = sbomCpeMap.get(canonicalName);
    const sr = extractManifestFile(c, scanDir);
    const manifestFile = sr ? toRepoRelative(scopePath, sr) : null;

    // Occurrences: same logic as persistAugmentedComponents.
    const occurrences = extractOccurrences(c, evidence?.path ?? null, false, scopePath);
    await resolveManifestLines(occurrences, canonicalName, scanDir || null, scopePath, lockfileCache, scopeIndex);

    // Identity-shaped evidence (same priority chain as persistAugmentedComponents).
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

    const discoveryMethod = (c as CdxComponent & { discoveryMethod?: string }).discoveryMethod ?? "manifest";
    const isDevOnly = extractIsDevOnly(c);
    const licenses = extractLicenses(c.licenses);

    // Build CycloneDX component.
    const cdxComp: CycloneDxComponent = {
      type: c.type ?? "library",
      name: canonicalName,
      purl: c.purl!,
      "bom-ref": c.purl!,
    };
    if (c.version) cdxComp.version = c.version;
    if (c.scope) cdxComp.scope = c.scope;

    // D3: sort licenses lexicographically.
    if (licenses.length > 0) {
      cdxComp.licenses = [...licenses].sort().map((id) => ({ license: { id } }));
    }

    // Evidence: identity block (manifest or componentRoot) + occurrences.
    const cdxEvidence: CycloneDxEvidence = {};
    if (identity?.componentRoot) {
      cdxEvidence.identity = [{
        field: "purl",
        concludedValue: identity.componentRoot,
        methods: [{ technique: "filename", value: identity.componentRoot, confidence: 0.9 }],
        confidence: 0.9,
      }];
    } else if (manifestFile) {
      cdxEvidence.identity = [{
        field: "purl",
        concludedValue: manifestFile,
        methods: [{ technique: "manifest-analysis", value: manifestFile, confidence: 0.8 }],
        confidence: 0.8,
      }];
    }
    const sortedOccurrences = sortOccurrences(occurrences);
    if (sortedOccurrences.length > 0) {
      cdxEvidence.occurrences = sortedOccurrences.map((o) => ({
        location: o.line != null ? `${o.path}#${o.line}` : o.path,
      }));
    }
    if (cdxEvidence.identity || cdxEvidence.occurrences) cdxComp.evidence = cdxEvidence;

    // Properties — all the sastbot:* round-trip properties.
    const properties: Array<{ name: string; value: string }> = [];

    properties.push({ name: "sastbot:discovery_method", value: discoveryMethod });
    if (identity?.componentRoot) {
      properties.push({ name: "sastbot:component_root", value: identity.componentRoot });
    }
    if (cpe) {
      properties.push({ name: "sastbot:cpe", value: cpe });
    }
    if (ecosystem) {
      properties.push({ name: "sastbot:ecosystem", value: ecosystem });
    }
    if (identityEvidence && identityEvidence.length > 0) {
      properties.push({ name: "sastbot:identity_evidence", value: JSON.stringify(identityEvidence) });
    }
    if (evidence) {
      properties.push({ name: "sastbot:llm_evidence", value: JSON.stringify({
        path: evidence.path,
        excerpt: evidence.excerpt,
        llmReason: evidence.llmReason,
      })});
    }
    if (manifestFile) {
      properties.push({ name: "sastbot:manifest_file", value: manifestFile });
    }
    if (occurrences.length > 0) {
      properties.push({ name: "sastbot:occurrences", value: JSON.stringify(occurrences) });
    }
    if (c.scope) {
      properties.push({ name: "sastbot:scope", value: c.scope });
    }
    if (c.type) {
      properties.push({ name: "sastbot:component_type", value: c.type });
    }
    if (isDevOnly) {
      properties.push({ name: "cdx:npm:package:development", value: "true" });
    }

    // D4: sort properties lexicographically.
    properties.sort((a, b) => {
      const nameCmp = a.name.localeCompare(b.name);
      return nameCmp !== 0 ? nameCmp : a.value.localeCompare(b.value);
    });
    if (properties.length > 0) cdxComp.properties = properties;

    cdxComponents.push(cdxComp);
  }

  // Sort components by (ecosystem, name, purl) — D1 tiebreaker.
  cdxComponents.sort((a, b) => {
    const ecoA = a.properties?.find((p) => p.name === "sastbot:ecosystem")?.value ?? "";
    const ecoB = b.properties?.find((p) => p.name === "sastbot:ecosystem")?.value ?? "";
    const ecoCmp = ecoA.localeCompare(ecoB);
    if (ecoCmp !== 0) return ecoCmp;
    const nameCmp = a.name.localeCompare(b.name);
    if (nameCmp !== 0) return nameCmp;
    return a.purl.localeCompare(b.purl);
  });

  const timestamp = (finishedAt ?? startedAt ?? new Date()).toISOString();

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.7",
    serialNumber: `urn:uuid:${scanRunId}`,
    version: 1,
    metadata: {
      timestamp,
      tools: { components: SBOM_TOOLS_COMPONENTS },
      component: {
        type: "application",
        name: `${repoName}${scopePath === "/" ? "" : scopePath}`,
        version: repoDefaultBranch ?? undefined,
      },
    },
    components: cdxComponents,
  };
}

