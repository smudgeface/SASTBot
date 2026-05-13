/**
 * NVD CVE API v2.0 client.
 *
 * Used as a fallback vulnerability source for `generic` ecosystem components
 * (vendored C/C++ libs, etc.) where OSV.dev has essentially no coverage.
 *
 * Rate limits:
 *   - Without API key:  5 req / 30 sec
 *   - With API key:    50 req / 30 sec
 *
 * Query strategy per component:
 *   - If component has a `cpe` field → query `?cpeName=<cpe>&isVulnerable`
 *   - Else → query `?keywordSearch=<name>` and post-filter by version
 */

import type { PrismaClient, SbomComponent, ScanFinding } from "@prisma/client";
import { pino } from "pino";

import { loadConfig } from "../config.js";
import type { Severity } from "../schemas.js";
import { upsertScaIssueFromDetection } from "./issueService.js";
import { getOrCreateSettings } from "./settingsService.js";
import { decodeCredential } from "./credentialService.js";

const logger = pino({ level: loadConfig().logLevel, name: "nvdService" });

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// ---------------------------------------------------------------------------
// NVD CVE API v2.0 response types (subset we care about)
// ---------------------------------------------------------------------------

interface NvdCvssV2 {
  cvssData: {
    baseScore: number;
    vectorString: string;
  };
  baseSeverity?: string;
}

interface NvdCvssV3 {
  cvssData: {
    baseScore: number;
    vectorString: string;
    baseSeverity: string;
  };
}

interface NvdMetrics {
  cvssMetricV2?: NvdCvssV2[];
  cvssMetricV30?: NvdCvssV3[];
  cvssMetricV31?: NvdCvssV3[];
}

interface NvdCpeMatch {
  vulnerable: boolean;
  criteria: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndIncluding?: string;
  versionEndExcluding?: string;
}

interface NvdNode {
  operator: string;
  negate?: boolean;
  cpeMatch?: NvdCpeMatch[];
  children?: NvdNode[];
}

interface NvdConfiguration {
  nodes: NvdNode[];
}

interface NvdDescription {
  lang: string;
  value: string;
}

interface NvdReference {
  url: string;
  source?: string;
}

interface NvdCve {
  id: string;
  published: string;
  lastModified: string;
  vulnStatus?: string;
  descriptions: NvdDescription[];
  metrics?: NvdMetrics;
  configurations?: NvdConfiguration[];
  references?: NvdReference[];
}

interface NvdVulnerability {
  cve: NvdCve;
}

interface NvdResponse {
  totalResults: number;
  vulnerabilities?: NvdVulnerability[];
}

// ---------------------------------------------------------------------------
// Throttle: token bucket
// ---------------------------------------------------------------------------

interface TokenBucket {
  tokens: number;
  maxTokens: number;
  refillRate: number; // tokens per ms
  lastRefill: number; // Date.now() timestamp
}

function createBucket(requestsPerWindow: number, windowMs: number): TokenBucket {
  return {
    tokens: requestsPerWindow,
    maxTokens: requestsPerWindow,
    refillRate: requestsPerWindow / windowMs,
    lastRefill: Date.now(),
  };
}

async function acquireToken(bucket: TokenBucket): Promise<void> {
  const now = Date.now();
  const elapsed = now - bucket.lastRefill;
  bucket.tokens = Math.min(bucket.maxTokens, bucket.tokens + elapsed * bucket.refillRate);
  bucket.lastRefill = now;

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return;
  }
  // Need to wait until we have a token.
  const waitMs = Math.ceil((1 - bucket.tokens) / bucket.refillRate);
  logger.debug({ waitMs }, "[nvdService] throttling NVD request");
  await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
  bucket.tokens = 0;
  bucket.lastRefill = Date.now();
}

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

function pickBestCvss(metrics: NvdMetrics | undefined): {
  score: number | null;
  severity: Severity;
  vector: string | null;
} {
  if (!metrics) return { score: null, severity: "unknown", vector: null };

  // Prefer V3.1 > V3.0 > V2
  const v31 = metrics.cvssMetricV31?.[0];
  if (v31) {
    const score = v31.cvssData.baseScore;
    return {
      score,
      severity: cvssScoreToSeverity(score),
      vector: v31.cvssData.vectorString,
    };
  }
  const v30 = metrics.cvssMetricV30?.[0];
  if (v30) {
    const score = v30.cvssData.baseScore;
    return {
      score,
      severity: cvssScoreToSeverity(score),
      vector: v30.cvssData.vectorString,
    };
  }
  const v2 = metrics.cvssMetricV2?.[0];
  if (v2) {
    const score = v2.cvssData.baseScore;
    return {
      score,
      severity: cvssScoreToSeverity(score),
      vector: v2.cvssData.vectorString,
    };
  }
  return { score: null, severity: "unknown", vector: null };
}

function cvssScoreToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

function firstEnglishDesc(descriptions: NvdDescription[]): string | null {
  const en = descriptions.find((d) => d.lang === "en");
  return en?.value ?? descriptions[0]?.value ?? null;
}

// ---------------------------------------------------------------------------
// Version matching helpers (for keyword-search fallback)
// ---------------------------------------------------------------------------

/**
 * Return a usable version string, or null when the component has no
 * extractable version. Treat "", "unknown", and "*" as no-version.
 * Querying NVD without a version produces noise — keyword search returns
 * every CVE that mentions the name, and there is nothing meaningful to
 * filter against.
 */
function sanitizeVersion(version: string | null | undefined): string | null {
  if (!version) return null;
  const trimmed = version.trim();
  if (trimmed === "" || trimmed === "*") return null;
  if (trimmed.toLowerCase() === "unknown") return null;
  return trimmed;
}

/**
 * Substitute a concrete version into the version segment of a CPE 2.3
 * string when that segment is currently a wildcard. Returns the original
 * CPE unchanged when it already carries a concrete version, or null when
 * the CPE doesn't look like a valid CPE 2.3 string.
 *
 * NVD's `cpeName=` parameter requires an exact match against the CPE
 * dictionary. A CPE with `*` in the version slot matches nothing — the
 * LLM emits these when it knows the vendor/product but not the version.
 * Re-attaching the component's version makes the precise path usable.
 */
function injectCpeVersion(cpe: string, version: string): string | null {
  const parts = cpe.split(":");
  if (parts.length < 6) return null;
  if (parts[0] !== "cpe" || parts[1] !== "2.3") return null;
  if (parts[5] && parts[5] !== "*" && parts[5] !== "") return cpe;
  parts[5] = version;
  return parts.join(":");
}

/**
 * Normalize a version string to a comparable array of numbers/strings.
 * E.g. "1.2.11" → [1, 2, 11].
 */
function parseVersion(v: string): (number | string)[] {
  return v.split(/[.\-_]/).map((p) => {
    const n = parseInt(p, 10);
    return Number.isNaN(n) ? p : n;
  });
}

function compareVersions(a: string, b: string): number {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const av = pa[i] ?? 0;
    const bv = pb[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  return 0;
}

/**
 * Collect all vulnerable CPE matches from a CVE's configuration tree.
 */
function collectVulnerableCpeMatches(cve: NvdCve): NvdCpeMatch[] {
  const results: NvdCpeMatch[] = [];
  function walk(nodes: NvdNode[]): void {
    for (const node of nodes) {
      for (const m of node.cpeMatch ?? []) {
        if (m.vulnerable) results.push(m);
      }
      if (node.children) walk(node.children);
    }
  }
  if (cve.configurations) {
    for (const cfg of cve.configurations) {
      walk(cfg.nodes);
    }
  }
  return results;
}

/**
 * Return true if the given version falls within the range specified by
 * a CPE match entry. When no version bounds are present the match is
 * treated as "any version".
 */
function versionMatchesCpe(version: string, match: NvdCpeMatch): boolean {
  const { versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding } = match;
  if (!versionStartIncluding && !versionStartExcluding && !versionEndIncluding && !versionEndExcluding) {
    // No range bounds — treat as any version (open-ended advisory).
    return true;
  }
  if (versionStartIncluding && compareVersions(version, versionStartIncluding) < 0) return false;
  if (versionStartExcluding && compareVersions(version, versionStartExcluding) <= 0) return false;
  if (versionEndIncluding && compareVersions(version, versionEndIncluding) > 0) return false;
  if (versionEndExcluding && compareVersions(version, versionEndExcluding) >= 0) return false;
  return true;
}

/**
 * Determine if a CVE affects the given component version by inspecting the
 * CPE match entries in its configurations.
 */
function cveAffectsVersion(cve: NvdCve, version: string | null): boolean {
  if (!version) return true; // Can't filter without a version — be conservative.
  const matches = collectVulnerableCpeMatches(cve);
  if (matches.length === 0) return true; // No config data → assume affected.
  return matches.some((m) => versionMatchesCpe(version, m));
}

// ---------------------------------------------------------------------------
// NVD API query (single call with one retry on transient error)
// ---------------------------------------------------------------------------

async function queryNvd(
  params: Record<string, string>,
  apiKey: string | null,
  bucket: TokenBucket,
): Promise<NvdVulnerability[]> {
  await acquireToken(bucket);

  const url = new URL(NVD_BASE_URL);
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, v);
  }

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) headers["apiKey"] = apiKey;

  const doFetch = async (): Promise<Response> =>
    fetch(url.toString(), { headers });

  let res = await doFetch();
  if (res.status === 503 || res.status === 429) {
    // Single retry after 2 seconds.
    await new Promise<void>((r) => setTimeout(r, 2000));
    res = await doFetch();
  }

  if (!res.ok) {
    logger.warn({ status: res.status, url: url.toString() }, "[nvdService] NVD query failed");
    return [];
  }

  let data: NvdResponse;
  try {
    data = (await res.json()) as NvdResponse;
  } catch {
    logger.warn({ url: url.toString() }, "[nvdService] NVD response JSON parse error");
    return [];
  }
  return data.vulnerabilities ?? [];
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/**
 * Look up NVD CVEs for a batch of `generic` ecosystem SBOM components.
 * Mirrors the calling convention of osvService.queryAndPersistFindings so the
 * worker can call both symmetrically, but the NVD pass is always-on for
 * generic components (no dev-dep filtering — C/C++ vendored libs are never
 * dev-only in the OSV/NVD sense).
 *
 * For each component:
 *   - If it has a CPE → CPE name query (precise).
 *   - Else → keyword search on the component name, post-filtered by version.
 *
 * Persists ScaIssue + ScanFinding rows with source="nvd".
 * Returns all newly created ScanFinding rows for this scan run.
 */
export async function queryAndPersistNvdFindings(
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  components: SbomComponent[],
  client: PrismaClient,
  onProgress?: (done: number, total: number) => void,
): Promise<ScanFinding[]> {
  // Only generic ecosystem — the whole reason this service exists.
  const genericComponents = components.filter(
    (c) => c.ecosystem === "generic" || c.ecosystem === null,
  ).filter((c) => c.name);

  if (genericComponents.length === 0) {
    logger.info({ scanRunId }, "[nvdService] no generic components — skipping NVD phase");
    return [];
  }

  // Resolve API key + choose rate limit tier.
  let apiKey: string | null = null;
  try {
    const settings = await getOrCreateSettings(orgId);
    if (settings.nvdCredentialId) {
      const decoded = await decodeCredential(settings.nvdCredentialId, client);
      if (decoded.kind === "nvd_api_key") apiKey = decoded.value;
    }
  } catch (err) {
    logger.warn({ err }, "[nvdService] could not load NVD credential — proceeding without key");
  }

  const requestsPerWindow = apiKey ? 50 : 5;
  const bucket = createBucket(requestsPerWindow, 30_000);

  logger.info(
    { scanRunId, count: genericComponents.length, withKey: !!apiKey },
    "[nvdService] querying NVD for generic components",
  );

  const findings: ScanFinding[] = [];
  const seen = new Set<string>(); // "componentId:cveId"
  let skippedNoVersion = 0;

  for (let i = 0; i < genericComponents.length; i++) {
    const component = genericComponents[i];
    onProgress?.(i, genericComponents.length);

    // Version gate: without a usable version we can't determine which CVEs
    // affect this component. Querying anyway either pulls every CVE that
    // mentions the name (keyword path) or matches nothing (wildcard CPE).
    // Both are noise. The component still lives in the SBOM — just no NVD lookup.
    const version = sanitizeVersion(component.version);
    if (!version) {
      skippedNoVersion += 1;
      logger.info(
        { name: component.name, rawVersion: component.version },
        "[nvdService] skipping component: no usable version",
      );
      continue;
    }

    let vulns: NvdVulnerability[] = [];
    try {
      const rawCpe = (component as SbomComponent & { cpe?: string | null }).cpe;
      const cpeWithVersion = rawCpe ? injectCpeVersion(rawCpe, version) : null;

      if (cpeWithVersion) {
        // Precise CPE match path — NVD returns only affecting CVEs when the
        // CPE matches a dictionary entry.
        vulns = await queryNvd({ cpeName: cpeWithVersion, isVulnerable: "" }, apiKey, bucket);
      }

      if (vulns.length === 0) {
        // Fallback path: either no CPE was emitted, or the CPE didn't match
        // the NVD dictionary (the most common cause of a 404 here). Run the
        // keyword search and post-filter by version so we still surface CVEs
        // for components whose CPE the LLM didn't know.
        const kwResults = await queryNvd(
          { keywordSearch: component.name },
          apiKey,
          bucket,
        );
        vulns = kwResults.filter((v) => cveAffectsVersion(v.cve, version));
      }
    } catch (err) {
      logger.warn({ err, name: component.name }, "[nvdService] NVD request failed — skipping component");
      continue;
    }

    for (const { cve } of vulns) {
      const key = `${component.id}:${cve.id}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const summary = firstEnglishDesc(cve.descriptions);
      const { score, severity, vector } = pickBestCvss(cve.metrics);
      const refs = (cve.references ?? []).map((r) => r.url);

      const { issue } = await upsertScaIssueFromDetection(
        client,
        scanRunId,
        scopeId,
        orgId,
        {
          name: component.name,
          version: component.version,
          ecosystem: component.ecosystem,
          scope: component.scope,
          isDevOnly: component.isDevOnly,
        },
        {
          osvId: cve.id, // re-uses osvId column for CVE IDs — globally unique
          cveId: cve.id,
          findingType: "cve",
          severity,
          cvssScore: score,
          cvssVector: vector,
          summary,
          aliases: [],
          activelyExploited: false,
          eolDate: null,
          detailJson: { id: cve.id, published: cve.published, refs },
          source: "nvd",
        },
      );

      const finding = await (client as PrismaClient).scanFinding.create({
        data: {
          scanRunId,
          componentId: component.id,
          issueId: issue.id,
          findingType: "cve",
          osvId: cve.id,
          cveId: cve.id,
          severity,
          cvssScore: score,
          cvssVector: vector,
          summary,
          aliases: [],
          activelyExploited: false,
        },
      });
      findings.push(finding);
    }

    if (vulns.length > 0) {
      logger.info(
        { name: component.name, version: component.version, cveCount: vulns.length },
        "[nvdService] NVD CVEs found",
      );
    }
  }

  onProgress?.(genericComponents.length, genericComponents.length);
  logger.info(
    { scanRunId, findings: findings.length, skippedNoVersion },
    "[nvdService] NVD findings persisted",
  );
  return findings;
}
