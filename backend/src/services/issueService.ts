/**
 * Upsert helpers used by the worker to create/advance Issue rows from scan detections.
 * Issues are the stable identity unit (one per scope+fingerprint or scope+pkg+osvId);
 * detections (SastFinding / ScanFinding) are the per-scan evidence rows.
 */
import type { Prisma, PrismaClient, SastIssue, ScaIssue } from "@prisma/client";

type Tx = PrismaClient | Prisma.TransactionClient;
type Db = PrismaClient;

/** Read the OSV detail JSON to detect whether a patched version exists. */
function computeHasFix(detailJson: unknown): boolean {
  if (!detailJson || typeof detailJson !== "object") return false;
  const vuln = detailJson as Record<string, unknown>;
  const affected = vuln.affected as Array<{
    ranges?: Array<{ events?: Array<Record<string, unknown>> }>;
  }> | undefined;
  if (!Array.isArray(affected)) return false;
  return affected.some((a) =>
    a.ranges?.some((r) =>
      r.events?.some((e) => "fixed" in e && e.fixed !== undefined),
    ),
  );
}

// ---------------------------------------------------------------------------
// SAST
// ---------------------------------------------------------------------------

export interface SastDetectionInput {
  fingerprint: string;
  ruleId: string;
  ruleName: string | null;
  ruleMessage: string | null;
  severity: string;
  cweIds: string[];
  filePath: string;
  startLine: number;
  /** Inclusive last line of the problem region. null for absence-style
   *  records (no specific code site) or for old data that pre-dates M6k. */
  endLine: number | null;
  snippet: string | null;
}

export async function upsertSastIssueFromDetection(
  client: Tx,
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  detection: SastDetectionInput,
): Promise<{ issue: SastIssue; isNew: boolean }> {
  const db = client as Db;
  const { fingerprint } = detection;

  const existing = await db.sastIssue.findUnique({
    where: { uq_sast_issues_scope_fingerprint: { scopeId, fingerprint } },
    select: { id: true },
  });

  const issue = await db.sastIssue.upsert({
    where: { uq_sast_issues_scope_fingerprint: { scopeId, fingerprint } },
    create: {
      orgId,
      scopeId,
      fingerprint,
      triageStatus: "pending",
      latestRuleId: detection.ruleId,
      latestRuleName: detection.ruleName,
      latestRuleMessage: detection.ruleMessage,
      latestSeverity: detection.severity,
      latestCweIds: detection.cweIds,
      latestFilePath: detection.filePath,
      latestStartLine: detection.startLine,
      latestEndLine: detection.endLine,
      latestSnippet: detection.snippet,
      firstSeenScanRunId: scanRunId,
      lastSeenScanRunId: scanRunId,
    },
    update: {
      lastSeenAt: new Date(),
      lastSeenScanRunId: scanRunId,
      latestRuleId: detection.ruleId,
      latestRuleName: detection.ruleName,
      latestRuleMessage: detection.ruleMessage,
      latestSeverity: detection.severity,
      latestCweIds: detection.cweIds,
      latestFilePath: detection.filePath,
      latestStartLine: detection.startLine,
      latestEndLine: detection.endLine,
      latestSnippet: detection.snippet,
    },
  });

  return { issue, isNew: existing === null };
}

// ---------------------------------------------------------------------------
// SCA
// ---------------------------------------------------------------------------

export interface ScaComponentInfo {
  name: string;
  version: string | null;
  ecosystem: string | null;
  scope: string | null;
  isDevOnly: boolean;
}

export interface ScaDetectionInput {
  osvId: string;
  cveId: string | null;
  findingType: string;
  severity: string;
  cvssScore: number | null;
  cvssVector: string | null;
  summary: string | null;
  aliases: string[];
  activelyExploited: boolean;
  eolDate: Date | null;
  detailJson?: unknown;
  manifestFile?: string | null;
  manifestLine?: number | null;
  manifestSnippet?: string | null;
  /** Provenance: "osv" (default) or "nvd". */
  source?: string;
}

export async function upsertScaIssueFromDetection(
  client: Tx,
  scanRunId: string,
  scopeId: string,
  orgId: string | null,
  component: ScaComponentInfo,
  detection: ScaDetectionInput,
  /** Optional: set of component names in this scope that are currently ignored.
   *  When a new issue's package matches an ignored component, it auto-lands as
   *  suppressed/component_ignored (sticky cascade). Pass from the worker via a
   *  batched lookup at the start of the OSV/NVD phase. */
  ignoredComponentNames?: Set<string>,
): Promise<{ issue: ScaIssue; isNew: boolean }> {
  const db = client as Db;
  const { name: packageName, version, ecosystem, scope: componentScope, isDevOnly } = component;
  const { osvId } = detection;
  const hasFix = computeHasFix(detection.detailJson);

  const existing = await db.scaIssue.findUnique({
    where: { uq_sca_issues_scope_pkg_osv: { scopeId, packageName, osvId } },
    select: { id: true },
  });

  const latestFields = {
    latestPackageVersion: version,
    latestEcosystem: ecosystem,
    latestComponentScope: componentScope,
    latestIsDevOnly: isDevOnly,
    latestFindingType: detection.findingType,
    latestCveId: detection.cveId,
    latestSeverity: detection.severity,
    latestCvssScore: detection.cvssScore,
    latestCvssVector: detection.cvssVector,
    latestSummary: detection.summary,
    latestAliases: detection.aliases,
    latestActivelyExploited: detection.activelyExploited,
    latestEolDate: detection.eolDate,
    latestHasFix: hasFix,
    latestManifestFile: detection.manifestFile ?? null,
    latestManifestLine: detection.manifestLine ?? null,
    latestManifestSnippet: detection.manifestSnippet ?? null,
  };

  // If the component is ignored by the operator, new issues auto-land as
  // suppressed. Only applies on CREATE — don't override existing triage.
  const isComponentIgnored = ignoredComponentNames?.has(packageName) ?? false;
  const createDismissedStatus = isComponentIgnored ? "suppressed" : "pending";
  const createDismissedReason = isComponentIgnored ? "component_ignored" : null;
  const createDismissedAt = isComponentIgnored ? new Date() : null;

  const issue = await db.scaIssue.upsert({
    where: { uq_sca_issues_scope_pkg_osv: { scopeId, packageName, osvId } },
    create: {
      orgId,
      scopeId,
      packageName,
      osvId,
      dismissedStatus: createDismissedStatus,
      dismissedReason: createDismissedReason,
      dismissedAt: createDismissedAt,
      source: detection.source ?? "osv",
      ...latestFields,
      firstSeenScanRunId: scanRunId,
      lastSeenScanRunId: scanRunId,
    },
    update: {
      lastSeenAt: new Date(),
      lastSeenScanRunId: scanRunId,
      source: detection.source ?? "osv",
      ...latestFields,
    },
  });

  return { issue, isNew: existing === null };
}
