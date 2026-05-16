import type {
  AppSettings,
  Credential,
  JiraTicket,
  Repo,
  SastFinding,
  SastIssue,
  SbomComponent,
  ScaIssue,
  ScanFinding,
  ScanRun,
  ScanScope,
  User,
} from "@prisma/client";

import type {
  AppSettingsOut,
  CredentialOut,
  CredentialReferences,
  FindingType,
  JiraTicketOut,
  RepoOut,
  SastFindingOut,
  SastIssueOut,
  SastSeverity,
  SastTriageStatus,
  SbomComponentOut,
  ScaDismissedStatus,
  ScaIssueOut,
  ScanFindingOut,
  ScanRunOut,
  ScanScopeOut,
  ScanWarning,
  Severity,
  UserOut,
} from "../schemas.js";

type AnalysisType = "sca" | "sast";
type RepoProtocol = "ssh" | "https";
type ScanStatus = "pending" | "running" | "success" | "failed" | "cancelled";
type ScanTriggeredBy = "user" | "api" | "schedule";
type ScanPhase = NonNullable<ScanRunOut["current_phase"]>;

const ALLOWED_PHASES: ReadonlyArray<ScanPhase> = [
  "cloning", "cdxgen", "osv", "eol",
  "llm_detection", "llm_recheck", "sca_summaries", "finalizing",
];

function toPhase(value: string | null): ScanPhase | null {
  if (value === null) return null;
  return (ALLOWED_PHASES as ReadonlyArray<string>).includes(value)
    ? (value as ScanPhase)
    : null;
}

const ALLOWED_PROTOCOLS: ReadonlyArray<RepoProtocol> = ["ssh", "https"];
const ALLOWED_ANALYSIS: ReadonlyArray<AnalysisType> = ["sca", "sast"];
const ALLOWED_STATUS: ReadonlyArray<ScanStatus> = [
  "pending",
  "running",
  "success",
  "failed",
  "cancelled",
];
const ALLOWED_TRIGGERED: ReadonlyArray<ScanTriggeredBy> = [
  "user",
  "api",
  "schedule",
];

function toProtocol(value: string): RepoProtocol {
  return (ALLOWED_PROTOCOLS as ReadonlyArray<string>).includes(value)
    ? (value as RepoProtocol)
    : "https";
}

function toAnalysisArray(value: unknown): AnalysisType[] {
  if (!Array.isArray(value)) return [];
  return value.filter(
    (v): v is AnalysisType =>
      typeof v === "string" && (ALLOWED_ANALYSIS as ReadonlyArray<string>).includes(v),
  );
}

function toStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string");
}

function toStatus(value: string): ScanStatus {
  return (ALLOWED_STATUS as ReadonlyArray<string>).includes(value)
    ? (value as ScanStatus)
    : "pending";
}

function toTriggeredBy(value: string): ScanTriggeredBy {
  return (ALLOWED_TRIGGERED as ReadonlyArray<string>).includes(value)
    ? (value as ScanTriggeredBy)
    : "user";
}

export function userToOut(user: User): UserOut {
  return {
    id: user.id,
    email: user.email,
    role: user.role === "admin" ? "admin" : "user",
    org_id: user.orgId,
  };
}

/** Distill the JSONB metadata blob into the UI-safe subset (no secrets).
 *  Used by the /admin/credentials responses. */
function credentialMetadataToOut(
  kind: string,
  raw: unknown,
): CredentialOut["metadata"] {
  if (raw === null || raw === undefined || typeof raw !== "object") return null;
  const meta = raw as Record<string, unknown>;
  switch (kind) {
    case "https_basic":
      return {
        username: typeof meta.username === "string" ? meta.username : null,
      };
    case "ssh_key":
      return {
        has_known_hosts: typeof meta.known_hosts === "string" && meta.known_hosts.length > 0,
      };
    default:
      return null;
  }
}

export function credentialToOut(
  cred: Credential,
  references: CredentialReferences,
): CredentialOut {
  return {
    id: cred.id,
    kind: cred.kind,
    name: cred.name,
    metadata: credentialMetadataToOut(cred.kind, cred.metadata),
    references,
    reference_count:
      references.repos.length +
      (references.jira_settings ? 1 : 0) +
      (references.llm_settings ? 1 : 0),
    expires_at: cred.expiresAt ? cred.expiresAt.toISOString() : null,
    created_at: cred.createdAt.toISOString(),
  };
}

export function repoToOut(repo: Repo): RepoOut {
  return {
    id: repo.id,
    org_id: repo.orgId,
    name: repo.name,
    url: repo.url,
    protocol: toProtocol(repo.protocol),
    credential_id: repo.credentialId,
    default_branch: repo.defaultBranch,
    scan_paths: toStringArray(repo.scanPaths),
    ignore_paths: toStringArray(repo.ignorePaths),
    analysis_types: toAnalysisArray(repo.analysisTypes),
    schedule_cron: repo.scheduleCron,
    source_url_template: repo.sourceUrlTemplate,
    is_active: repo.isActive,
    retain_clone: repo.retainClone,
    reachability_enabled: repo.reachabilityEnabled,
    reachability_include_dev_deps: repo.reachabilityIncludeDevDeps,
    llm_sast_effort: repo.llmSastEffort as "low" | "medium" | "high" | "xhigh" | "max",
    llm_recheck_effort: repo.llmRecheckEffort as "low" | "medium" | "high" | "xhigh" | "max",
    first_party_namespaces: repo.firstPartyNamespaces,
    vendored_dirs: repo.vendoredDirs,
    llm_sbom_effort: repo.llmSbomEffort as "low" | "medium" | "high" | "xhigh" | "max",
    llm_sbom_recheck_effort: repo.llmSbomRecheckEffort as "low" | "medium" | "high" | "xhigh" | "max",
    llm_sbom_token_budget: repo.llmSbomTokenBudget ?? null,
    llm_sbom_recheck_token_budget: repo.llmSbomRecheckTokenBudget ?? null,
    llm_sast_token_budget: repo.llmSastTokenBudget ?? null,
    llm_recheck_token_budget: repo.llmRecheckTokenBudget ?? null,
    last_cloned_at: repo.lastClonedAt ? repo.lastClonedAt.toISOString() : null,
    created_at: repo.createdAt.toISOString(),
  };
}

export function appSettingsToOut(s: AppSettings): AppSettingsOut {
  return {
    id: s.id,
    org_id: s.orgId,
    jira_base_url: s.jiraBaseUrl,
    jira_email: s.jiraEmail,
    jira_credential_id: s.jiraCredentialId,
    llm_base_url: s.llmBaseUrl,
    llm_api_format: s.llmApiFormat,
    llm_model: s.llmModel,
    llm_credential_id: s.llmCredentialId,
    reachability_min_severity: s.reachabilityMinSeverity as "critical" | "high" | "medium" | "low",
    nvd_credential_id: s.nvdCredentialId,
    updated_at: s.updatedAt.toISOString(),
  };
}

const ALLOWED_SEVERITY: ReadonlyArray<Severity> = [
  "critical",
  "high",
  "medium",
  "low",
  "unknown",
];

function toSeverity(value: string): Severity {
  return (ALLOWED_SEVERITY as ReadonlyArray<string>).includes(value)
    ? (value as Severity)
    : "unknown";
}

export function scanRunToOut(
  s: ScanRun & { scope?: Pick<ScanScope, "path"> | null },
): ScanRunOut {
  return {
    id: s.id,
    org_id: s.orgId,
    repo_id: s.repoId,
    scope_id: s.scopeId,
    scope_path: s.scope?.path ?? "/",
    status: toStatus(s.status),
    triggered_by: toTriggeredBy(s.triggeredBy),
    triggered_by_user_id: s.triggeredByUserId,
    started_at: s.startedAt ? s.startedAt.toISOString() : null,
    finished_at: s.finishedAt ? s.finishedAt.toISOString() : null,
    error: s.error,
    component_count: s.componentCount,
    critical_count: s.criticalCount,
    high_count: s.highCount,
    medium_count: s.mediumCount,
    low_count: s.lowCount,
    warnings: Array.isArray(s.warnings) ? (s.warnings as ScanWarning[]) : [],
    llm_input_tokens: s.llmInputTokens,
    llm_output_tokens: s.llmOutputTokens,
    llm_request_count: s.llmRequestCount,
    sast_finding_count: s.sastFindingCount,
    confirmed_reachable_count: s.confirmedReachableCount,
    current_phase: toPhase(s.currentPhase),
    phase_progress: s.phaseProgress as ScanRunOut["phase_progress"],
    created_at: s.createdAt.toISOString(),
  };
}

export function scanScopeToOut(s: ScanScope): ScanScopeOut {
  return {
    id: s.id,
    repo_id: s.repoId,
    path: s.path,
    display_name: s.displayName,
    is_active: s.isActive,
    created_at: s.createdAt.toISOString(),
  };
}

/**
 * Convert a ScopeComponent row to the same SbomComponentOut shape used by the
 * scan-detail view. Used by the Scope page's Components tab so manual deletes
 * and merges on scope_components flow straight into the UI. Per-scan
 * `occurrences` are pulled from the matching sbom_components row when available
 * (lookup keyed on lastSeenScanRunId + purl); empty array when no match.
 *
 * scan_run_id in the response is set to lastSeenScanRunId — the most recent
 * scan that observed this component — so the UI still has a scan to link to
 * when needed.
 */
export function scopeComponentToOut(
  c: {
    id: string;
    name: string;
    version: string | null;
    purl: string;
    ecosystem: string | null;
    licenses: string[];
    componentType: string;
    scope: string | null;
    isDevOnly: boolean;
    manifestFile: string | null;
    discoveryMethod: string | null;
    evidencePath: string | null;
    llmEvidence: unknown;
    cpe: string | null;
    componentRoot: string | null;
    evidence: unknown;
    usage: unknown;
    lastSeenScanRunId: string | null;
  },
): SbomComponentOut {
  let llmEvidence: { path: string; excerpt: string | null; llmReason: string } | null = null;
  if (c.llmEvidence && typeof c.llmEvidence === "object") {
    const ev = c.llmEvidence as Record<string, unknown>;
    if (typeof ev.llmReason === "string") {
      llmEvidence = {
        path: typeof ev.path === "string" ? ev.path : "",
        excerpt: typeof ev.excerpt === "string" ? ev.excerpt : null,
        llmReason: ev.llmReason,
      };
    }
  }
  // Identity-shaped evidence (small list, with optional snippet for manifest hits).
  const evidence = parseEvidence(c.evidence);
  // Usage list — same {path, line?} shape as occurrences on the scan side.
  const usage = parseOccurrenceList(c.usage);
  return {
    id: c.id,
    // scan_run_id is the most-recent scan that observed this component, used
    // by the UI's scan-link affordances. Null for manual-override rows that
    // have never been seen by a scan.
    scan_run_id: c.lastSeenScanRunId,
    name: c.name,
    version: c.version,
    purl: c.purl,
    ecosystem: c.ecosystem,
    licenses: c.licenses,
    component_type: c.componentType,
    scope: c.scope,
    is_dev_only: c.isDevOnly,
    manifest_file: c.manifestFile ?? null,
    discovery_method: c.discoveryMethod ?? null,
    // Backwards-compat: legacy callers still read `occurrences`. The scope
    // page now exposes the same data under `usage`; populate both with
    // identical content from the `usage` column so old clients don't
    // regress mid-rollout.
    occurrences: usage,
    usage,
    ...(llmEvidence ? { llm_evidence: llmEvidence } : {}),
    component_root: c.componentRoot ?? null,
    evidence,
  };
}

/**
 * Normalize a jsonb identity `evidence` column value into
 * `{path, line?, snippet?}[]` for the API. Each entry may be a bare
 * string (legacy rows) or an object; non-object/non-string entries are
 * skipped. Snippet is preserved verbatim when present.
 */
function parseEvidence(
  value: unknown,
): Array<{ path: string; line: number | null; snippet: string | null }> {
  if (!Array.isArray(value)) return [];
  const out: Array<{ path: string; line: number | null; snippet: string | null }> = [];
  for (const e of value as unknown[]) {
    if (typeof e === "string" && e.trim() !== "") {
      out.push({ path: e, line: null, snippet: null });
    } else if (e !== null && typeof e === "object") {
      const r = e as Record<string, unknown>;
      const path = typeof r.path === "string" ? r.path : "";
      if (!path) continue;
      const line = typeof r.line === "number" ? r.line : null;
      const snippet = typeof r.snippet === "string" ? r.snippet : null;
      out.push({ path, line, snippet });
    }
  }
  return out;
}

/**
 * Normalize a jsonb usage/occurrences column value into `{path, line?}[]`.
 * Symmetric helper to parseEvidence but without the snippet field —
 * usage entries are clickable links, not snippet previews.
 */
function parseOccurrenceList(
  value: unknown,
): Array<{ path: string; line: number | null }> {
  if (!Array.isArray(value)) return [];
  const out: Array<{ path: string; line: number | null }> = [];
  for (const e of value as unknown[]) {
    if (typeof e === "string" && e.trim() !== "") {
      out.push({ path: e, line: null });
    } else if (e !== null && typeof e === "object") {
      const r = e as Record<string, unknown>;
      const path = typeof r.path === "string" ? r.path : "";
      if (!path) continue;
      const line = typeof r.line === "number" ? r.line : null;
      out.push({ path, line });
    }
  }
  return out;
}

export function sbomComponentToOut(c: SbomComponent): SbomComponentOut {
  // Parse llmEvidence from JSONB if present.
  let llmEvidence: { path: string; excerpt: string | null; llmReason: string } | null = null;
  if (c.llmEvidence && typeof c.llmEvidence === "object") {
    const ev = c.llmEvidence as Record<string, unknown>;
    if (typeof ev.llmReason === "string") {
      llmEvidence = {
        path: typeof ev.path === "string" ? ev.path : "",
        excerpt: typeof ev.excerpt === "string" ? ev.excerpt : null,
        llmReason: ev.llmReason,
      };
    }
  }

  // Parse occurrences from JSONB. Shape: {path: string, line: number | null}[].
  // Default to [] when missing or null (pre-M6q rows will be backfilled).
  let occurrences: Array<{ path: string; line: number | null }> = [];
  if (Array.isArray(c.occurrences)) {
    occurrences = (c.occurrences as unknown[])
      .filter((o): o is Record<string, unknown> => o !== null && typeof o === "object")
      .map((o) => ({
        path: typeof o.path === "string" ? o.path : "",
        line: typeof o.line === "number" ? o.line : null,
      }))
      .filter((o) => o.path !== "");
  }

  return {
    id: c.id,
    scan_run_id: c.scanRunId,
    name: c.name,
    version: c.version,
    purl: c.purl,
    ecosystem: c.ecosystem,
    licenses: c.licenses,
    component_type: c.componentType,
    scope: c.scope,
    is_dev_only: c.isDevOnly,
    manifest_file: c.manifestFile ?? null,
    discovery_method: c.discoveryMethod ?? null,
    occurrences,
    // Mirror occurrences under `usage` so scope-page and scan-page consumers
    // share one field name on the wire — even though sbom_components stores
    // it as `occurrences` and scope_components stores it as `usage`.
    usage: occurrences,
    ...(llmEvidence ? { llm_evidence: llmEvidence } : {}),
    component_root: (c as unknown as { componentRoot?: string | null }).componentRoot ?? null,
    evidence: parseEvidence((c as unknown as { evidence?: unknown }).evidence),
  };
}

/**
 * Returns true when the OSV advisory contains at least one "fixed" event,
 * meaning a patched version is publicly available.
 */
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

const ALLOWED_FINDING_TYPES: ReadonlyArray<FindingType> = ["cve", "eol", "deprecated"];

function toFindingType(value: string): FindingType {
  return (ALLOWED_FINDING_TYPES as ReadonlyArray<string>).includes(value)
    ? (value as FindingType)
    : "cve";
}

type IssueFieldsForMapper = {
  latestLlmSummary: string | null;
  latestManifestFile: string | null;
  latestManifestLine: number | null;
  latestManifestSnippet: string | null;
  confirmedReachable: boolean;
  reachableConfidence: number | null;
  reachableReasoning: string | null;
  reachableCallSites: unknown;
  reachableModel: string | null;
  reachableAssessedAt: Date | null;
};

export function scanFindingToOut(
  f: ScanFinding & {
    component: Pick<SbomComponent, "name" | "version" | "scope" | "isDevOnly" | "ecosystem">;
    issue: IssueFieldsForMapper | null;
  },
): ScanFindingOut {
  // Reachability call sites are stored as JSONB — coerce to the wire shape
  // and reject obvious garbage so a bad row can't crash the response.
  const callSites = (() => {
    const raw = f.issue?.reachableCallSites;
    if (!Array.isArray(raw)) return null;
    const cleaned = raw
      .filter((s): s is { file: string; line: number; snippet: string } =>
        typeof s === "object" && s !== null
        && typeof (s as { file?: unknown }).file === "string"
        && typeof (s as { line?: unknown }).line === "number"
        && typeof (s as { snippet?: unknown }).snippet === "string",
      );
    return cleaned;
  })();

  return {
    id: f.id,
    scan_run_id: f.scanRunId,
    component_id: f.componentId,
    issue_id: f.issueId,
    component_name: f.component.name,
    component_version: f.component.version,
    component_scope: f.component.scope,
    is_dev_only: f.component.isDevOnly,
    finding_type: toFindingType(f.findingType),
    osv_id: f.osvId,
    cve_id: f.cveId,
    severity: toSeverity(f.severity),
    cvss_score: f.cvssScore,
    cvss_vector: f.cvssVector,
    summary: f.summary,
    aliases: f.aliases,
    actively_exploited: f.activelyExploited,
    eol_date: f.eolDate ? f.eolDate.toISOString() : null,
    has_fix: computeHasFix(f.detailJson),
    ecosystem: f.component.ecosystem,
    manifest_file: f.issue?.latestManifestFile ?? null,
    manifest_line: f.issue?.latestManifestLine ?? null,
    manifest_snippet: f.issue?.latestManifestSnippet ?? null,
    llm_summary: f.issue?.latestLlmSummary ?? null,
    confirmed_reachable: f.issue?.confirmedReachable ?? false,
    reachable_confidence: f.issue?.reachableConfidence ?? null,
    reachable_reasoning: f.issue?.reachableReasoning ?? null,
    reachable_call_sites: callSites,
    reachable_model: f.issue?.reachableModel ?? null,
    reachable_assessed_at: f.issue?.reachableAssessedAt ? f.issue.reachableAssessedAt.toISOString() : null,
    created_at: f.createdAt.toISOString(),
  };
}

const ALLOWED_SAST_SEVERITY: ReadonlyArray<SastSeverity> = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

function toSastSeverity(value: string): SastSeverity {
  return (ALLOWED_SAST_SEVERITY as ReadonlyArray<string>).includes(value)
    ? (value as SastSeverity)
    : "info";
}

const ALLOWED_TRIAGE_STATUS: ReadonlyArray<SastTriageStatus> = [
  "pending",
  "confirmed",
  "planned",        // linked to a Jira ticket; sub-state from jira.statusCategory
  "fixed",          // issue no longer detected in latest scan (auto-set by worker)
  "false_positive",
  "suppressed",
  "error",
];

function toTriageStatus(value: string): SastTriageStatus {
  return (ALLOWED_TRIAGE_STATUS as ReadonlyArray<string>).includes(value)
    ? (value as SastTriageStatus)
    : "pending";
}

export function sastFindingToOut(f: SastFinding): SastFindingOut {
  return {
    id: f.id,
    scan_run_id: f.scanRunId,
    scope_id: f.scopeId,
    issue_id: f.issueId,
    fingerprint: f.fingerprint,
    rule_id: f.ruleId,
    rule_name: f.ruleName,
    rule_message: f.ruleMessage,
    cwe_ids: f.cweIds,
    severity: toSastSeverity(f.severity),
    file_path: f.filePath,
    start_line: f.startLine,
    end_line: f.endLine,
    snippet: f.snippet,
    created_at: f.createdAt.toISOString(),
  };
}

export function sastIssueToOut(i: SastIssue): SastIssueOut {
  return {
    id: i.id,
    org_id: i.orgId,
    scope_id: i.scopeId,
    fingerprint: i.fingerprint,
    triage_status: toTriageStatus(i.triageStatus),
    triage_confidence: i.triageConfidence,
    triage_reasoning: i.triageReasoning,
    triage_model: i.triageModel,
    triage_input_tokens: i.triageInputTokens,
    triage_output_tokens: i.triageOutputTokens,
    suppressed_at: i.suppressedAt ? i.suppressedAt.toISOString() : null,
    suppressed_by_user_id: i.suppressedByUserId,
    suppressed_reason: i.suppressedReason,
    notes: i.notes,
    jira_ticket_id: i.jiraTicketId,
    latest_rule_id: i.latestRuleId,
    latest_rule_name: i.latestRuleName,
    latest_rule_message: i.latestRuleMessage,
    latest_llm_summary: i.latestLlmSummary,
    latest_severity: toSastSeverity(i.latestSeverity),
    latest_cwe_ids: i.latestCweIds,
    latest_file_path: i.latestFilePath,
    latest_start_line: i.latestStartLine,
    latest_end_line: i.latestEndLine,
    latest_snippet: i.latestSnippet,
    first_seen_at: i.firstSeenAt.toISOString(),
    last_seen_at: i.lastSeenAt.toISOString(),
    created_at: i.createdAt.toISOString(),
    updated_at: i.updatedAt.toISOString(),
  };
}

const ALLOWED_DISMISSED: ReadonlyArray<ScaDismissedStatus> = [
  "pending", "confirmed", "planned", "fixed", "suppressed", "false_positive",
];
function toDismissedStatus(value: string): ScaDismissedStatus {
  return (ALLOWED_DISMISSED as ReadonlyArray<string>).includes(value)
    ? (value as ScaDismissedStatus)
    : "pending";
}

export function scaIssueToOut(i: ScaIssue): ScaIssueOut {
  return {
    id: i.id,
    org_id: i.orgId,
    scope_id: i.scopeId,
    package_name: i.packageName,
    osv_id: i.osvId,
    dismissed_status: toDismissedStatus(i.dismissedStatus),
    dismissed_at: i.dismissedAt ? i.dismissedAt.toISOString() : null,
    dismissed_by_user_id: i.dismissedByUserId,
    dismissed_reason: i.dismissedReason,
    notes: i.notes,
    jira_ticket_id: i.jiraTicketId,
    latest_package_version: i.latestPackageVersion,
    latest_ecosystem: i.latestEcosystem,
    latest_component_scope: i.latestComponentScope,
    latest_is_dev_only: i.latestIsDevOnly,
    latest_finding_type: toFindingType(i.latestFindingType),
    latest_cve_id: i.latestCveId,
    latest_severity: toSeverity(i.latestSeverity),
    latest_cvss_score: i.latestCvssScore,
    latest_cvss_vector: i.latestCvssVector,
    latest_summary: i.latestSummary,
    latest_llm_summary: i.latestLlmSummary,
    latest_aliases: i.latestAliases,
    latest_actively_exploited: i.latestActivelyExploited,
    latest_eol_date: i.latestEolDate ? i.latestEolDate.toISOString() : null,
    latest_has_fix: i.latestHasFix,
    latest_manifest_file: i.latestManifestFile,
    latest_manifest_line: i.latestManifestLine,
    latest_manifest_snippet: i.latestManifestSnippet,
    confirmed_reachable: i.confirmedReachable,
    reachable_via_sast_fingerprint: i.reachableViaSastFingerprint,
    reachable_reasoning: i.reachableReasoning,
    reachable_confidence: i.reachableConfidence,
    reachable_call_sites: (i.reachableCallSites ?? null) as ScaIssueOut["reachable_call_sites"],
    reachable_assessed_at: i.reachableAssessedAt ? i.reachableAssessedAt.toISOString() : null,
    reachable_model: i.reachableModel,
    source: i.source,
    first_seen_at: i.firstSeenAt.toISOString(),
    last_seen_at: i.lastSeenAt.toISOString(),
    created_at: i.createdAt.toISOString(),
    updated_at: i.updatedAt.toISOString(),
  };
}

export function jiraTicketToOut(t: JiraTicket): JiraTicketOut {
  const sc = t.statusCategory;
  return {
    id: t.id,
    org_id: t.orgId,
    issue_key: t.issueKey,
    issue_id: t.issueId,
    project_key: t.projectKey,
    project_name: t.projectName,
    summary: t.summary,
    status: t.status,
    status_category: (sc === "new" || sc === "indeterminate" || sc === "done") ? sc : null,
    resolution: t.resolution,
    assignee_name: t.assigneeName,
    assignee_email: t.assigneeEmail,
    fix_versions: t.fixVersions,
    issue_type: t.issueType,
    url: t.url,
    resolved_at: t.resolvedAt ? t.resolvedAt.toISOString() : null,
    last_synced_at: t.lastSyncedAt ? t.lastSyncedAt.toISOString() : null,
    sync_error: t.syncError,
    created_at: t.createdAt.toISOString(),
  };
}
