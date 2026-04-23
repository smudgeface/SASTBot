import type {
  AppSettings,
  Credential,
  Repo,
  SastFinding,
  SbomComponent,
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
  RepoOut,
  SastFindingOut,
  SastSeverity,
  SastTriageStatus,
  SbomComponentOut,
  ScanFindingOut,
  ScanRunOut,
  ScanScopeOut,
  ScanWarning,
  Severity,
  UserOut,
} from "../schemas.js";

type AnalysisType = "sca" | "sast";
type RepoProtocol = "ssh" | "https";
type ScanStatus = "pending" | "running" | "success" | "failed";
type ScanTriggeredBy = "user" | "api" | "schedule";

const ALLOWED_PROTOCOLS: ReadonlyArray<RepoProtocol> = ["ssh", "https"];
const ALLOWED_ANALYSIS: ReadonlyArray<AnalysisType> = ["sca", "sast"];
const ALLOWED_STATUS: ReadonlyArray<ScanStatus> = [
  "pending",
  "running",
  "success",
  "failed",
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
    analysis_types: toAnalysisArray(repo.analysisTypes),
    schedule_cron: repo.scheduleCron,
    is_active: repo.isActive,
    retain_clone: repo.retainClone,
    last_cloned_at: repo.lastClonedAt ? repo.lastClonedAt.toISOString() : null,
    created_at: repo.createdAt.toISOString(),
  };
}

export function appSettingsToOut(s: AppSettings): AppSettingsOut {
  return {
    id: s.id,
    org_id: s.orgId,
    jira_base_url: s.jiraBaseUrl,
    jira_credential_id: s.jiraCredentialId,
    llm_base_url: s.llmBaseUrl,
    llm_api_format: s.llmApiFormat,
    llm_model: s.llmModel,
    llm_credential_id: s.llmCredentialId,
    llm_assistance_enabled: s.llmAssistanceEnabled,
    llm_triage_token_budget: s.llmTriageTokenBudget,
    reachability_cvss_threshold: s.reachabilityCvssThreshold,
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

export function sbomComponentToOut(c: SbomComponent): SbomComponentOut {
  return {
    id: c.id,
    scan_run_id: c.scanRunId,
    name: c.name,
    version: c.version,
    purl: c.purl,
    ecosystem: c.ecosystem,
    licenses: c.licenses,
    component_type: c.componentType,
  };
}

const ALLOWED_FINDING_TYPES: ReadonlyArray<FindingType> = ["cve", "eol", "deprecated"];

function toFindingType(value: string): FindingType {
  return (ALLOWED_FINDING_TYPES as ReadonlyArray<string>).includes(value)
    ? (value as FindingType)
    : "cve";
}

export function scanFindingToOut(
  f: ScanFinding & { component: Pick<SbomComponent, "name" | "version"> },
): ScanFindingOut {
  return {
    id: f.id,
    scan_run_id: f.scanRunId,
    component_id: f.componentId,
    component_name: f.component.name,
    component_version: f.component.version,
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
    confirmed_reachable: f.confirmedReachable,
    reachable_via_sast_fingerprint: f.reachableViaSastFingerprint,
    reachable_reasoning: f.reachableReasoning,
    reachable_assessed_at: f.reachableAssessedAt ? f.reachableAssessedAt.toISOString() : null,
    reachable_model: f.reachableModel,
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
    triage_status: toTriageStatus(f.triageStatus),
    triage_confidence: f.triageConfidence,
    triage_reasoning: f.triageReasoning,
    triage_model: f.triageModel,
    triage_input_tokens: f.triageInputTokens,
    triage_output_tokens: f.triageOutputTokens,
    suppressed_at: f.suppressedAt ? f.suppressedAt.toISOString() : null,
    suppressed_by_user_id: f.suppressedByUserId,
    suppressed_reason: f.suppressedReason,
    created_at: f.createdAt.toISOString(),
  };
}
