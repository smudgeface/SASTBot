/**
 * Hand-maintained shapes used by the UI. These mirror the backend's Zod
 * schemas; the auto-generated `schema.d.ts` from `npm run gen:types` is
 * the canonical source for request/response wire types, but these
 * user-friendly aliases are what app code imports.
 */

export type Role = "admin" | "member" | string;

export interface User {
  id: string;
  email: string;
  role: Role;
  org_id: string;
}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
//
// The five supported credential kinds. Each kind has its own secret shape
// sent to the backend; the backend decides which fields are secret vs.
// non-secret (see backend/src/services/credentialService.ts).

export type CredentialKind =
  | "https_token"
  | "https_basic"
  | "ssh_key"
  | "jira_token"
  | "llm_api_key";

export const CREDENTIAL_KIND_LABELS: Record<CredentialKind, string> = {
  https_token: "HTTPS token",
  https_basic: "HTTPS basic auth (username + password)",
  ssh_key: "SSH private key",
  jira_token: "Jira API token",
  llm_api_key: "LLM API key",
};

export interface CredentialMetadata {
  /** https_basic only. */
  username?: string | null;
  /** ssh_key only — we surface whether a passphrase is stored, but never the value. */
  has_passphrase?: boolean;
  /** ssh_key only — whether a known_hosts line is pinned. */
  has_known_hosts?: boolean;
}

export interface CredentialReferences {
  repos: { id: string; name: string }[];
  jira_settings: boolean;
  llm_settings: boolean;
}

export interface Credential {
  id: string;
  kind: CredentialKind;
  name: string;
  metadata: CredentialMetadata | null;
  references: CredentialReferences;
  reference_count: number;
  expires_at: string | null;
  created_at: string;
}

// -------- Create payloads (discriminated union on `kind`) --------

interface NamedBase {
  name: string;
  expires_at?: string | null;
}

export interface HttpsTokenCreate extends NamedBase {
  kind: "https_token";
  value: string;
}
export interface HttpsBasicCreate extends NamedBase {
  kind: "https_basic";
  username: string;
  password: string;
}
export interface SshKeyCreate extends NamedBase {
  kind: "ssh_key";
  private_key: string;
  passphrase?: string | null;
  known_hosts?: string | null;
}
export interface JiraTokenCreate extends NamedBase {
  kind: "jira_token";
  value: string;
}
export interface LlmKeyCreate extends NamedBase {
  kind: "llm_api_key";
  value: string;
}

export type CredentialCreateInput =
  | HttpsTokenCreate
  | HttpsBasicCreate
  | SshKeyCreate
  | JiraTokenCreate
  | LlmKeyCreate;

/** Rotate = same shape as Create minus the name (kind is locked). */
export type CredentialRotateInput =
  | Omit<HttpsTokenCreate, "name">
  | Omit<HttpsBasicCreate, "name">
  | Omit<SshKeyCreate, "name">
  | Omit<JiraTokenCreate, "name">
  | Omit<LlmKeyCreate, "name">;

/** Legacy simple-shape alias used in places where the kind is always
 *  `https_token`/`jira_token`/`llm_api_key`. */
export interface NewCredentialInput {
  kind: CredentialKind;
  name: string;
  value: string;
}

// ---------------------------------------------------------------------------
// Repositories
// ---------------------------------------------------------------------------

export type RepoProtocol = "ssh" | "https";
export type AnalysisType = "sca" | "sast";

export interface Repo {
  id: string;
  name: string;
  url: string;
  protocol: RepoProtocol;
  default_branch: string;
  scan_paths: string[];
  analysis_types: AnalysisType[];
  credential_id: string | null;
  retain_clone: boolean;
  last_cloned_at: string | null;
  created_at?: string;
  updated_at?: string;
}

export interface RepoUpsertInput {
  name: string;
  url: string;
  protocol: RepoProtocol;
  default_branch: string;
  scan_paths: string[];
  analysis_types: AnalysisType[];
  retain_clone?: boolean;
  /** Existing credential to link. Ignored if `credential` (inline) is supplied. */
  credential_id?: string | null;
  /** Optional inline credential to create and link in the same request. */
  credential?: CredentialCreateInput | null;
}

// ---------------------------------------------------------------------------
// AppSettings (flat on the wire)
// ---------------------------------------------------------------------------

export type LlmApiFormat = "anthropic-messages" | "openai-completions" | "openai-chat";

export interface AdminSettings {
  id: string;
  org_id: string | null;
  jira_base_url: string | null;
  jira_email: string | null;
  jira_credential_id: string | null;
  llm_base_url: string | null;
  llm_api_format: LlmApiFormat | null;
  llm_model: string | null;
  llm_credential_id: string | null;
  llm_triage_token_budget: number;
  reachability_cvss_threshold: number;
  updated_at: string;
}

export interface AdminSettingsUpdate {
  jira_base_url?: string | null;
  jira_email?: string | null;
  jira_credential_id?: string | null;
  jira_credential?: CredentialCreateInput | null;
  llm_base_url?: string | null;
  llm_api_format?: LlmApiFormat | null;
  llm_model?: string | null;
  llm_credential_id?: string | null;
  llm_credential?: CredentialCreateInput | null;
  llm_triage_token_budget?: number;
  reachability_cvss_threshold?: number;
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export type ScanStatus = "pending" | "running" | "success" | "failed";
export type ScanTrigger = "user" | "api" | "schedule";

export interface ScanWarning {
  code: string;
  message: string;
  context?: Record<string, unknown>;
}

export interface Scan {
  id: string;
  org_id: string | null;
  repo_id: string;
  scope_id: string;
  /** Relative path within the repo this scan targeted (e.g. "/" or "services/api"). */
  scope_path: string;
  status: ScanStatus;
  triggered_by: ScanTrigger;
  triggered_by_user_id: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  component_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  warnings: ScanWarning[];
  llm_input_tokens: number;
  llm_output_tokens: number;
  llm_request_count: number;
  sast_finding_count: number;
  confirmed_reachable_count: number;
  created_at: string;
}

// ---------------------------------------------------------------------------
// SCA — SBOM components and findings (M3)
// ---------------------------------------------------------------------------

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "unknown";
export type FindingType = "cve" | "eol" | "deprecated";

export interface SbomComponent {
  id: string;
  scan_run_id: string;
  name: string;
  version: string | null;
  purl: string;
  ecosystem: string | null;
  licenses: string[];
  component_type: string;
}

export interface ScanFinding {
  id: string;
  scan_run_id: string;
  component_id: string;
  issue_id: string;
  component_name: string;
  component_version: string | null;
  /** "required" = runtime dep, "optional" = dev/test dep, "excluded", or null */
  component_scope: string | null;
  finding_type: FindingType;
  osv_id: string;
  cve_id: string | null;
  severity: FindingSeverity;
  cvss_score: number | null;
  cvss_vector: string | null;
  summary: string | null;
  aliases: string[];
  actively_exploited: boolean;
  eol_date: string | null;
  /** True when OSV advisory includes at least one fixed version. */
  has_fix: boolean;
  created_at: string;
}

// ---------------------------------------------------------------------------
// SAST findings (M4 — detection rows; triage now lives on SastIssue)
// ---------------------------------------------------------------------------

export type SastTriageStatus = "pending" | "confirmed" | "planned" | "fixed" | "false_positive" | "suppressed" | "error";
export type SastSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface SastFinding {
  id: string;
  scan_run_id: string;
  scope_id: string;
  issue_id: string;
  fingerprint: string;
  rule_id: string;
  rule_name: string | null;
  rule_message: string | null;
  cwe_ids: string[];
  severity: SastSeverity;
  file_path: string;
  start_line: number;
  end_line: number | null;
  snippet: string | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Issues (M5) — stable identity rows
// ---------------------------------------------------------------------------

export type ScaDismissedStatus = "active" | "confirmed" | "acknowledged" | "wont_fix" | "false_positive";

export interface SastIssue {
  id: string;
  org_id: string | null;
  scope_id: string;
  fingerprint: string;
  triage_status: SastTriageStatus;
  triage_confidence: number | null;
  triage_reasoning: string | null;
  triage_model: string | null;
  triage_input_tokens: number | null;
  triage_output_tokens: number | null;
  suppressed_at: string | null;
  suppressed_by_user_id: string | null;
  suppressed_reason: string | null;
  notes: string | null;
  jira_ticket_id: string | null;
  latest_rule_id: string;
  latest_rule_name: string | null;
  latest_rule_message: string | null;
  latest_severity: SastSeverity;
  latest_cwe_ids: string[];
  latest_file_path: string;
  latest_start_line: number;
  latest_snippet: string | null;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface ScaIssue {
  id: string;
  org_id: string | null;
  scope_id: string;
  package_name: string;
  osv_id: string;
  dismissed_status: ScaDismissedStatus;
  dismissed_at: string | null;
  dismissed_by_user_id: string | null;
  dismissed_reason: string | null;
  notes: string | null;
  jira_ticket_id: string | null;
  latest_package_version: string | null;
  latest_ecosystem: string | null;
  latest_component_scope: string | null;
  latest_finding_type: FindingType;
  latest_cve_id: string | null;
  latest_severity: FindingSeverity;
  latest_cvss_score: number | null;
  latest_cvss_vector: string | null;
  latest_summary: string | null;
  latest_aliases: string[];
  latest_actively_exploited: boolean;
  latest_eol_date: string | null;
  latest_has_fix: boolean;
  confirmed_reachable: boolean;
  reachable_via_sast_fingerprint: string | null;
  reachable_reasoning: string | null;
  reachable_assessed_at: string | null;
  reachable_model: string | null;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

// ---------------------------------------------------------------------------
// Jira (M5c)
// ---------------------------------------------------------------------------

export interface JiraTicket {
  id: string;
  org_id: string | null;
  issue_key: string;
  issue_id: string | null;
  project_key: string | null;
  project_name: string | null;
  summary: string | null;
  status: string | null;
  status_category: "new" | "indeterminate" | "done" | null;
  resolution: string | null;
  assignee_name: string | null;
  assignee_email: string | null;
  fix_versions: string[];
  issue_type: string | null;
  url: string | null;
  resolved_at: string | null;
  last_synced_at: string | null;
  sync_error: string | null;
  created_at: string;
}

export interface JiraResolution {
  id: string;
  name: string;
  description: string | null;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

// ---------------------------------------------------------------------------
// Scopes (M5)
// ---------------------------------------------------------------------------

export interface ScopeListItem {
  id: string;
  org_id: string | null;
  repo_id: string;
  repo_name: string;
  repo_branch: string;
  path: string;
  display_name: string | null;
  is_active: boolean;
  last_scan_run_id: string | null;
  last_scan_completed_at: string | null;
  active_sast_issue_count: number;
  active_sca_issue_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  pending_triage_count: number;
  created_at: string;
}

export interface ScopeDetail extends ScopeListItem {
  resolved_sast_count: number;
  resolved_sca_count: number;
}

export interface ScanRunSummary {
  id: string;
  status: ScanStatus;
  triggered_by: string;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  component_count: number;
  critical_count: number;
  high_count: number;
  sast_finding_count: number;
  created_at: string;
}
