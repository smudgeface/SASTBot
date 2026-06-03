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
  must_change_password: boolean;
}

/** Full admin-facing user row (from /admin/users). */
export interface AdminUser {
  id: string;
  email: string;
  name: string | null;
  role: "admin" | "member" | "user";
  is_active: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  created_at: string;
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
  | "llm_api_key"
  | "nvd_api_key";

export const CREDENTIAL_KIND_LABELS: Record<CredentialKind, string> = {
  https_token: "HTTPS token",
  https_basic: "HTTPS basic auth (username + password)",
  ssh_key: "SSH private key",
  jira_token: "Jira API token",
  llm_api_key: "LLM API key",
  nvd_api_key: "NVD API key",
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
  nvd_settings: boolean;
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
export interface NvdKeyCreate extends NamedBase {
  kind: "nvd_api_key";
  value: string;
}

export type CredentialCreateInput =
  | HttpsTokenCreate
  | HttpsBasicCreate
  | SshKeyCreate
  | JiraTokenCreate
  | LlmKeyCreate
  | NvdKeyCreate;

/** Rotate = same shape as Create minus the name (kind is locked). */
export type CredentialRotateInput =
  | Omit<HttpsTokenCreate, "name">
  | Omit<HttpsBasicCreate, "name">
  | Omit<SshKeyCreate, "name">
  | Omit<JiraTokenCreate, "name">
  | Omit<LlmKeyCreate, "name">
  | Omit<NvdKeyCreate, "name">;

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
/** `claude -p --effort` value. xhigh is Opus-only; Sonnet silently degrades. */
export type LlmEffort = "low" | "medium" | "high" | "xhigh" | "max";

export interface Repo {
  id: string;
  name: string;
  url: string;
  protocol: RepoProtocol;
  default_branch: string;
  scan_paths: string[];
  ignore_paths: string[];
  analysis_types: AnalysisType[];
  credential_id: string | null;
  retain_clone: boolean;
  reachability_enabled: boolean;
  include_dev_deps: boolean;
  llm_sast_effort: LlmEffort;
  llm_recheck_effort: LlmEffort;
  /** M6p Stage 2: first-party namespace prefixes the LLM drops. */
  first_party_namespaces: string[];
  /** M6p Stage 2: vendored directories the LLM inspects for missed libs. */
  vendored_dirs: string[];
  /** M6p Stage 2: effort level for the SBOM augmentation LLM pass. */
  llm_sbom_effort: LlmEffort;
  /** SBOM Component Recheck Stage 2: effort for the recheck pass. */
  llm_sbom_recheck_effort: LlmEffort;
  /** Per-repo token budgets. null = use the worker's compiled-in default. */
  llm_sbom_token_budget: number | null;
  llm_sbom_recheck_token_budget: number | null;
  llm_sast_token_budget: number | null;
  llm_recheck_token_budget: number | null;
  source_url_template: string | null;
  /** Live disk truth: a cached clone exists on the server right now. Source of
   *  truth for the "cached" badge — last_cloned_at is just an informational
   *  timestamp and can be set even when this is false (e.g. after a DB restore). */
  clone_present: boolean;
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
  ignore_paths?: string[];
  analysis_types: AnalysisType[];
  retain_clone?: boolean;
  reachability_enabled?: boolean;
  include_dev_deps?: boolean;
  llm_sast_effort?: LlmEffort;
  llm_recheck_effort?: LlmEffort;
  /** M6p Stage 2: first-party namespace prefixes. */
  first_party_namespaces?: string[];
  /** M6p Stage 2: vendored directories to scan. */
  vendored_dirs?: string[];
  /** M6p Stage 2: effort for the SBOM augmentation pass. */
  llm_sbom_effort?: LlmEffort;
  /** SBOM Component Recheck Stage 2: effort for the recheck pass. */
  llm_sbom_recheck_effort?: LlmEffort;
  /** Per-repo token budgets. null/omitted = use the worker's compiled-in default. */
  llm_sbom_token_budget?: number | null;
  llm_sbom_recheck_token_budget?: number | null;
  llm_sast_token_budget?: number | null;
  llm_recheck_token_budget?: number | null;
  source_url_template?: string | null;
  /** Existing credential to link. Ignored if `credential` (inline) is supplied. */
  credential_id?: string | null;
  /** Optional inline credential to create and link in the same request. */
  credential?: CredentialCreateInput | null;
}

// ---------------------------------------------------------------------------
// AppSettings (flat on the wire)
// ---------------------------------------------------------------------------

export type LlmApiFormat = "anthropic-messages" | "openai-completions" | "openai-chat";
export type ReachabilityMinSeverity = "critical" | "high" | "medium" | "low";

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
  reachability_min_severity: ReachabilityMinSeverity;
  nvd_credential_id: string | null;
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
  reachability_min_severity?: ReachabilityMinSeverity;
  nvd_credential_id?: string | null;
  nvd_credential?: CredentialCreateInput | null;
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export type ScanStatus = "pending" | "running" | "success" | "failed" | "cancelled";
export type ScanTrigger = "user" | "api" | "schedule";

export interface ScanWarning {
  code: string;
  message: string;
  /** "error" warnings flag the scan as untrustworthy enough to skip the
   *  SCA auto-fix sweep. "info" is the default and informs without
   *  blocking remediation logic. */
  severity: "info" | "error";
  context?: Record<string, unknown>;
  /** Raw parse-error payloads from the LLM JSONL parser (up to 5 entries,
   *  each `raw` capped to 2 KB). Present only on `*_parse_errors` warnings.
   *  Shape is `unknown` — guard before rendering. */
  details?: unknown;
}

export interface Scan {
  id: string;
  org_id: string | null;
  repo_id: string;
  /** Repo display name, joined server-side. Null if the join was absent. */
  repo_name: string | null;
  scope_id: string;
  /** Relative path within the repo this scan targeted (e.g. "/" or "services/api"). */
  scope_path: string;
  status: ScanStatus;
  triggered_by: ScanTrigger;
  triggered_by_user_id: string | null;
  /** Who triggered the scan — populated on the scan-detail endpoint only
   *  (null in the /scans list, and for api/schedule scans or deleted users). */
  triggered_by_user_email: string | null;
  triggered_by_user_name: string | null;
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
  /** Live progress fields, populated only while status==="running". */
  current_phase: ScanPhase | null;
  phase_progress: { done: number; total: number; label?: string } | null;
  created_at: string;
}

export type ScanPhase =
  | "cloning"
  | "cdxgen"
  | "llm_sbom"
  | "sbom_persist"
  | "llm_sbom_recheck"
  | "osv"
  | "nvd"
  | "eol"
  | "sbom_emit"
  | "llm_detection"
  | "llm_recheck"
  | "sarif_emit"
  | "sast_ingest"
  | "sca_summaries"
  | "finalizing";

export const SCAN_PHASE_LABELS: Record<ScanPhase, string> = {
  cloning: "Cloning repo",
  cdxgen: "Building SBOM",
  llm_sbom: "LLM SBOM augmentation",
  sbom_persist: "Persisting components",
  llm_sbom_recheck: "SBOM recheck",
  osv: "Querying OSV.dev",
  nvd: "Querying NVD",
  eol: "Checking EOL / deprecation",
  sbom_emit: "Writing SBOM artifact",
  llm_detection: "LLM SAST detection",
  llm_recheck: "LLM SAST recheck",
  sarif_emit: "Writing SARIF artifact",
  sast_ingest: "Indexing SAST findings",
  sca_summaries: "Generating summaries",
  finalizing: "Finalizing",
};

// Unit for the done/total counters per phase. Phases without an entry render
// just the number (e.g. "0 of 45 · 10%"); phases with one append the unit
// ("0 of 300000 tokens · 0%") so the magnitude isn't mysterious.
export const SCAN_PHASE_UNITS: Partial<Record<ScanPhase, string>> = {
  osv: "components",
  nvd: "components",
  eol: "components",
  llm_sbom: "tokens",
  llm_sbom_recheck: "components",
  llm_detection: "tokens",
  llm_recheck: "tokens",
  sca_summaries: "summaries",
};

// Phases where `total` is a hard cap (e.g. token budget), not a goal — `done`
// advances toward the cap as a "still moving" signal but isn't expected to
// reach it. Render with `(max)` suffix and no percentage / bar so the UI
// doesn't suggest filling to 100% is the objective.
export const SCAN_PHASE_CAPS = new Set<ScanPhase>(["llm_sbom", "llm_sbom_recheck", "llm_detection", "llm_recheck"]);

// ---------------------------------------------------------------------------
// SCA — SBOM components and findings (M3)
// ---------------------------------------------------------------------------

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "unknown";
export type FindingType = "cve" | "eol" | "deprecated";

export interface LlmEvidence {
  /** Repo-relative file path where the LLM found the evidence. */
  path: string;
  excerpt: string | null;
  /** One-sentence rationale from the LLM. */
  llmReason: string;
}

/** M6q: single location where a component is used. */
export interface ComponentOccurrence {
  path: string;
  line: number | null;
}

export interface SbomComponent {
  id: string;
  scan_run_id: string;
  name: string;
  version: string | null;
  purl: string;
  ecosystem: string | null;
  licenses: string[];
  component_type: string;
  scope?: string | null;
  /** True iff cdxgen 12.2+ flagged this npm package as dev-only (lockfile dev: true). */
  is_dev_only: boolean;
  manifest_file?: string | null;
  /** How the component was discovered: "manifest" | "llm_augmentation". */
  discovery_method?: string | null;
  /** M6q: full list of locations where this component is used. */
  occurrences?: ComponentOccurrence[];
  /** M6q (scope endpoint only): linked SCA/SAST issue IDs. */
  linked_issue_ids?: { sca: string[]; sast: string[] };
  /** M6p Stage 2: evidence from LLM augmentation, set for added/kept-with-rationale components. */
  llm_evidence?: LlmEvidence | null;
  /** M7: shallowest directory uniquely owned by this component (dedup identity). */
  component_root?: string | null;
  /** Identity-shaped evidence — the small list of locations that establish
   *  this component is present. For manifest-tracked packages, one entry
   *  per representative manifest with `{path, line, snippet}` (snippet is
   *  ±3 lines of the lockfile entry). For vendored libraries, one entry
   *  with `{path: component_root}`. Renders as the "Evidence" section
   *  in the component detail panel, with a code preview when snippet is set. */
  evidence?: Array<{ path: string; line?: number | null; snippet?: string | null }>;
  /** Usage list — where the component is imported / included from. Long
   *  list of {path, line?}, rendered as clickable file:line links. The
   *  same data as `occurrences` for scan-page rows; both are populated
   *  identically to keep call sites symmetric. */
  usage?: ComponentOccurrence[];
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
  ecosystem: string | null;
  /** Manifest declaration site — joined from the SCA issue. */
  manifest_file: string | null;
  manifest_line: number | null;
  manifest_snippet: string | null;
  /** LLM-generated longer-form description for the expanded panel. */
  llm_summary: string | null;
  /** Reachability verdict — `reachable_assessed_at` is the truthiness gate;
   *  null means the verdict hasn't been computed yet for this issue. */
  confirmed_reachable: boolean;
  reachable_confidence: number | null;
  reachable_reasoning: string | null;
  reachable_call_sites: { file: string; line: number; snippet: string }[] | null;
  reachable_model: string | null;
  reachable_assessed_at: string | null;
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

export type ScaDismissedStatus = "pending" | "confirmed" | "planned" | "fixed" | "suppressed" | "false_positive";

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
  latest_llm_summary: string | null;
  latest_severity: SastSeverity;
  latest_cwe_ids: string[];
  latest_file_path: string;
  latest_start_line: number;
  /** Inclusive last line of the problem region. null for absence rows and
   *  for issues that pre-date the worker-builds-snippet cutover. */
  latest_end_line: number | null;
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
  /** Mirrors SbomComponent.is_dev_only from latest detection. */
  latest_is_dev_only: boolean;
  latest_finding_type: FindingType;
  latest_cve_id: string | null;
  latest_severity: FindingSeverity;
  latest_cvss_score: number | null;
  latest_cvss_vector: string | null;
  latest_summary: string | null;
  latest_llm_summary: string | null;
  latest_aliases: string[];
  latest_actively_exploited: boolean;
  latest_eol_date: string | null;
  latest_has_fix: boolean;
  latest_manifest_file: string | null;
  latest_manifest_line: number | null;
  latest_manifest_snippet: string | null;
  confirmed_reachable: boolean;
  reachable_via_sast_fingerprint: string | null;
  reachable_reasoning: string | null;
  reachable_confidence: number | null;
  reachable_call_sites: { file: string; line: number; snippet: string }[] | null;
  reachable_assessed_at: string | null;
  reachable_model: string | null;
  /** Provenance of this finding: "osv" | "nvd". */
  source: string;
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
  /** Present on endpoints that support dev-only filtering (components, sca-issues). */
  total_dev?: number;
  total_runtime?: number;
}

// ---------------------------------------------------------------------------
// Scopes (M5)
// ---------------------------------------------------------------------------

export interface ActiveScan {
  id: string;
  status: "pending" | "running";
  started_at: string | null;
  current_phase: ScanPhase | null;
  phase_progress: { done: number; total: number; label?: string } | null;
}

export interface ScopeListItem {
  id: string;
  org_id: string | null;
  repo_id: string;
  repo_name: string;
  repo_branch: string;
  include_dev_deps: boolean;
  path: string;
  display_name: string | null;
  is_active: boolean;
  last_scan_run_id: string | null;
  last_scan_completed_at: string | null;
  /** Most recent pending/running scan, null if none in flight. */
  active_scan: ActiveScan | null;
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
  source_url_template: string | null;
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
  current_phase: ScanPhase | null;
  phase_progress: { done: number; total: number; label?: string } | null;
  created_at: string;
  warnings: ScanWarning[];
}
