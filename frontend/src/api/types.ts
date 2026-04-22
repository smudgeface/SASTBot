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
  jira_credential_id: string | null;
  llm_base_url: string | null;
  llm_api_format: LlmApiFormat | null;
  llm_model: string | null;
  llm_credential_id: string | null;
  updated_at: string;
}

export interface AdminSettingsUpdate {
  jira_base_url?: string | null;
  jira_credential_id?: string | null;
  jira_credential?: CredentialCreateInput | null;
  llm_base_url?: string | null;
  llm_api_format?: LlmApiFormat | null;
  llm_model?: string | null;
  llm_credential_id?: string | null;
  llm_credential?: CredentialCreateInput | null;
}

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export type ScanStatus = "pending" | "running" | "success" | "failed";
export type ScanTrigger = "user" | "api" | "schedule";

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
  component_name: string;
  component_version: string | null;
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
  created_at: string;
}
