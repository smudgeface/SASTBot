/**
 * Hand-maintained shapes used by the UI until `npm run gen:types` replaces
 * `schema.d.ts`. These mirror the backend's Pydantic models at a surface level
 * — once the OpenAPI types are generated, these can be re-exported from
 * `components.schemas` instead.
 */

export type Role = "admin" | "member" | string;

export interface User {
  id: string;
  email: string;
  role: Role;
  org_id: string;
}

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
  created_at?: string;
  updated_at?: string;
}

export type CredentialKind = "https_token" | "https_basic" | "ssh_key" | "jira_basic" | "llm_api_key" | string;

export interface Credential {
  id: string;
  kind: CredentialKind;
  label: string;
  created_at: string;
}

export interface NewCredentialInput {
  kind: CredentialKind;
  label: string;
  value: string;
}

export interface RepoUpsertInput {
  name: string;
  url: string;
  protocol: RepoProtocol;
  default_branch: string;
  scan_paths: string[];
  analysis_types: AnalysisType[];
  /** Existing credential to link. Ignored if `credential` (inline) is supplied. */
  credential_id?: string | null;
  /** Optional inline credential to create and link in the same request. */
  credential?: NewCredentialInput | null;
}

export type LlmApiFormat = "anthropic-messages" | "openai-completions" | "openai-chat";

// AdminSettings mirrors the backend's flat shape (AppSettingsOut).
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

// AdminSettingsUpdate is a partial-update body (AppSettingsUpdate on the backend).
// Any field omitted leaves the stored value unchanged. Inline credential fields
// (`jira_credential`, `llm_credential`) are created + linked in the same request.
export interface AdminSettingsUpdate {
  jira_base_url?: string | null;
  jira_credential_id?: string | null;
  jira_credential?: NewCredentialInput | null;
  llm_base_url?: string | null;
  llm_api_format?: LlmApiFormat | null;
  llm_model?: string | null;
  llm_credential_id?: string | null;
  llm_credential?: NewCredentialInput | null;
}

export interface Scan {
  id: string;
  repo_id: string;
  status: string;
  created_at: string;
}
