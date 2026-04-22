import type { AppSettings, Credential, Repo, ScanRun, User } from "@prisma/client";

import type {
  AppSettingsOut,
  CredentialOut,
  CredentialReferences,
  RepoOut,
  ScanRunOut,
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
    updated_at: s.updatedAt.toISOString(),
  };
}

export function scanRunToOut(s: ScanRun): ScanRunOut {
  return {
    id: s.id,
    org_id: s.orgId,
    repo_id: s.repoId,
    status: toStatus(s.status),
    triggered_by: toTriggeredBy(s.triggeredBy),
    triggered_by_user_id: s.triggeredByUserId,
    started_at: s.startedAt ? s.startedAt.toISOString() : null,
    finished_at: s.finishedAt ? s.finishedAt.toISOString() : null,
    error: s.error,
    created_at: s.createdAt.toISOString(),
  };
}
