import { z } from "zod";

/**
 * Canonical request/response schemas shared by routes. These are the source of
 * truth for the OpenAPI spec served at /docs and for the types consumed by the
 * frontend via `openapi-typescript`.
 */

// ---------------------------------------------------------------------------
// Shared primitives
// ---------------------------------------------------------------------------

export const UuidSchema = z.string().uuid();
export const IsoDateTimeSchema = z.string();

export const RepoProtocolSchema = z.enum(["ssh", "https"]);
export const AnalysisTypeSchema = z.enum(["sca", "sast"]);

// `kind` is open — the frontend sends common values like "https_token",
// "https_basic", "ssh_key", "jira_token", "llm_api_key".
export const CredentialKindSchema = z.string().min(1).max(64);

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

export const ErrorSchema = z.object({ detail: z.string() });

// ---------------------------------------------------------------------------
// User / Auth
// ---------------------------------------------------------------------------

export const UserOutSchema = z.object({
  id: UuidSchema,
  email: z.string(),
  role: z.enum(["admin", "user"]),
  org_id: UuidSchema.nullable(),
});
export type UserOut = z.infer<typeof UserOutSchema>;

export const LoginBodySchema = z.object({
  email: z.string().min(1),
  password: z.string().min(1),
});
export type LoginBody = z.infer<typeof LoginBodySchema>;

export const LogoutOutSchema = z.object({ ok: z.boolean() });

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------
//
// Credentials are a discriminated union on `kind`. Each kind has its own
// required secret fields. Storage rules:
//   - secrets (tokens, passwords, private keys, passphrases) go through
//     AES-GCM encryption into `credentials.ciphertext`
//   - non-secret kind-specific fields (username for https_basic,
//     known_hosts for ssh_key) are stored in `credentials.metadata` (JSONB)
//
// See backend/src/services/credentialService.ts for the encoding.

const NameSchema = z.string().min(1).max(255);

/** Optional ISO-8601 expiry timestamp. When set, the UI surfaces it and
 *  future automated rotation reminders can query for near-expiry rows. */
const ExpiresAtSchema = z.string().datetime({ offset: true }).nullable().optional();

export const HttpsTokenCreateSchema = z.object({
  kind: z.literal("https_token"),
  name: NameSchema,
  value: z.string().min(1),
  expires_at: ExpiresAtSchema,
});

export const HttpsBasicCreateSchema = z.object({
  kind: z.literal("https_basic"),
  name: NameSchema,
  username: z.string().min(1).max(255),
  password: z.string().min(1),
  expires_at: ExpiresAtSchema,
});

export const SshKeyCreateSchema = z.object({
  kind: z.literal("ssh_key"),
  name: NameSchema,
  /** PEM-encoded private key (OpenSSH or RSA format). */
  private_key: z.string().min(1),
  /** Optional — only needed if the key is passphrase-protected. */
  passphrase: z.string().min(1).nullable().optional(),
  /**
   * Optional — a `known_hosts`-style line (or several) to pin the remote
   * host key. If omitted, the scan worker will auto-fetch and trust.
   */
  known_hosts: z.string().min(1).nullable().optional(),
  expires_at: ExpiresAtSchema,
});

export const JiraTokenCreateSchema = z.object({
  kind: z.literal("jira_token"),
  name: NameSchema,
  value: z.string().min(1),
  expires_at: ExpiresAtSchema,
});

export const LlmKeyCreateSchema = z.object({
  kind: z.literal("llm_api_key"),
  name: NameSchema,
  value: z.string().min(1),
  expires_at: ExpiresAtSchema,
});

export const CredentialCreateSchema = z.discriminatedUnion("kind", [
  HttpsTokenCreateSchema,
  HttpsBasicCreateSchema,
  SshKeyCreateSchema,
  JiraTokenCreateSchema,
  LlmKeyCreateSchema,
]);
export type CredentialCreate = z.infer<typeof CredentialCreateSchema>;

/**
 * Shape for rotating an existing credential (replacing its secret value
 * while keeping its id — so every row that references it stays linked).
 *
 * Like Create, discriminated on `kind`, but without `name`.
 */
export const CredentialRotateSchema = z.discriminatedUnion("kind", [
  HttpsTokenCreateSchema.omit({ name: true }),
  HttpsBasicCreateSchema.omit({ name: true }),
  SshKeyCreateSchema.omit({ name: true }),
  JiraTokenCreateSchema.omit({ name: true }),
  LlmKeyCreateSchema.omit({ name: true }),
]);
export type CredentialRotate = z.infer<typeof CredentialRotateSchema>;

/** Shape for renaming a credential (name-only edit — the secret value is
 *  immutable; use the rotate endpoint to replace it). Also accepts an
 *  updated expiry date. */
export const CredentialRenameSchema = z.object({
  name: NameSchema,
  expires_at: ExpiresAtSchema,
});
export type CredentialRename = z.infer<typeof CredentialRenameSchema>;

/** Non-secret metadata surfaced to the UI. `username` for https_basic,
 *  `has_passphrase` + `has_known_hosts` for ssh_key. Never includes any
 *  decrypted value. */
export const CredentialMetadataSchema = z
  .object({
    username: z.string().nullable().optional(),
    has_passphrase: z.boolean().optional(),
    has_known_hosts: z.boolean().optional(),
  })
  .nullable();

/** Summary of what uses a credential — drives the "Used by" column. */
export const CredentialReferencesSchema = z.object({
  repos: z.array(z.object({ id: UuidSchema, name: z.string() })),
  jira_settings: z.boolean(),
  llm_settings: z.boolean(),
});
export type CredentialReferences = z.infer<typeof CredentialReferencesSchema>;

export const CredentialOutSchema = z.object({
  id: UuidSchema,
  kind: z.string(),
  name: z.string(),
  metadata: CredentialMetadataSchema,
  references: CredentialReferencesSchema,
  reference_count: z.number().int().nonnegative(),
  expires_at: IsoDateTimeSchema.nullable(),
  created_at: IsoDateTimeSchema,
});
export type CredentialOut = z.infer<typeof CredentialOutSchema>;

export const CredentialListSchema = z.array(CredentialOutSchema);

// ---------------------------------------------------------------------------
// Repos
// ---------------------------------------------------------------------------

export const RepoCreateSchema = z.object({
  name: z.string().min(1).max(255),
  url: z.string().min(1).max(1024),
  protocol: RepoProtocolSchema,
  default_branch: z.string().min(1).max(255).default("main"),
  scan_paths: z.array(z.string()).default(["/"]),
  analysis_types: z.array(AnalysisTypeSchema).default(["sca"]),
  schedule_cron: z.string().nullable().optional(),
  is_active: z.boolean().default(true),
  /** When true, worker keeps the clone between scans and updates via
   *  `git fetch`; when false, each scan starts from a fresh tmpdir. */
  retain_clone: z.boolean().default(false),
  credential_id: UuidSchema.nullable().optional(),
  // NOTE: the contract names the inline field `credential`, NOT `new_credential`.
  credential: CredentialCreateSchema.nullable().optional(),
});
export type RepoCreate = z.infer<typeof RepoCreateSchema>;

export const RepoUpdateSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  url: z.string().min(1).max(1024).optional(),
  protocol: RepoProtocolSchema.optional(),
  default_branch: z.string().min(1).max(255).optional(),
  scan_paths: z.array(z.string()).optional(),
  analysis_types: z.array(AnalysisTypeSchema).optional(),
  schedule_cron: z.string().nullable().optional(),
  is_active: z.boolean().optional(),
  retain_clone: z.boolean().optional(),
  credential_id: UuidSchema.nullable().optional(),
  credential: CredentialCreateSchema.nullable().optional(),
});
export type RepoUpdate = z.infer<typeof RepoUpdateSchema>;

export const RepoOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  name: z.string(),
  url: z.string(),
  protocol: RepoProtocolSchema,
  credential_id: UuidSchema.nullable(),
  default_branch: z.string(),
  scan_paths: z.array(z.string()),
  analysis_types: z.array(AnalysisTypeSchema),
  schedule_cron: z.string().nullable(),
  is_active: z.boolean(),
  retain_clone: z.boolean(),
  /** Set whenever the worker finishes a clone/fetch for this repo. Null
   *  means no local cache exists — "Purge cache" should be disabled. */
  last_cloned_at: IsoDateTimeSchema.nullable(),
  created_at: IsoDateTimeSchema,
});
export type RepoOut = z.infer<typeof RepoOutSchema>;

export const RepoListSchema = z.array(RepoOutSchema);

export const RepoIdParamsSchema = z.object({ id: UuidSchema });

// ---------------------------------------------------------------------------
// AppSettings — flat on purpose
// ---------------------------------------------------------------------------

/** Severity gate for reachability assessment. info/unknown excluded — they
 *  are too noisy / underspecified to act on. */
export const ReachabilityMinSeveritySchema = z.enum(["critical", "high", "medium", "low"]);
export type ReachabilityMinSeverity = z.infer<typeof ReachabilityMinSeveritySchema>;

export const AppSettingsUpdateSchema = z.object({
  jira_base_url: z.string().nullable().optional(),
  jira_email: z.string().email().nullable().optional(),
  jira_credential_id: UuidSchema.nullable().optional(),
  jira_credential: CredentialCreateSchema.nullable().optional(),
  llm_base_url: z.string().nullable().optional(),
  llm_api_format: z.string().nullable().optional(),
  llm_model: z.string().nullable().optional(),
  llm_credential_id: UuidSchema.nullable().optional(),
  llm_credential: CredentialCreateSchema.nullable().optional(),
  llm_triage_token_budget: z.number().int().min(1000).optional(),
  reachability_min_severity: ReachabilityMinSeveritySchema.optional(),
});
export type AppSettingsUpdate = z.infer<typeof AppSettingsUpdateSchema>;

export const AppSettingsOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  jira_base_url: z.string().nullable(),
  jira_email: z.string().nullable(),
  jira_credential_id: UuidSchema.nullable(),
  llm_base_url: z.string().nullable(),
  llm_api_format: z.string().nullable(),
  llm_model: z.string().nullable(),
  llm_credential_id: UuidSchema.nullable(),
  llm_triage_token_budget: z.number().int(),
  reachability_min_severity: ReachabilityMinSeveritySchema,
  updated_at: IsoDateTimeSchema,
});
export type AppSettingsOut = z.infer<typeof AppSettingsOutSchema>;

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const ScanStatusSchema = z.enum(["pending", "running", "success", "failed"]);
export const ScanTriggeredBySchema = z.enum(["user", "api", "schedule"]);

export const ScanWarningSchema = z.object({
  code: z.string(),
  message: z.string(),
  context: z.record(z.unknown()).optional(),
});
export type ScanWarning = z.infer<typeof ScanWarningSchema>;

export const ScanRunOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  repo_id: UuidSchema,
  scope_id: UuidSchema,
  /** Relative path within the repo this scan targeted (e.g. "/" or "services/api"). */
  scope_path: z.string(),
  status: ScanStatusSchema,
  triggered_by: ScanTriggeredBySchema,
  triggered_by_user_id: UuidSchema.nullable(),
  started_at: IsoDateTimeSchema.nullable(),
  finished_at: IsoDateTimeSchema.nullable(),
  error: z.string().nullable(),
  component_count: z.number().int().nonnegative(),
  critical_count: z.number().int().nonnegative(),
  high_count: z.number().int().nonnegative(),
  medium_count: z.number().int().nonnegative(),
  low_count: z.number().int().nonnegative(),
  warnings: z.array(ScanWarningSchema),
  llm_input_tokens: z.number().int().nonnegative(),
  llm_output_tokens: z.number().int().nonnegative(),
  llm_request_count: z.number().int().nonnegative(),
  sast_finding_count: z.number().int().nonnegative(),
  confirmed_reachable_count: z.number().int().nonnegative(),
  created_at: IsoDateTimeSchema,
});
export type ScanRunOut = z.infer<typeof ScanRunOutSchema>;

export const ScanRunListSchema = z.array(ScanRunOutSchema);

// ---------------------------------------------------------------------------
// ScanScope
// ---------------------------------------------------------------------------

export const ScanScopeOutSchema = z.object({
  id: UuidSchema,
  repo_id: UuidSchema,
  path: z.string(),
  display_name: z.string().nullable(),
  is_active: z.boolean(),
  created_at: IsoDateTimeSchema,
});
export type ScanScopeOut = z.infer<typeof ScanScopeOutSchema>;

// ---------------------------------------------------------------------------
// SCA — SBOM components and findings (M3)
// ---------------------------------------------------------------------------

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "unknown"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const SbomComponentOutSchema = z.object({
  id: UuidSchema,
  scan_run_id: UuidSchema,
  name: z.string(),
  version: z.string().nullable(),
  purl: z.string(),
  ecosystem: z.string().nullable(),
  licenses: z.array(z.string()),
  component_type: z.string(),
  scope: z.string().nullable(),
});
export type SbomComponentOut = z.infer<typeof SbomComponentOutSchema>;

export const FindingTypeSchema = z.enum(["cve", "eol", "deprecated"]);
export type FindingType = z.infer<typeof FindingTypeSchema>;

export const ScanFindingOutSchema = z.object({
  id: UuidSchema,
  scan_run_id: UuidSchema,
  component_id: UuidSchema,
  issue_id: UuidSchema,
  component_name: z.string(),
  component_version: z.string().nullable(),
  /** CycloneDX scope: "required" (runtime dep), "optional" (dev/test), "excluded", or null */
  component_scope: z.string().nullable(),
  finding_type: FindingTypeSchema,
  osv_id: z.string(),
  cve_id: z.string().nullable(),
  severity: SeveritySchema,
  cvss_score: z.number().nullable(),
  cvss_vector: z.string().nullable(),
  summary: z.string().nullable(),
  aliases: z.array(z.string()),
  actively_exploited: z.boolean(),
  eol_date: IsoDateTimeSchema.nullable(),
  has_fix: z.boolean(),
  created_at: IsoDateTimeSchema,
});
export type ScanFindingOut = z.infer<typeof ScanFindingOutSchema>;

export const ScanFindingListSchema = z.array(ScanFindingOutSchema);

export const FindingsQuerySchema = z.object({
  severity: SeveritySchema.optional(),
  package: z.string().optional(),
});

// ---------------------------------------------------------------------------
// SAST findings (M4)
// ---------------------------------------------------------------------------

export const SastTriageStatusSchema = z.enum([
  "pending",
  "confirmed",
  "planned",        // linked to a Jira ticket; sub-state comes from jira.statusCategory
  "fixed",          // issue no longer detected in latest scan (auto-set by worker)
  "false_positive", // kept for backwards compat; UI calls it "invalid"
  "suppressed",     // kept for backwards compat; UI calls it "won't fix"
  "error",
]);
export type SastTriageStatus = z.infer<typeof SastTriageStatusSchema>;

export const SastSeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export type SastSeverity = z.infer<typeof SastSeveritySchema>;

export const SastFindingOutSchema = z.object({
  id: UuidSchema,
  scan_run_id: UuidSchema,
  scope_id: UuidSchema,
  issue_id: UuidSchema,
  fingerprint: z.string(),
  rule_id: z.string(),
  rule_name: z.string().nullable(),
  rule_message: z.string().nullable(),
  cwe_ids: z.array(z.string()),
  severity: SastSeveritySchema,
  file_path: z.string(),
  start_line: z.number().int(),
  end_line: z.number().int().nullable(),
  snippet: z.string().nullable(),
  created_at: IsoDateTimeSchema,
});
export type SastFindingOut = z.infer<typeof SastFindingOutSchema>;

export const SastFindingListSchema = z.array(SastFindingOutSchema);

export const SastTriageBodySchema = z.object({
  status: z.enum(["confirmed", "false_positive", "suppressed", "pending", "fixed"]),
  reason: z.string().optional(),
});
export type SastTriageBody = z.infer<typeof SastTriageBodySchema>;

export const SastFindingsQuerySchema = z.object({
  severity: SastSeveritySchema.optional(),
  file_path: z.string().optional(),
});

// ---------------------------------------------------------------------------
// Common params
// ---------------------------------------------------------------------------

export const IdParamsSchema = z.object({ id: UuidSchema });

export const SastFindingParamsSchema = z.object({
  id: UuidSchema,
  fid: UuidSchema,
});

// ---------------------------------------------------------------------------
// Issues (M5) — stable identity rows, one per (scope, fingerprint/pkg+osv)
// ---------------------------------------------------------------------------

export const SastIssueOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  scope_id: UuidSchema,
  fingerprint: z.string(),
  triage_status: SastTriageStatusSchema,
  triage_confidence: z.number().nullable(),
  triage_reasoning: z.string().nullable(),
  triage_model: z.string().nullable(),
  triage_input_tokens: z.number().int().nullable(),
  triage_output_tokens: z.number().int().nullable(),
  suppressed_at: IsoDateTimeSchema.nullable(),
  suppressed_by_user_id: UuidSchema.nullable(),
  suppressed_reason: z.string().nullable(),
  notes: z.string().nullable(),
  jira_ticket_id: UuidSchema.nullable(),
  latest_rule_id: z.string(),
  latest_rule_name: z.string().nullable(),
  latest_rule_message: z.string().nullable(),
  latest_llm_summary: z.string().nullable(),
  latest_severity: SastSeveritySchema,
  latest_cwe_ids: z.array(z.string()),
  latest_file_path: z.string(),
  latest_start_line: z.number().int(),
  latest_snippet: z.string().nullable(),
  first_seen_at: IsoDateTimeSchema,
  last_seen_at: IsoDateTimeSchema,
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type SastIssueOut = z.infer<typeof SastIssueOutSchema>;

export const ScaDismissedStatusSchema = z.enum(["pending", "confirmed", "planned", "fixed", "suppressed", "false_positive"]);
export type ScaDismissedStatus = z.infer<typeof ScaDismissedStatusSchema>;

export const ScaIssueOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  scope_id: UuidSchema,
  package_name: z.string(),
  osv_id: z.string(),
  dismissed_status: ScaDismissedStatusSchema,
  dismissed_at: IsoDateTimeSchema.nullable(),
  dismissed_by_user_id: UuidSchema.nullable(),
  dismissed_reason: z.string().nullable(),
  notes: z.string().nullable(),
  jira_ticket_id: UuidSchema.nullable(),
  latest_package_version: z.string().nullable(),
  latest_ecosystem: z.string().nullable(),
  latest_component_scope: z.string().nullable(),
  latest_finding_type: FindingTypeSchema,
  latest_cve_id: z.string().nullable(),
  latest_severity: SeveritySchema,
  latest_cvss_score: z.number().nullable(),
  latest_cvss_vector: z.string().nullable(),
  latest_summary: z.string().nullable(),
  latest_llm_summary: z.string().nullable(),
  latest_aliases: z.array(z.string()),
  latest_actively_exploited: z.boolean(),
  latest_eol_date: IsoDateTimeSchema.nullable(),
  latest_has_fix: z.boolean(),
  latest_manifest_file: z.string().nullable(),
  latest_manifest_line: z.number().int().nullable(),
  latest_manifest_snippet: z.string().nullable(),
  confirmed_reachable: z.boolean(),
  reachable_via_sast_fingerprint: z.string().nullable(),
  reachable_reasoning: z.string().nullable(),
  reachable_confidence: z.number().min(0).max(1).nullable(),
  reachable_call_sites: z.array(z.object({
    file: z.string(),
    line: z.number().int(),
    snippet: z.string(),
  })).nullable(),
  reachable_assessed_at: IsoDateTimeSchema.nullable(),
  reachable_model: z.string().nullable(),
  first_seen_at: IsoDateTimeSchema,
  last_seen_at: IsoDateTimeSchema,
  created_at: IsoDateTimeSchema,
  updated_at: IsoDateTimeSchema,
});
export type ScaIssueOut = z.infer<typeof ScaIssueOutSchema>;

export const SastIssueListSchema = z.array(SastIssueOutSchema);
export const ScaIssueListSchema = z.array(ScaIssueOutSchema);

// Triage action for a SastIssue
export const SastIssueTriageBodySchema = z.object({
  status: z.enum(["confirmed", "false_positive", "suppressed", "pending", "fixed", "planned"]),
  reason: z.string().optional(),
});
export type SastIssueTriageBody = z.infer<typeof SastIssueTriageBodySchema>;

// Dismiss action for a ScaIssue
export const ScaIssueDismissBodySchema = z.object({
  status: ScaDismissedStatusSchema,
  reason: z.string().optional(),
});
export type ScaIssueDismissBody = z.infer<typeof ScaIssueDismissBodySchema>;

// Paginated wrapper
export const PaginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  page_size: z.coerce.number().int().min(1).max(500).default(100),
});
export type PaginationQuery = z.infer<typeof PaginationQuerySchema>;

export function PaginatedSchema<T extends z.ZodTypeAny>(itemSchema: T) {
  return z.object({
    items: z.array(itemSchema),
    total: z.number().int().nonnegative(),
    page: z.number().int().min(1),
    page_size: z.number().int().min(1),
  });
}

// ---------------------------------------------------------------------------
// JiraTicket (M5c)
// ---------------------------------------------------------------------------

export const JiraTicketOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  issue_key: z.string(),
  issue_id: z.string().nullable(),
  project_key: z.string().nullable(),
  project_name: z.string().nullable(),
  summary: z.string().nullable(),
  status: z.string().nullable(),
  status_category: z.enum(["new", "indeterminate", "done"]).nullable(),
  resolution: z.string().nullable(),
  assignee_name: z.string().nullable(),
  assignee_email: z.string().nullable(),
  fix_versions: z.array(z.string()),
  issue_type: z.string().nullable(),
  url: z.string().nullable(),
  resolved_at: IsoDateTimeSchema.nullable(),
  last_synced_at: IsoDateTimeSchema.nullable(),
  sync_error: z.string().nullable(),
  created_at: IsoDateTimeSchema,
});
export type JiraTicketOut = z.infer<typeof JiraTicketOutSchema>;

export const LinkJiraTicketBodySchema = z.object({
  issue_key: z.string().min(1).max(64),
});
