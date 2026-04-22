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

export const CredentialCreateSchema = z.object({
  kind: CredentialKindSchema,
  label: z.string().min(1).max(255),
  value: z.string().min(1),
});
export type CredentialCreate = z.infer<typeof CredentialCreateSchema>;

export const CredentialOutSchema = z.object({
  id: UuidSchema,
  kind: z.string(),
  label: z.string(),
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
  created_at: IsoDateTimeSchema,
});
export type RepoOut = z.infer<typeof RepoOutSchema>;

export const RepoListSchema = z.array(RepoOutSchema);

export const RepoIdParamsSchema = z.object({ id: UuidSchema });

// ---------------------------------------------------------------------------
// AppSettings — flat on purpose
// ---------------------------------------------------------------------------

export const AppSettingsUpdateSchema = z.object({
  jira_base_url: z.string().nullable().optional(),
  jira_credential_id: UuidSchema.nullable().optional(),
  jira_credential: CredentialCreateSchema.nullable().optional(),
  llm_base_url: z.string().nullable().optional(),
  llm_api_format: z.string().nullable().optional(),
  llm_model: z.string().nullable().optional(),
  llm_credential_id: UuidSchema.nullable().optional(),
  llm_credential: CredentialCreateSchema.nullable().optional(),
});
export type AppSettingsUpdate = z.infer<typeof AppSettingsUpdateSchema>;

export const AppSettingsOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  jira_base_url: z.string().nullable(),
  jira_credential_id: UuidSchema.nullable(),
  llm_base_url: z.string().nullable(),
  llm_api_format: z.string().nullable(),
  llm_model: z.string().nullable(),
  llm_credential_id: UuidSchema.nullable(),
  updated_at: IsoDateTimeSchema,
});
export type AppSettingsOut = z.infer<typeof AppSettingsOutSchema>;

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const ScanStatusSchema = z.enum(["pending", "running", "success", "failed"]);
export const ScanTriggeredBySchema = z.enum(["user", "api", "schedule"]);

export const ScanRunOutSchema = z.object({
  id: UuidSchema,
  org_id: UuidSchema.nullable(),
  repo_id: UuidSchema,
  status: ScanStatusSchema,
  triggered_by: ScanTriggeredBySchema,
  triggered_by_user_id: UuidSchema.nullable(),
  started_at: IsoDateTimeSchema.nullable(),
  finished_at: IsoDateTimeSchema.nullable(),
  error: z.string().nullable(),
  created_at: IsoDateTimeSchema,
});
export type ScanRunOut = z.infer<typeof ScanRunOutSchema>;

export const ScanRunListSchema = z.array(ScanRunOutSchema);

// ---------------------------------------------------------------------------
// Common params
// ---------------------------------------------------------------------------

export const IdParamsSchema = z.object({ id: UuidSchema });
