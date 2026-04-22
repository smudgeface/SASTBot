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

export const HttpsTokenCreateSchema = z.object({
  kind: z.literal("https_token"),
  name: NameSchema,
  value: z.string().min(1),
});

export const HttpsBasicCreateSchema = z.object({
  kind: z.literal("https_basic"),
  name: NameSchema,
  username: z.string().min(1).max(255),
  password: z.string().min(1),
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
});

export const JiraTokenCreateSchema = z.object({
  kind: z.literal("jira_token"),
  name: NameSchema,
  value: z.string().min(1),
});

export const LlmKeyCreateSchema = z.object({
  kind: z.literal("llm_api_key"),
  name: NameSchema,
  value: z.string().min(1),
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
 *  immutable; use the rotate endpoint to replace it). */
export const CredentialRenameSchema = z.object({
  name: NameSchema,
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
