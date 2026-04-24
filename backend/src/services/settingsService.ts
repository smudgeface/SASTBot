import type { AppSettings, Prisma } from "@prisma/client";

import { prisma } from "../db.js";
import type { AppSettingsUpdate } from "../schemas.js";

import { createCredential } from "./credentialService.js";

/**
 * Singleton-per-org AppSettings. `GET` creates a row lazily on first access so
 * the admin UI can render a form bound to a guaranteed-existing object.
 */
export async function getOrCreateSettings(orgId: string | null): Promise<AppSettings> {
  const existing = await prisma.appSettings.findFirst({ where: { orgId: orgId ?? null } });
  if (existing) return existing;
  return prisma.appSettings.create({ data: { orgId: orgId ?? null } });
}

export async function updateSettings(
  orgId: string | null,
  input: AppSettingsUpdate,
  createdBy: string | null,
): Promise<AppSettings> {
  return prisma.$transaction(async (tx) => {
    const existing =
      (await tx.appSettings.findFirst({ where: { orgId: orgId ?? null } })) ??
      (await tx.appSettings.create({ data: { orgId: orgId ?? null } }));

    let jiraCredentialId: string | null | undefined;
    if (input.jira_credential) {
      const cred = await createCredential(
        { orgId, input: input.jira_credential, createdBy },
        tx,
      );
      jiraCredentialId = cred.id;
    } else if (Object.prototype.hasOwnProperty.call(input, "jira_credential_id")) {
      jiraCredentialId = input.jira_credential_id ?? null;
    }

    let llmCredentialId: string | null | undefined;
    if (input.llm_credential) {
      const cred = await createCredential(
        { orgId, input: input.llm_credential, createdBy },
        tx,
      );
      llmCredentialId = cred.id;
    } else if (Object.prototype.hasOwnProperty.call(input, "llm_credential_id")) {
      llmCredentialId = input.llm_credential_id ?? null;
    }

    const data: Prisma.AppSettingsUpdateInput = {};
    if (Object.prototype.hasOwnProperty.call(input, "jira_base_url")) {
      data.jiraBaseUrl = input.jira_base_url ?? null;
    }
    if (Object.prototype.hasOwnProperty.call(input, "jira_email")) {
      data.jiraEmail = input.jira_email ?? null;
    }
    if (jiraCredentialId !== undefined) {
      data.jiraCredential = jiraCredentialId
        ? { connect: { id: jiraCredentialId } }
        : { disconnect: true };
    }
    if (Object.prototype.hasOwnProperty.call(input, "llm_base_url")) {
      data.llmBaseUrl = input.llm_base_url ?? null;
    }
    if (Object.prototype.hasOwnProperty.call(input, "llm_api_format")) {
      data.llmApiFormat = input.llm_api_format ?? null;
    }
    if (Object.prototype.hasOwnProperty.call(input, "llm_model")) {
      data.llmModel = input.llm_model ?? null;
    }
    if (llmCredentialId !== undefined) {
      data.llmCredential = llmCredentialId
        ? { connect: { id: llmCredentialId } }
        : { disconnect: true };
    }
    if (Object.prototype.hasOwnProperty.call(input, "llm_triage_token_budget")) {
      data.llmTriageTokenBudget = input.llm_triage_token_budget;
    }
    if (Object.prototype.hasOwnProperty.call(input, "reachability_min_severity") && input.reachability_min_severity) {
      data.reachabilityMinSeverity = input.reachability_min_severity;
    }

    return tx.appSettings.update({ where: { id: existing.id }, data });
  });
}
