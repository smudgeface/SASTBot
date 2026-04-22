import type { Credential, Prisma, PrismaClient } from "@prisma/client";

import { prisma } from "../db.js";
import { decrypt, encrypt } from "../security/crypto.js";

export class CredentialInUseError extends Error {
  readonly referencedBy: "repo" | "app settings";
  constructor(referencedBy: "repo" | "app settings") {
    super(`Credential is referenced by ${referencedBy}`);
    this.name = "CredentialInUseError";
    this.referencedBy = referencedBy;
  }
}

export class CredentialNotFoundError extends Error {
  constructor() {
    super("Credential not found");
    this.name = "CredentialNotFoundError";
  }
}

type Tx = PrismaClient | Prisma.TransactionClient;

export interface CreateCredentialInput {
  orgId: string | null;
  kind: string;
  label: string;
  value: string;
  createdBy?: string | null;
}

export async function createCredential(
  input: CreateCredentialInput,
  client: Tx = prisma,
): Promise<Credential> {
  const blob = encrypt(Buffer.from(input.value, "utf8"));
  return client.credential.create({
    data: {
      orgId: input.orgId ?? null,
      kind: input.kind,
      label: input.label,
      ciphertext: blob.ciphertext,
      nonce: blob.nonce,
      tag: blob.tag,
      keyVersion: 1,
      createdBy: input.createdBy ?? null,
    },
  });
}

export async function listCredentials(
  orgId: string | null,
  client: Tx = prisma,
): Promise<Credential[]> {
  return client.credential.findMany({
    where: { orgId: orgId ?? null },
    orderBy: { createdAt: "desc" },
  });
}

/**
 * Internal-only: decrypt a credential's value. Never expose through a route.
 * Used by outbound integrations (git clone, Jira sync, LLM calls) in later
 * milestones.
 */
export async function getPlaintext(credentialId: string, client: Tx = prisma): Promise<Buffer> {
  const row = await client.credential.findUnique({ where: { id: credentialId } });
  if (!row) throw new CredentialNotFoundError();
  return decrypt(
    Buffer.from(row.ciphertext),
    Buffer.from(row.nonce),
    Buffer.from(row.tag),
  );
}

export async function deleteCredential(
  credentialId: string,
  orgId: string | null,
  client: Tx = prisma,
): Promise<void> {
  const existing = await client.credential.findFirst({
    where: { id: credentialId, orgId: orgId ?? null },
  });
  if (!existing) throw new CredentialNotFoundError();

  const repoUse = await client.repo.count({ where: { credentialId } });
  if (repoUse > 0) throw new CredentialInUseError("repo");

  const settingsUse = await client.appSettings.count({
    where: {
      OR: [{ jiraCredentialId: credentialId }, { llmCredentialId: credentialId }],
    },
  });
  if (settingsUse > 0) throw new CredentialInUseError("app settings");

  await client.credential.delete({ where: { id: credentialId } });
}
