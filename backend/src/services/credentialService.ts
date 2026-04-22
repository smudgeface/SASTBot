import { Prisma } from "@prisma/client";
import type { Credential, PrismaClient } from "@prisma/client";

import { prisma } from "../db.js";
import type {
  CredentialCreate,
  CredentialReferences,
  CredentialRotate,
} from "../schemas.js";
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

// ---------------------------------------------------------------------------
// Encoding — how each kind maps to (ciphertext plaintext, metadata JSON)
// ---------------------------------------------------------------------------
//
// Simple kinds (https_token, jira_token, llm_api_key): ciphertext holds the
//   raw UTF-8 secret string. metadata is null.
// https_basic: ciphertext holds the password. metadata = { username }.
// ssh_key: ciphertext holds a JSON blob of the secrets: at minimum
//   { private_key } and optionally { private_key, passphrase }. metadata
//   may hold { known_hosts } which is not secret.

interface EncodedSecret {
  plaintext: Buffer;
  metadata: Prisma.InputJsonValue | Prisma.NullableJsonNullValueInput;
}

/**
 * Turn a Create or Rotate payload into (plaintext-to-encrypt, metadata-to-store).
 * Accepts the union of both since they share the kind-discriminated secret
 * fields; Create also has a `name` which we ignore here (the caller sets it).
 */
type SecretInput = CredentialCreate | CredentialRotate;

function encodeSecret(input: SecretInput): EncodedSecret {
  switch (input.kind) {
    case "https_token":
    case "jira_token":
    case "llm_api_key":
      return {
        plaintext: Buffer.from(input.value, "utf8"),
        metadata: Prisma.JsonNull,
      };
    case "https_basic":
      return {
        plaintext: Buffer.from(input.password, "utf8"),
        metadata: { username: input.username },
      };
    case "ssh_key": {
      const secret: Record<string, string> = { private_key: input.private_key };
      if (input.passphrase) secret.passphrase = input.passphrase;
      const meta: Record<string, string> = {};
      if (input.known_hosts) meta.known_hosts = input.known_hosts;
      return {
        plaintext: Buffer.from(JSON.stringify(secret), "utf8"),
        metadata: Object.keys(meta).length > 0 ? meta : Prisma.JsonNull,
      };
    }
    default: {
      // Exhaustiveness check — TypeScript narrows to never here.
      const _exhaustive: never = input;
      throw new Error(`Unhandled credential kind: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Decoded plaintext surfaces — for integration code (gitClone, jira, llm)
// ---------------------------------------------------------------------------

export type DecodedCredential =
  | { kind: "https_token"; value: string }
  | { kind: "https_basic"; username: string; password: string }
  | {
      kind: "ssh_key";
      private_key: string;
      passphrase: string | null;
      known_hosts: string | null;
    }
  | { kind: "jira_token"; value: string }
  | { kind: "llm_api_key"; value: string };

export async function decodeCredential(
  credentialId: string,
  client: Tx = prisma,
): Promise<DecodedCredential> {
  const row = await client.credential.findUnique({ where: { id: credentialId } });
  if (!row) throw new CredentialNotFoundError();
  const plaintext = decrypt(
    Buffer.from(row.ciphertext),
    Buffer.from(row.nonce),
    Buffer.from(row.tag),
  ).toString("utf8");
  const meta = (row.metadata ?? null) as null | { username?: string; known_hosts?: string };

  switch (row.kind) {
    case "https_token":
    case "jira_token":
    case "llm_api_key":
      return { kind: row.kind, value: plaintext };
    case "https_basic":
      if (!meta?.username) {
        throw new Error("https_basic credential missing username in metadata");
      }
      return { kind: "https_basic", username: meta.username, password: plaintext };
    case "ssh_key": {
      let parsed: { private_key?: string; passphrase?: string };
      try {
        parsed = JSON.parse(plaintext) as { private_key?: string; passphrase?: string };
      } catch {
        // Legacy rows encrypted before this kind used JSON — treat whole blob as key.
        parsed = { private_key: plaintext };
      }
      if (!parsed.private_key) {
        throw new Error("ssh_key credential missing private_key");
      }
      return {
        kind: "ssh_key",
        private_key: parsed.private_key,
        passphrase: parsed.passphrase ?? null,
        known_hosts: meta?.known_hosts ?? null,
      };
    }
    default:
      throw new Error(`Unknown credential kind in DB: ${row.kind}`);
  }
}

// ---------------------------------------------------------------------------
// CRUD + rename + rotate
// ---------------------------------------------------------------------------

export interface CreateCredentialInput {
  orgId: string | null;
  input: CredentialCreate;
  createdBy?: string | null;
}

export async function createCredential(
  { orgId, input, createdBy }: CreateCredentialInput,
  client: Tx = prisma,
): Promise<Credential> {
  const encoded = encodeSecret(input);
  const blob = encrypt(encoded.plaintext);
  return client.credential.create({
    data: {
      orgId: orgId ?? null,
      kind: input.kind,
      name: input.name,
      ciphertext: blob.ciphertext,
      nonce: blob.nonce,
      tag: blob.tag,
      keyVersion: 1,
      metadata: encoded.metadata,
      expiresAt: input.expires_at ? new Date(input.expires_at) : null,
      createdBy: createdBy ?? null,
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

export async function getCredential(
  credentialId: string,
  orgId: string | null,
  client: Tx = prisma,
): Promise<Credential> {
  const row = await client.credential.findFirst({
    where: { id: credentialId, orgId: orgId ?? null },
  });
  if (!row) throw new CredentialNotFoundError();
  return row;
}

export async function renameCredential(
  credentialId: string,
  orgId: string | null,
  body: { name: string; expires_at?: string | null },
  client: Tx = prisma,
): Promise<Credential> {
  await getCredential(credentialId, orgId, client);
  return client.credential.update({
    where: { id: credentialId },
    data: {
      name: body.name,
      ...(body.expires_at !== undefined
        ? { expiresAt: body.expires_at ? new Date(body.expires_at) : null }
        : {}),
    },
  });
}

/** Replace a credential's secret value in-place, preserving the id so every
 *  repo/app-settings reference stays valid. The kind cannot change via
 *  rotate — create a new credential if you need a different kind. */
export async function rotateCredential(
  credentialId: string,
  orgId: string | null,
  input: CredentialRotate,
  client: Tx = prisma,
): Promise<Credential> {
  const existing = await getCredential(credentialId, orgId, client);
  if (existing.kind !== input.kind) {
    throw new Error(
      `Cannot rotate credential to a different kind (${existing.kind} → ${input.kind}). ` +
        `Create a new credential and swap references instead.`,
    );
  }
  const encoded = encodeSecret(input);
  const blob = encrypt(encoded.plaintext);
  return client.credential.update({
    where: { id: credentialId },
    data: {
      ciphertext: blob.ciphertext,
      nonce: blob.nonce,
      tag: blob.tag,
      metadata: encoded.metadata,
      keyVersion: existing.keyVersion,
    },
  });
}

export async function credentialReferences(
  credentialId: string,
  client: Tx = prisma,
): Promise<CredentialReferences> {
  const [repos, jiraCount, llmCount] = await Promise.all([
    client.repo.findMany({
      where: { credentialId },
      select: { id: true, name: true },
      orderBy: { name: "asc" },
    }),
    client.appSettings.count({ where: { jiraCredentialId: credentialId } }),
    client.appSettings.count({ where: { llmCredentialId: credentialId } }),
  ]);
  return {
    repos: repos.map((r) => ({ id: r.id, name: r.name })),
    jira_settings: jiraCount > 0,
    llm_settings: llmCount > 0,
  };
}

/**
 * Internal-only: raw decrypted bytes. Most callers should use
 * `decodeCredential` for a typed, structured result. Kept for outbound
 * integrations that want the raw secret (future Jira sync, LLM calls).
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
