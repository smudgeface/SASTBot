import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";
import {
  CredentialCreateSchema,
  CredentialListSchema,
  CredentialOutSchema,
  CredentialRenameSchema,
  CredentialRotateSchema,
  ErrorSchema,
  IdParamsSchema,
} from "../schemas.js";
import {
  CredentialInUseError,
  CredentialNotFoundError,
  createCredential,
  credentialReferences,
  deleteCredential,
  getCredential,
  listCredentials,
  renameCredential,
  rotateCredential,
} from "../services/credentialService.js";
import { credentialToOut } from "../services/mappers.js";

const adminCredentialsRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/admin/credentials",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "credentials"],
        summary: "List credential metadata (NEVER plaintext)",
        response: {
          200: CredentialListSchema,
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req) => {
      const creds = await listCredentials(req.user?.orgId ?? null);
      // Batch-fetch all references in parallel; could later be a single
      // grouped query if the credential count grows.
      const refs = await Promise.all(creds.map((c) => credentialReferences(c.id)));
      return creds.map((c, i) => credentialToOut(c, refs[i]));
    },
  );

  typed.post(
    "/admin/credentials",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "credentials"],
        summary: "Create a new credential",
        description:
          "Kind-aware body: `https_token`/`jira_token`/`llm_api_key` take `value`; `https_basic` takes `username`+`password`; `ssh_key` takes `private_key`, optional `passphrase`, and optional `known_hosts`.",
        body: CredentialCreateSchema,
        response: {
          201: CredentialOutSchema,
          400: ErrorSchema,
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const cred = await prisma.$transaction(async (tx) =>
        createCredential(
          {
            orgId: req.user?.orgId ?? null,
            input: req.body,
            createdBy: req.user?.id ?? null,
          },
          tx,
        ),
      );
      const refs = await credentialReferences(cred.id);
      return reply.code(201).send(credentialToOut(cred, refs));
    },
  );

  typed.patch(
    "/admin/credentials/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "credentials"],
        summary: "Rename a credential (label-only edit — value is immutable)",
        params: IdParamsSchema,
        body: CredentialRenameSchema,
        response: {
          200: CredentialOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const cred = await renameCredential(
          req.params.id,
          req.user?.orgId ?? null,
          req.body.label,
        );
        const refs = await credentialReferences(cred.id);
        return credentialToOut(cred, refs);
      } catch (err) {
        if (err instanceof CredentialNotFoundError) {
          return reply.code(404).send({ detail: "Credential not found" });
        }
        throw err;
      }
    },
  );

  typed.post(
    "/admin/credentials/:id/rotate",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "credentials"],
        summary: "Rotate the secret value of an existing credential",
        description:
          "Keeps the credential id so every repo / app_settings reference stays linked. Kind cannot change via rotate — create a new credential if you need a different kind.",
        params: IdParamsSchema,
        body: CredentialRotateSchema,
        response: {
          200: CredentialOutSchema,
          400: ErrorSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        // Ensure kind on the body matches the stored kind (Zod's
        // discriminated union would otherwise let callers rotate one
        // kind's secret into another kind of row).
        const existing = await getCredential(
          req.params.id,
          req.user?.orgId ?? null,
        );
        if (existing.kind !== req.body.kind) {
          return reply.code(400).send({
            detail: `Rotate kind ${req.body.kind} does not match credential kind ${existing.kind}`,
          });
        }
        const cred = await rotateCredential(
          req.params.id,
          req.user?.orgId ?? null,
          req.body,
        );
        const refs = await credentialReferences(cred.id);
        return credentialToOut(cred, refs);
      } catch (err) {
        if (err instanceof CredentialNotFoundError) {
          return reply.code(404).send({ detail: "Credential not found" });
        }
        throw err;
      }
    },
  );

  typed.delete(
    "/admin/credentials/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "credentials"],
        summary: "Delete a credential (409 if referenced)",
        params: IdParamsSchema,
        response: {
          204: z.null().describe("Credential deleted"),
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        await deleteCredential(req.params.id, req.user?.orgId ?? null);
        return reply.code(204).send();
      } catch (err) {
        if (err instanceof CredentialNotFoundError) {
          return reply.code(404).send({ detail: "Credential not found" });
        }
        if (err instanceof CredentialInUseError) {
          return reply
            .code(409)
            .send({ detail: `Credential is referenced by ${err.referencedBy}` });
        }
        throw err;
      }
    },
  );
};

export default adminCredentialsRoutes;
