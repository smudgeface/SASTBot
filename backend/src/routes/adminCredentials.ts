import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import {
  CredentialListSchema,
  ErrorSchema,
  IdParamsSchema,
} from "../schemas.js";
import {
  CredentialInUseError,
  CredentialNotFoundError,
  deleteCredential,
  listCredentials,
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
      return creds.map(credentialToOut);
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
