import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import {
  ErrorSchema,
  IdParamsSchema,
  RepoCreateSchema,
  RepoListSchema,
  RepoOutSchema,
  RepoUpdateSchema,
  ScanRunOutSchema,
} from "../schemas.js";
import { repoToOut, scanRunToOut } from "../services/mappers.js";
import {
  RepoConflictError,
  RepoNotFoundError,
  createRepo,
  deleteRepo,
  getRepo,
  listRepos,
  updateRepo,
} from "../services/repoService.js";
import { triggerScan } from "../services/scanService.js";

const adminReposRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/admin/repos",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "repos"],
        summary: "List repos for the current org",
        response: { 200: RepoListSchema, 401: ErrorSchema, 403: ErrorSchema },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const repos = await listRepos(orgId);
      return repos.map(repoToOut);
    },
  );

  typed.post(
    "/admin/repos",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "repos"],
        summary: "Create a new repo (optionally with an inline credential)",
        body: RepoCreateSchema,
        response: {
          201: RepoOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const repo = await createRepo(
          req.body,
          req.user?.orgId ?? null,
          req.user?.id ?? null,
        );
        return reply.code(201).send(repoToOut(repo));
      } catch (err) {
        if (err instanceof RepoConflictError) {
          return reply.code(409).send({ detail: err.message });
        }
        throw err;
      }
    },
  );

  typed.get(
    "/admin/repos/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "repos"],
        summary: "Get a repo by id",
        params: IdParamsSchema,
        response: {
          200: RepoOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const repo = await getRepo(req.params.id, req.user?.orgId ?? null);
        return repoToOut(repo);
      } catch (err) {
        if (err instanceof RepoNotFoundError) {
          return reply.code(404).send({ detail: "Repo not found" });
        }
        throw err;
      }
    },
  );

  typed.put(
    "/admin/repos/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "repos"],
        summary: "Update a repo",
        params: IdParamsSchema,
        body: RepoUpdateSchema,
        response: {
          200: RepoOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const repo = await updateRepo(
          req.params.id,
          req.body,
          req.user?.orgId ?? null,
          req.user?.id ?? null,
        );
        return repoToOut(repo);
      } catch (err) {
        if (err instanceof RepoNotFoundError) {
          return reply.code(404).send({ detail: "Repo not found" });
        }
        if (err instanceof RepoConflictError) {
          return reply.code(409).send({ detail: err.message });
        }
        throw err;
      }
    },
  );

  typed.post(
    "/admin/repos/:id/scan",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "repos"],
        summary: "Trigger a scan for this repo",
        description:
          "Creates a scan_runs row in `pending` and enqueues a BullMQ job. M1/M2 handler is a 2-second stub; M3 fills in the real SCA work.",
        params: IdParamsSchema,
        response: {
          202: ScanRunOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const run = await triggerScan({
          repoId: req.params.id,
          orgId: req.user?.orgId ?? null,
          triggeredByUserId: req.user?.id ?? null,
          triggeredBy: "user",
        });
        return reply.code(202).send(scanRunToOut(run));
      } catch (err) {
        if (err instanceof RepoNotFoundError) {
          return reply.code(404).send({ detail: "Repo not found" });
        }
        throw err;
      }
    },
  );

  typed.delete(
    "/admin/repos/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "repos"],
        summary: "Delete a repo",
        params: IdParamsSchema,
        response: {
          204: z.null().describe("Repo deleted"),
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        await deleteRepo(req.params.id, req.user?.orgId ?? null);
        return reply.code(204).send();
      } catch (err) {
        if (err instanceof RepoNotFoundError) {
          return reply.code(404).send({ detail: "Repo not found" });
        }
        throw err;
      }
    },
  );
};

export default adminReposRoutes;
