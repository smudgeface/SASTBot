import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

import { prisma } from "../db.js";
import {
  ErrorSchema,
  IdParamsSchema,
  ScanRunListSchema,
  ScanRunOutSchema,
} from "../schemas.js";
import { scanRunToOut } from "../services/mappers.js";

const scansRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/scans",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "List scan runs visible to the current org",
        response: {
          200: ScanRunListSchema,
          401: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const runs = await prisma.scanRun.findMany({
        where: { orgId: orgId ?? null },
        orderBy: { createdAt: "desc" },
      });
      return runs.map(scanRunToOut);
    },
  );

  typed.get(
    "/scans/:id",
    {
      preHandler: [app.authenticate],
      schema: {
        tags: ["scans"],
        summary: "Get a scan run by id",
        params: IdParamsSchema,
        response: {
          200: ScanRunOutSchema,
          401: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const run = await prisma.scanRun.findFirst({
        where: { id: req.params.id, orgId: orgId ?? null },
      });
      if (!run) {
        return reply.code(404).send({ detail: "Scan run not found" });
      }
      return scanRunToOut(run);
    },
  );
};

export default scansRoutes;
