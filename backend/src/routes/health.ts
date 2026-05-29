import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import { prisma } from "../db.js";
import { getRedis } from "../queue/connection.js";
import { APP_VERSION } from "./version.js";

const HealthResponseSchema = z.object({
  status: z.literal("ok"),
  version: z.string(),
});

const ReadyResponseSchema = z.object({
  status: z.enum(["ready", "degraded"]),
  version: z.string(),
  checks: z.object({
    database: z.boolean(),
    redis: z.boolean(),
  }),
});

/** Run a promise with a hard timeout so a hung dependency can't hang the probe. */
async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
  ]);
}

const healthRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  // Liveness: is the process up and serving? Cheap, never touches dependencies.
  // Used by the container HEALTHCHECK to decide "is this process alive".
  typed.get(
    "/healthz",
    {
      schema: {
        tags: ["health"],
        summary: "Liveness probe",
        response: { 200: HealthResponseSchema },
      },
    },
    async () => ({ status: "ok" as const, version: APP_VERSION }),
  );

  // Readiness: can the process actually serve traffic — DB + Redis reachable?
  // Returns 503 when a dependency is down so an orchestrator can hold traffic
  // off this instance instead of routing requests that will fail.
  typed.get(
    "/readyz",
    {
      schema: {
        tags: ["health"],
        summary: "Readiness probe (verifies Postgres + Redis connectivity)",
        response: { 200: ReadyResponseSchema, 503: ReadyResponseSchema },
      },
    },
    async (_req, reply) => {
      const [database, redis] = await Promise.all([
        withTimeout(prisma.$queryRaw`SELECT 1`, 1000)
          .then(() => true)
          .catch(() => false),
        withTimeout(getRedis().ping(), 1000)
          .then((res) => res === "PONG")
          .catch(() => false),
      ]);
      const ready = database && redis;
      reply.code(ready ? 200 : 503);
      return {
        status: ready ? ("ready" as const) : ("degraded" as const),
        version: APP_VERSION,
        checks: { database, redis },
      };
    },
  );
};

export default healthRoutes;
