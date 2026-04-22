import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

const HealthResponseSchema = z.object({
  status: z.literal("ok"),
  version: z.string(),
});

const healthRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/healthz",
    {
      schema: {
        tags: ["health"],
        summary: "Liveness probe",
        response: { 200: HealthResponseSchema },
      },
    },
    async () => ({ status: "ok" as const, version: "0.1.0" }),
  );
};

export default healthRoutes;
