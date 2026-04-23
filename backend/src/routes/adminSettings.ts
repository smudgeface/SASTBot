import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import {
  AppSettingsOutSchema,
  AppSettingsUpdateSchema,
  ErrorSchema,
} from "../schemas.js";
import { appSettingsToOut } from "../services/mappers.js";
import { getOrCreateSettings, updateSettings } from "../services/settingsService.js";
import { checkLlmConnection } from "../services/llmClient.js";

const adminSettingsRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/admin/settings",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "settings"],
        summary: "Get app settings for the current org (created lazily)",
        response: {
          200: AppSettingsOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const settings = await getOrCreateSettings(orgId);
      return appSettingsToOut(settings);
    },
  );

  typed.put(
    "/admin/settings",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "settings"],
        summary: "Partially update app settings (flat shape)",
        body: AppSettingsUpdateSchema,
        response: {
          200: AppSettingsOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const settings = await updateSettings(orgId, req.body, req.user?.id ?? null);
      return appSettingsToOut(settings);
    },
  );
  typed.post(
    "/admin/settings/llm/check",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "settings"],
        summary: "Check LLM connection with current settings",
        response: {
          200: z.object({
            success: z.boolean(),
            latency_ms: z.number(),
            model: z.string(),
            input_tokens: z.number().int(),
            output_tokens: z.number().int(),
            error: z.string().optional(),
          }),
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const result = await checkLlmConnection(orgId);
      return {
        success: result.success,
        latency_ms: result.latencyMs,
        model: result.model,
        input_tokens: result.inputTokens,
        output_tokens: result.outputTokens,
        error: result.error,
      };
    },
  );
};

export default adminSettingsRoutes;
