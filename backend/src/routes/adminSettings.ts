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
import { checkJiraConnection, fetchResolutions, loadJiraConfig } from "../services/jiraClient.js";

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
  typed.post(
    "/admin/settings/jira/check",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "settings"],
        summary: "Check Jira connectivity with current settings",
        response: {
          200: z.discriminatedUnion("ok", [
            z.object({ ok: z.literal(true), account_name: z.string(), account_email: z.string() }),
            z.object({ ok: z.literal(false), error: z.string() }),
          ]),
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req) => {
      const orgId = req.user?.orgId ?? null;
      const cfg = await loadJiraConfig(orgId);
      if (!cfg) return { ok: false as const, error: "Jira base URL, email, or credential not configured" };
      const result = await checkJiraConnection(cfg);
      if (result.ok) return { ok: true as const, account_name: result.accountName, account_email: result.accountEmail };
      return { ok: false as const, error: result.error };
    },
  );

  typed.get(
    "/admin/jira/resolutions",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["jira"],
        summary: "List available Jira resolution values for this org",
        response: {
          200: z.array(z.object({ id: z.string(), name: z.string(), description: z.string().nullable() })),
          400: ErrorSchema,
          401: ErrorSchema,
          403: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const orgId = req.user?.orgId ?? null;
      const cfg = await loadJiraConfig(orgId);
      if (!cfg) return reply.code(400).send({ detail: "Jira not configured" });
      try {
        return await fetchResolutions(cfg);
      } catch (err) {
        return reply.code(400).send({ detail: err instanceof Error ? err.message : String(err) });
      }
    },
  );
};

export default adminSettingsRoutes;
