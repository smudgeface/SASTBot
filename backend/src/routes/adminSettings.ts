import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

import {
  AppSettingsOutSchema,
  AppSettingsUpdateSchema,
  ErrorSchema,
} from "../schemas.js";
import { appSettingsToOut } from "../services/mappers.js";
import { getOrCreateSettings, updateSettings } from "../services/settingsService.js";

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
};

export default adminSettingsRoutes;
