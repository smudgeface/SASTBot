import type { User } from "@prisma/client";
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";

import { SESSION_COOKIE_NAME, getUserFromToken } from "../security/sessions.js";

declare module "fastify" {
  interface FastifyRequest {
    user: User | null;
  }
  interface FastifyInstance {
    authenticate(req: FastifyRequest, reply: FastifyReply): Promise<void>;
    requireAdmin(req: FastifyRequest, reply: FastifyReply): Promise<void>;
  }
}

/**
 * Auth plugin. Reads `sastbot_session` cookie on every request and decorates
 * `req.user` with the resolved User (or null). Route modules opt into
 * authentication via the exposed `authenticate` / `requireAdmin` preHandlers.
 */
const authPlugin: FastifyPluginAsync = async (app: FastifyInstance) => {
  app.decorateRequest("user", null);

  app.addHook("preHandler", async (req) => {
    const cookieToken = req.cookies?.[SESSION_COOKIE_NAME];
    if (!cookieToken) {
      req.user = null;
      return;
    }
    req.user = await getUserFromToken(cookieToken);
  });

  app.decorate(
    "authenticate",
    async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
      if (!req.user) {
        await reply.code(401).send({ detail: "Not authenticated" });
      }
    },
  );

  app.decorate(
    "requireAdmin",
    async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
      if (!req.user) {
        await reply.code(401).send({ detail: "Not authenticated" });
        return;
      }
      if (req.user.role !== "admin") {
        await reply.code(403).send({ detail: "Admin privileges required" });
      }
    },
  );
};

export default fp(authPlugin, { name: "sastbot-auth" });
