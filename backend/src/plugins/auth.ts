import type { User } from "@prisma/client";
import type { FastifyInstance, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";
import fp from "fastify-plugin";

import { SESSION_COOKIE_NAME, getUserFromToken } from "../security/sessions.js";
import { countAdmins } from "../services/bootstrap.js";
import { decideSetupGate } from "../services/setupService.js";

declare module "fastify" {
  interface FastifyRequest {
    user: User | null;
  }
  interface FastifyInstance {
    authenticate(req: FastifyRequest, reply: FastifyReply): Promise<void>;
    requireAdmin(req: FastifyRequest, reply: FastifyReply): Promise<void>;
    requireAdminOrSetupWindow(req: FastifyRequest, reply: FastifyReply): Promise<void>;
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

  // Allow an authenticated admin OR — during the first-run setup window only
  // (zero admins exist) — an unauthenticated caller. This lets a brand-new
  // instance restore a backup before any admin exists, so an operator can
  // migrate an existing installation without first creating a throwaway account.
  // The window slams shut the moment the first admin exists (created by the
  // setup form or carried in by the restored dump), so this is exactly the same
  // trust window as the unauthenticated `POST /auth/setup` itself.
  app.decorate(
    "requireAdminOrSetupWindow",
    async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
      const role = req.user?.role ?? null;
      // The admin count is only consulted for unauthenticated callers; pass a
      // harmless placeholder otherwise to avoid an extra query (decideSetupGate
      // ignores the count when a role is present).
      const decision = decideSetupGate(role, role ? 1 : await countAdmins());
      if (decision === "allow") return;
      if (decision === "forbid") {
        await reply.code(403).send({ detail: "Admin privileges required" });
        return;
      }
      await reply.code(401).send({ detail: "Not authenticated" });
    },
  );
};

export default fp(authPlugin, { name: "sastbot-auth" });
