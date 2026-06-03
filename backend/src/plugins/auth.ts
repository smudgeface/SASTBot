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
    requireMember(req: FastifyRequest, reply: FastifyReply): Promise<void>;
    requireAdmin(req: FastifyRequest, reply: FastifyReply): Promise<void>;
    requireAdminOrSetupWindow(req: FastifyRequest, reply: FastifyReply): Promise<void>;
  }
}

/**
 * Auth plugin. Reads `sastbot_session` cookie on every request and decorates
 * `req.user` with the resolved User (or null). Route modules opt into
 * authentication via the exposed `authenticate` / `requireAdmin` preHandlers.
 */
/**
 * Privilege ladder: user < member < admin. Any unrecognized DB role value
 * (the column is free TEXT) ranks as the least-privileged `user` — fail closed.
 */
const ROLE_RANK: Record<string, number> = { user: 0, member: 1, admin: 2 };
function rankOf(role: string | null | undefined): number {
  if (role == null) return -1;
  return ROLE_RANK[role] ?? 0;
}

const authPlugin: FastifyPluginAsync = async (app: FastifyInstance) => {
  app.decorateRequest("user", null);

  app.addHook("preHandler", async (req, reply) => {
    const cookieToken = req.cookies?.[SESSION_COOKIE_NAME];
    req.user = cookieToken ? await getUserFromToken(cookieToken) : null;

    // Forced-password-change gate: a user on a one-time admin-set password may
    // only reach the change-password / logout / me endpoints until they change
    // it. Scoped to /api/* domain routes (root utility routes like /healthz are
    // never gated). Enforcement lives here; the SPA also reads must_change_password
    // off /auth/me to redirect proactively.
    if (req.user?.mustChangePassword) {
      const path = req.url.split("?")[0];
      const allowed =
        path === "/api/auth/change-password" ||
        path === "/api/auth/logout" ||
        path === "/api/auth/me";
      if (path.startsWith("/api/") && !allowed) {
        await reply.code(403).send({
          detail: "You must change your password before continuing.",
          code: "password_change_required",
        });
      }
    }
  });

  app.decorate(
    "authenticate",
    async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
      if (!req.user) {
        await reply.code(401).send({ detail: "Not authenticated" });
      }
    },
  );

  // Requires at least `member` rank (member or admin). Gates the finding /
  // Jira / component-state mutations — the triage queue work a security-tasked
  // developer does. Config (repos, credentials, settings, users, backup, key
  // rotation) and scan control stay on requireAdmin.
  app.decorate(
    "requireMember",
    async (req: FastifyRequest, reply: FastifyReply): Promise<void> => {
      if (!req.user) {
        await reply.code(401).send({ detail: "Not authenticated" });
        return;
      }
      if (rankOf(req.user.role) < ROLE_RANK.member) {
        await reply.code(403).send({ detail: "Member privileges required" });
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
      if (rankOf(req.user.role) < ROLE_RANK.admin) {
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
