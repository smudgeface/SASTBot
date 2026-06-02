import type { FastifyPluginAsync, FastifyReply } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

import { loadConfig } from "../config.js";
import {
  ChangePasswordBodySchema,
  ErrorSchema,
  LoginBodySchema,
  LogoutOutSchema,
  SetupBodySchema,
  SetupStatusOutSchema,
  UserOutSchema,
} from "../schemas.js";
import { getAuthBackend } from "../security/authBackend.js";
import {
  SESSION_COOKIE_NAME,
  SESSION_TTL_HOURS,
  createSession,
  revokeSession,
} from "../security/sessions.js";
import { countAdmins } from "../services/bootstrap.js";
import { userToOut } from "../services/mappers.js";
import { createFirstAdmin, SetupAlreadyCompleteError } from "../services/setupService.js";
import {
  changeOwnPassword,
  InvalidCurrentPasswordError,
  SamePasswordError,
} from "../services/userService.js";

/** Build the rate-limit config for auth endpoints from app config. */
function authRateLimit() {
  const cfg = loadConfig();
  return {
    max: cfg.authRateLimitMax,
    timeWindow: cfg.authRateLimitWindowMs,
    // Use the configured values, not a hardcoded key prefix, so the
    // window is per-IP and independent for each route.
    keyGenerator: (req: { ip: string }) => req.ip,
    // Emit standard Retry-After header so the frontend can render a countdown.
    addHeaders: {
      "x-ratelimit-limit": true,
      "x-ratelimit-remaining": true,
      "x-ratelimit-reset": true,
      "retry-after": true,
    },
  };
}

function cookieOptions(): {
  httpOnly: boolean;
  sameSite: "lax";
  secure: boolean;
  path: string;
  maxAge: number;
} {
  return {
    httpOnly: true,
    sameSite: "lax",
    secure: loadConfig().sessionCookieSecure,
    path: "/",
    maxAge: SESSION_TTL_HOURS * 60 * 60,
  };
}

function setSessionCookie(reply: FastifyReply, token: string): void {
  reply.setCookie(SESSION_COOKIE_NAME, token, cookieOptions());
}

function clearSessionCookie(reply: FastifyReply): void {
  const opts = cookieOptions();
  reply.clearCookie(SESSION_COOKIE_NAME, { path: opts.path });
}

const authRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.post(
    "/auth/login",
    {
      config: { rateLimit: authRateLimit() },
      schema: {
        tags: ["auth"],
        summary: "Log in with email + password",
        body: LoginBodySchema,
        response: {
          200: UserOutSchema,
          401: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      const { email, password } = req.body;
      const backend = getAuthBackend();
      const user = await backend.authenticate(email, password);
      if (!user) {
        return reply.code(401).send({ detail: "Invalid email or password" });
      }
      const { tokenStr } = await createSession(
        user.id,
        req.headers["user-agent"] ?? undefined,
        req.ip ?? undefined,
      );
      setSessionCookie(reply, tokenStr);
      return userToOut(user);
    },
  );

  typed.post(
    "/auth/logout",
    {
      config: { rateLimit: authRateLimit() },
      schema: {
        tags: ["auth"],
        summary: "Log out — revoke current session",
        response: { 200: LogoutOutSchema },
      },
    },
    async (req, reply) => {
      const token = req.cookies?.[SESSION_COOKIE_NAME];
      if (token) {
        await revokeSession(token);
      }
      clearSessionCookie(reply);
      return { ok: true };
    },
  );

  typed.get(
    "/auth/me",
    {
      schema: {
        tags: ["auth"],
        summary: "Get the current authenticated user",
        response: {
          200: UserOutSchema,
          401: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      if (!req.user) {
        return reply.code(401).send({ detail: "Not authenticated" });
      }
      return userToOut(req.user);
    },
  );

  typed.post(
    "/auth/change-password",
    {
      config: { rateLimit: authRateLimit() },
      preHandler: [app.authenticate],
      schema: {
        tags: ["auth"],
        summary: "Change your own password",
        body: ChangePasswordBodySchema,
        response: {
          200: UserOutSchema,
          400: ErrorSchema,
          401: ErrorSchema,
          429: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      if (!req.user) return reply.code(401).send({ detail: "Not authenticated" });
      const currentToken = req.cookies?.[SESSION_COOKIE_NAME];
      try {
        const updated = await changeOwnPassword(
          req.user.id,
          req.body.current_password,
          req.body.new_password,
          currentToken,
        );
        return userToOut(updated);
      } catch (err) {
        if (err instanceof InvalidCurrentPasswordError || err instanceof SamePasswordError) {
          return reply.code(400).send({ detail: err.message });
        }
        throw err;
      }
    },
  );

  // First-run setup ---------------------------------------------------------

  typed.get(
    "/auth/setup-status",
    {
      schema: {
        tags: ["auth"],
        summary: "Whether the instance still needs first-run admin setup",
        response: { 200: SetupStatusOutSchema },
      },
    },
    async () => {
      return { needs_setup: (await countAdmins()) === 0 };
    },
  );

  typed.post(
    "/auth/setup",
    {
      config: { rateLimit: authRateLimit() },
      schema: {
        tags: ["auth"],
        summary: "Create the first admin account (only while no admin exists)",
        body: SetupBodySchema,
        response: {
          200: UserOutSchema,
          409: ErrorSchema,
          429: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      // Fast pre-check; the authoritative guard is the advisory-locked re-check
      // inside createFirstAdmin (avoids a race between two concurrent calls).
      if ((await countAdmins()) > 0) {
        return reply.code(409).send({ detail: "Setup has already been completed." });
      }

      const { email, password } = req.body;
      let user;
      try {
        user = await createFirstAdmin(email, password);
      } catch (err) {
        if (err instanceof SetupAlreadyCompleteError) {
          return reply.code(409).send({ detail: err.message });
        }
        throw err;
      }

      // Auto-login: issue a session so the operator lands straight in the app.
      const { tokenStr } = await createSession(
        user.id,
        req.headers["user-agent"] ?? undefined,
        req.ip ?? undefined,
      );
      setSessionCookie(reply, tokenStr);
      return userToOut(user);
    },
  );
};

export default authRoutes;
