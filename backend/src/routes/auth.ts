import type { FastifyPluginAsync, FastifyReply } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";

import { loadConfig } from "../config.js";
import {
  ErrorSchema,
  LoginBodySchema,
  LogoutOutSchema,
  UserOutSchema,
} from "../schemas.js";
import { getAuthBackend } from "../security/authBackend.js";
import {
  SESSION_COOKIE_NAME,
  SESSION_TTL_HOURS,
  createSession,
  revokeSession,
} from "../security/sessions.js";
import { userToOut } from "../services/mappers.js";

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
};

export default authRoutes;
