/**
 * Admin user management (M17 — local user management, Phase 1).
 *
 * All routes are admin-only. Two invariants are enforced in the service layer
 * (advisory-locked): never leave zero active admins, and an admin can't lock
 * themselves out (no self role-change / disable / delete).
 */

import type { FastifyPluginAsync } from "fastify";
import type { ZodTypeProvider } from "fastify-type-provider-zod";
import { z } from "zod";

import {
  CreateUserBodySchema,
  ErrorSchema,
  IdParamsSchema,
  ResetPasswordBodySchema,
  UpdateUserBodySchema,
  UserAdminOutSchema,
} from "../schemas.js";
import { userToAdminOut } from "../services/mappers.js";
import {
  createUser,
  deleteUser,
  DuplicateEmailError,
  LastAdminError,
  listUsers,
  resetUserPassword,
  SelfActionError,
  updateUser,
  UserNotFoundError,
} from "../services/userService.js";

const adminUsersRoutes: FastifyPluginAsync = async (app) => {
  const typed = app.withTypeProvider<ZodTypeProvider>();

  typed.get(
    "/admin/users",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "users"],
        summary: "List user accounts",
        response: { 200: z.array(UserAdminOutSchema), 401: ErrorSchema, 403: ErrorSchema },
      },
    },
    async (req) => {
      const users = await listUsers(req.user?.orgId ?? null);
      return users.map(userToAdminOut);
    },
  );

  typed.post(
    "/admin/users",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "users"],
        summary: "Create a user (admin sets a one-time password; user must change it on first login)",
        body: CreateUserBodySchema,
        response: {
          201: UserAdminOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const user = await createUser({ orgId: req.user?.orgId ?? null, input: req.body });
        return reply.code(201).send(userToAdminOut(user));
      } catch (err) {
        if (err instanceof DuplicateEmailError) {
          return reply.code(409).send({ detail: err.message });
        }
        throw err;
      }
    },
  );

  typed.patch(
    "/admin/users/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "users"],
        summary: "Update a user's name, role, or active status",
        params: IdParamsSchema,
        body: UpdateUserBodySchema,
        response: {
          200: UserAdminOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const user = await updateUser(
          req.user!.id,
          req.params.id,
          req.user?.orgId ?? null,
          req.body,
        );
        return userToAdminOut(user);
      } catch (err) {
        if (err instanceof UserNotFoundError) return reply.code(404).send({ detail: err.message });
        if (err instanceof LastAdminError || err instanceof SelfActionError) {
          return reply.code(409).send({ detail: err.message });
        }
        throw err;
      }
    },
  );

  typed.post(
    "/admin/users/:id/reset-password",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "users"],
        summary: "Set a one-time password for a user (forces a change on their next login)",
        params: IdParamsSchema,
        body: ResetPasswordBodySchema,
        response: {
          200: UserAdminOutSchema,
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        const user = await resetUserPassword(
          req.params.id,
          req.user?.orgId ?? null,
          req.body.password,
        );
        return userToAdminOut(user);
      } catch (err) {
        if (err instanceof UserNotFoundError) return reply.code(404).send({ detail: err.message });
        throw err;
      }
    },
  );

  typed.delete(
    "/admin/users/:id",
    {
      preHandler: [app.requireAdmin],
      schema: {
        tags: ["admin", "users"],
        summary: "Delete a user account",
        params: IdParamsSchema,
        response: {
          200: z.object({ ok: z.boolean() }),
          401: ErrorSchema,
          403: ErrorSchema,
          404: ErrorSchema,
          409: ErrorSchema,
        },
      },
    },
    async (req, reply) => {
      try {
        await deleteUser(req.user!.id, req.params.id, req.user?.orgId ?? null);
        return { ok: true };
      } catch (err) {
        if (err instanceof UserNotFoundError) return reply.code(404).send({ detail: err.message });
        if (err instanceof LastAdminError || err instanceof SelfActionError) {
          return reply.code(409).send({ detail: err.message });
        }
        throw err;
      }
    },
  );
};

export default adminUsersRoutes;
