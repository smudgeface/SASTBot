/**
 * Unit tests for the privilege-ladder gates (M18).
 *
 * Verifies the `requireMember` / `requireAdmin` decorators enforce the
 * user < member < admin ladder:
 *   - requireMember: admin + member allowed; user 403; anon 401
 *   - requireAdmin:  admin allowed; member + user 403; anon 401
 *
 * We register the real auth plugin on a bare Fastify instance and invoke the
 * decorated functions directly with synthetic req/reply objects — this tests
 * the actual decorator logic without standing up the DB-backed request hook.
 */

import { randomBytes } from "node:crypto";

import Fastify, { type FastifyInstance } from "fastify";
import { beforeAll, describe, expect, it } from "vitest";

beforeAll(() => {
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
});

/** Minimal reply double that records the first status code sent. null = allowed. */
function makeReply() {
  const r: { statusCode: number | null; payload: unknown; code: (c: number) => typeof r; send: (p?: unknown) => Promise<typeof r> } = {
    statusCode: null,
    payload: null,
    code(c: number) {
      this.statusCode = c;
      return this;
    },
    async send(p?: unknown) {
      this.payload = p;
      return this;
    },
  };
  return r;
}

async function buildApp(): Promise<FastifyInstance> {
  const { default: authPlugin } = await import("../src/plugins/auth.js");
  const app = Fastify();
  await app.register(authPlugin);
  await app.ready();
  return app;
}

const reqWith = (role: string | null) =>
  ({ user: role === null ? null : { role } }) as unknown as Parameters<FastifyInstance["requireMember"]>[0];

describe("requireMember gate", () => {
  it("allows admin and member, rejects user (403) and anon (401)", async () => {
    const app = await buildApp();

    const admin = makeReply();
    await app.requireMember(reqWith("admin"), admin as never);
    expect(admin.statusCode).toBeNull();

    const member = makeReply();
    await app.requireMember(reqWith("member"), member as never);
    expect(member.statusCode).toBeNull();

    const user = makeReply();
    await app.requireMember(reqWith("user"), user as never);
    expect(user.statusCode).toBe(403);

    const anon = makeReply();
    await app.requireMember(reqWith(null), anon as never);
    expect(anon.statusCode).toBe(401);

    await app.close();
  });

  it("treats an unrecognized role as below member (fail closed → 403)", async () => {
    const app = await buildApp();
    const weird = makeReply();
    await app.requireMember(reqWith("wizard"), weird as never);
    expect(weird.statusCode).toBe(403);
    await app.close();
  });
});

describe("requireAdmin gate", () => {
  it("allows admin only; member and user get 403; anon 401", async () => {
    const app = await buildApp();

    const admin = makeReply();
    await app.requireAdmin(reqWith("admin"), admin as never);
    expect(admin.statusCode).toBeNull();

    const member = makeReply();
    await app.requireAdmin(reqWith("member"), member as never);
    expect(member.statusCode).toBe(403);

    const user = makeReply();
    await app.requireAdmin(reqWith("user"), user as never);
    expect(user.statusCode).toBe(403);

    const anon = makeReply();
    await app.requireAdmin(reqWith(null), anon as never);
    expect(anon.statusCode).toBe(401);

    await app.close();
  });
});
