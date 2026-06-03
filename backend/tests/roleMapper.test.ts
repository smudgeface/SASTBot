/**
 * Regression tests for the user mappers (M18).
 *
 * Before M18, `userToOut`/`userToAdminOut` collapsed any non-admin role to
 * "user", which would mislabel a member AND break `/auth/me` response
 * serialization once the role enum gained "member". These assert the real role
 * is passed through and that an unrecognized DB value fails closed to "user".
 */

import type { User } from "@prisma/client";

import { describe, expect, it } from "vitest";

import { userToAdminOut, userToOut } from "../src/services/mappers.js";

const baseUser = (over: Partial<User> = {}): User =>
  ({
    id: "u-1",
    orgId: "org-1",
    email: "m@x.com",
    name: "M",
    role: "member",
    isActive: true,
    mustChangePassword: false,
    passwordHash: "x",
    lastLoginAt: null,
    createdAt: new Date("2026-06-02T00:00:00.000Z"),
    ...over,
  }) as User;

describe("userToOut", () => {
  it.each(["admin", "member", "user"] as const)("round-trips role %s", (role) => {
    expect(userToOut(baseUser({ role })).role).toBe(role);
  });

  it("coerces an unrecognized role to user (fail closed)", () => {
    expect(userToOut(baseUser({ role: "wizard" })).role).toBe("user");
  });
});

describe("userToAdminOut", () => {
  it.each(["admin", "member", "user"] as const)("round-trips role %s", (role) => {
    expect(userToAdminOut(baseUser({ role })).role).toBe(role);
  });

  it("coerces an unrecognized role to user (fail closed)", () => {
    expect(userToAdminOut(baseUser({ role: "" })).role).toBe("user");
  });
});
