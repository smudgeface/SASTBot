/**
 * Unit tests for user management (M17, Phase 1) — the security-critical paths:
 *   - createUser sets mustChangePassword + rejects duplicate email
 *   - updateUser: self role/active change rejected; last-admin demote/disable rejected
 *   - deleteUser: self-delete rejected; last-admin delete rejected
 *   - changeOwnPassword: verifies current, rejects wrong/same, clears the flag
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
});

const h = vi.hoisted(() => {
  const tx = {
    $executeRawUnsafe: vi.fn().mockResolvedValue(undefined),
    user: { findFirst: vi.fn(), count: vi.fn(), update: vi.fn(), delete: vi.fn() },
  };
  const prisma = {
    user: {
      findUnique: vi.fn(),
      findFirst: vi.fn(),
      findMany: vi.fn(),
      count: vi.fn(),
      create: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
    session: { deleteMany: vi.fn().mockResolvedValue({ count: 0 }) },
    $transaction: vi.fn(async (cb: (t: typeof tx) => unknown) => cb(tx)),
  };
  return { tx, prisma };
});

vi.mock("../src/db.js", () => ({ prisma: h.prisma }));

afterEach(() => {
  vi.clearAllMocks();
});

const adminTarget = (over = {}) => ({
  id: "u-target",
  orgId: null,
  email: "t@x.com",
  name: null,
  role: "admin",
  isActive: true,
  mustChangePassword: false,
  passwordHash: "x",
  ...over,
});

describe("createUser", () => {
  it("creates with mustChangePassword=true and the given role", async () => {
    h.prisma.user.findUnique.mockResolvedValue(null);
    h.prisma.user.create.mockResolvedValue(adminTarget({ role: "user" }));
    const { createUser } = await import("../src/services/userService.js");
    await createUser({ orgId: null, input: { email: "New@X.com", role: "user", password: "longenoughpw1" } });
    const data = (h.prisma.user.create.mock.calls[0] as [{ data: Record<string, unknown> }])[0].data;
    expect(data.mustChangePassword).toBe(true);
    expect(data.role).toBe("user");
    expect(data.email).toBe("new@x.com");
    expect(data.passwordHash).not.toBe("longenoughpw1");
  });

  it("rejects a duplicate email", async () => {
    h.prisma.user.findUnique.mockResolvedValue(adminTarget());
    const { createUser, DuplicateEmailError } = await import("../src/services/userService.js");
    await expect(
      createUser({ orgId: null, input: { email: "t@x.com", role: "user", password: "longenoughpw1" } }),
    ).rejects.toBeInstanceOf(DuplicateEmailError);
    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });
});

describe("updateUser — guards", () => {
  it("rejects an ACTUAL change to your own role or active status", async () => {
    // Self target is an active admin; role->user and active->false are real changes.
    h.tx.user.findFirst.mockResolvedValue(adminTarget({ id: "me" }));
    const { updateUser, SelfActionError } = await import("../src/services/userService.js");
    await expect(updateUser("me", "me", null, { role: "user" })).rejects.toBeInstanceOf(SelfActionError);
    await expect(updateUser("me", "me", null, { is_active: false })).rejects.toBeInstanceOf(SelfActionError);
    expect(h.tx.user.update).not.toHaveBeenCalled();
  });

  it("allows editing your OWN name (name-only edit, no lock, no self-guard)", async () => {
    h.prisma.user.findFirst.mockResolvedValue(adminTarget({ id: "me" }));
    h.prisma.user.update.mockResolvedValue(adminTarget({ id: "me", name: "New Name" }));
    const { updateUser } = await import("../src/services/userService.js");
    const res = await updateUser("me", "me", null, { name: "New Name" });
    expect(res.name).toBe("New Name");
    expect(h.prisma.user.update).toHaveBeenCalledOnce();
    expect(h.tx.$executeRawUnsafe).not.toHaveBeenCalled(); // name-only skips the advisory lock
  });

  it("allows a self-edit that submits role/active UNCHANGED (e.g. saving a name)", async () => {
    h.tx.user.findFirst.mockResolvedValue(adminTarget({ id: "me", role: "admin", isActive: true }));
    h.tx.user.count.mockResolvedValue(1);
    h.tx.user.update.mockResolvedValue(adminTarget({ id: "me", name: "Renamed" }));
    const { updateUser } = await import("../src/services/userService.js");
    const res = await updateUser("me", "me", null, { name: "Renamed", role: "admin", is_active: true });
    expect(res.name).toBe("Renamed");
    expect(h.tx.user.update).toHaveBeenCalledOnce();
  });

  it("rejects demoting the LAST active admin", async () => {
    h.tx.user.findFirst.mockResolvedValue(adminTarget());
    h.tx.user.count.mockResolvedValue(0); // no other active admins
    const { updateUser, LastAdminError } = await import("../src/services/userService.js");
    await expect(updateUser("admin1", "u-target", null, { role: "user" })).rejects.toBeInstanceOf(LastAdminError);
    expect(h.tx.user.update).not.toHaveBeenCalled();
  });

  it("rejects disabling the LAST active admin", async () => {
    h.tx.user.findFirst.mockResolvedValue(adminTarget());
    h.tx.user.count.mockResolvedValue(0);
    const { updateUser, LastAdminError } = await import("../src/services/userService.js");
    await expect(updateUser("admin1", "u-target", null, { is_active: false })).rejects.toBeInstanceOf(LastAdminError);
  });

  it("allows demoting an admin when another active admin remains", async () => {
    h.tx.user.findFirst.mockResolvedValue(adminTarget());
    h.tx.user.count.mockResolvedValue(1); // one other active admin
    h.tx.user.update.mockResolvedValue(adminTarget({ role: "user" }));
    const { updateUser } = await import("../src/services/userService.js");
    const res = await updateUser("admin1", "u-target", null, { role: "user" });
    expect(res.role).toBe("user");
    expect(h.tx.user.update).toHaveBeenCalledOnce();
    expect(h.tx.$executeRawUnsafe).toHaveBeenCalledOnce(); // advisory lock taken
  });
});

describe("deleteUser — guards", () => {
  it("rejects deleting your own account", async () => {
    const { deleteUser, SelfActionError } = await import("../src/services/userService.js");
    await expect(deleteUser("me", "me", null)).rejects.toBeInstanceOf(SelfActionError);
  });

  it("rejects deleting the last active admin", async () => {
    h.tx.user.findFirst.mockResolvedValue(adminTarget());
    h.tx.user.count.mockResolvedValue(0);
    const { deleteUser, LastAdminError } = await import("../src/services/userService.js");
    await expect(deleteUser("admin1", "u-target", null)).rejects.toBeInstanceOf(LastAdminError);
    expect(h.tx.user.delete).not.toHaveBeenCalled();
  });
});

describe("changeOwnPassword", () => {
  it("rejects a wrong current password", async () => {
    const { hashPassword } = await import("../src/security/passwords.js");
    const hash = await hashPassword("the-real-current-pw");
    h.prisma.user.findUnique.mockResolvedValue(adminTarget({ id: "u1", passwordHash: hash }));
    const { changeOwnPassword, InvalidCurrentPasswordError } = await import("../src/services/userService.js");
    await expect(changeOwnPassword("u1", "WRONG", "brand-new-password")).rejects.toBeInstanceOf(
      InvalidCurrentPasswordError,
    );
    expect(h.prisma.user.update).not.toHaveBeenCalled();
  });

  it("rejects a new password equal to the current", async () => {
    const { hashPassword } = await import("../src/security/passwords.js");
    const hash = await hashPassword("samepassword12");
    h.prisma.user.findUnique.mockResolvedValue(adminTarget({ id: "u1", passwordHash: hash }));
    const { changeOwnPassword, SamePasswordError } = await import("../src/services/userService.js");
    await expect(changeOwnPassword("u1", "samepassword12", "samepassword12")).rejects.toBeInstanceOf(
      SamePasswordError,
    );
  });

  it("sets a new hash, clears mustChangePassword, and revokes other sessions", async () => {
    const { hashPassword } = await import("../src/security/passwords.js");
    const hash = await hashPassword("old-password-12");
    h.prisma.user.findUnique.mockResolvedValue(adminTarget({ id: "u1", passwordHash: hash, mustChangePassword: true }));
    h.prisma.user.update.mockResolvedValue(adminTarget({ id: "u1", mustChangePassword: false }));
    const { changeOwnPassword } = await import("../src/services/userService.js");
    await changeOwnPassword("u1", "old-password-12", "new-password-34", "current-token");
    const data = (h.prisma.user.update.mock.calls[0] as [{ data: Record<string, unknown> }])[0].data;
    expect(data.mustChangePassword).toBe(false);
    expect(typeof data.passwordHash).toBe("string");
    expect(data.passwordHash).not.toBe(hash);
    expect(h.prisma.session.deleteMany).toHaveBeenCalledOnce(); // other sessions revoked
  });
});
