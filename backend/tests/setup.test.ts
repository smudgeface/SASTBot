/**
 * Unit tests for first-run setup (M16).
 *
 * Covers:
 *   - decideSetupGate truth table (the requireAdminOrSetupWindow decision).
 *   - bootstrapIfEmpty: no dev password → org seeded, NO admin auto-created;
 *     dev password set → admin auto-created.
 *   - createFirstAdmin: creates the admin when none exists; refuses with
 *     SetupAlreadyCompleteError when an admin already exists (the advisory-locked
 *     re-check), and never writes in that case.
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
});

// Hoisted prisma mock — both bootstrap.ts and setupService.ts import it.
const h = vi.hoisted(() => {
  const tx = {
    $executeRawUnsafe: vi.fn().mockResolvedValue(undefined),
    user: { count: vi.fn(), create: vi.fn() },
    org: { findFirst: vi.fn(), create: vi.fn() },
  };
  const prisma = {
    org: { findFirst: vi.fn(), create: vi.fn() },
    user: { count: vi.fn(), create: vi.fn() },
    $transaction: vi.fn(async (cb: (t: typeof tx) => unknown) => cb(tx)),
  };
  return { tx, prisma };
});

vi.mock("../src/db.js", () => ({ prisma: h.prisma }));

afterEach(() => {
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// decideSetupGate
// ---------------------------------------------------------------------------

describe("decideSetupGate", () => {
  it("allows an admin regardless of admin count", async () => {
    const { decideSetupGate } = await import("../src/services/setupService.js");
    expect(decideSetupGate("admin", 5)).toBe("allow");
    expect(decideSetupGate("admin", 0)).toBe("allow");
  });

  it("forbids an authenticated non-admin", async () => {
    const { decideSetupGate } = await import("../src/services/setupService.js");
    expect(decideSetupGate("user", 0)).toBe("forbid");
    expect(decideSetupGate("user", 3)).toBe("forbid");
  });

  it("allows an unauthenticated caller only while zero admins exist", async () => {
    const { decideSetupGate } = await import("../src/services/setupService.js");
    expect(decideSetupGate(null, 0)).toBe("allow");
    expect(decideSetupGate(undefined, 0)).toBe("allow");
  });

  it("rejects an unauthenticated caller once an admin exists", async () => {
    const { decideSetupGate } = await import("../src/services/setupService.js");
    expect(decideSetupGate(null, 1)).toBe("unauthorized");
  });
});

// ---------------------------------------------------------------------------
// bootstrapIfEmpty
// ---------------------------------------------------------------------------

describe("bootstrapIfEmpty", () => {
  it("seeds the org but does NOT auto-create an admin when no dev password is set", async () => {
    delete process.env.BOOTSTRAP_ADMIN_PASSWORD;
    const { _resetConfigForTests } = await import("../src/config.js");
    _resetConfigForTests();

    h.prisma.org.findFirst.mockResolvedValue({ id: "org-1" });
    h.prisma.user.count.mockResolvedValue(0);

    const { bootstrapIfEmpty } = await import("../src/services/bootstrap.js");
    await bootstrapIfEmpty();

    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });

  it("auto-creates the admin when the dev password hatch is set", async () => {
    process.env.BOOTSTRAP_ADMIN_PASSWORD = "dev-password-123";
    const { _resetConfigForTests } = await import("../src/config.js");
    _resetConfigForTests();

    h.prisma.org.findFirst.mockResolvedValue({ id: "org-1" });
    h.prisma.user.count.mockResolvedValue(0);
    h.prisma.user.create.mockResolvedValue({ id: "u-1", role: "admin" });

    const { bootstrapIfEmpty } = await import("../src/services/bootstrap.js");
    await bootstrapIfEmpty();

    expect(h.prisma.user.create).toHaveBeenCalledOnce();
    const data = (h.prisma.user.create.mock.calls[0] as [{ data: Record<string, unknown> }])[0].data;
    expect(data.role).toBe("admin");
    expect(data.orgId).toBe("org-1");

    delete process.env.BOOTSTRAP_ADMIN_PASSWORD;
  });

  it("does nothing when an admin already exists", async () => {
    delete process.env.BOOTSTRAP_ADMIN_PASSWORD;
    const { _resetConfigForTests } = await import("../src/config.js");
    _resetConfigForTests();

    h.prisma.org.findFirst.mockResolvedValue({ id: "org-1" });
    h.prisma.user.count.mockResolvedValue(1);

    const { bootstrapIfEmpty } = await import("../src/services/bootstrap.js");
    await bootstrapIfEmpty();

    expect(h.prisma.user.create).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// createFirstAdmin
// ---------------------------------------------------------------------------

describe("createFirstAdmin", () => {
  it("creates the admin under an advisory lock when none exists", async () => {
    h.tx.user.count.mockResolvedValue(0);
    h.tx.org.findFirst.mockResolvedValue({ id: "org-1" });
    h.tx.user.create.mockResolvedValue({ id: "u-1", email: "a@b.com", role: "admin" });

    const { createFirstAdmin } = await import("../src/services/setupService.js");
    const user = await createFirstAdmin("A@B.com", "longenoughpassword");

    expect(user.role).toBe("admin");
    // Advisory lock was taken before the check/insert.
    expect(h.tx.$executeRawUnsafe).toHaveBeenCalledOnce();
    const data = (h.tx.user.create.mock.calls[0] as [{ data: Record<string, unknown> }])[0].data;
    expect(data.role).toBe("admin");
    expect(data.email).toBe("a@b.com"); // lowercased
    expect(typeof data.passwordHash).toBe("string");
    expect(data.passwordHash).not.toBe("longenoughpassword"); // hashed, not plaintext
  });

  it("refuses (and writes nothing) when an admin already exists", async () => {
    h.tx.user.count.mockResolvedValue(1);

    const { createFirstAdmin, SetupAlreadyCompleteError } = await import("../src/services/setupService.js");
    await expect(createFirstAdmin("a@b.com", "longenoughpassword")).rejects.toBeInstanceOf(
      SetupAlreadyCompleteError,
    );
    expect(h.tx.user.create).not.toHaveBeenCalled();
  });
});
