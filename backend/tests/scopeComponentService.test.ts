/**
 * Unit tests for ignoreScopeComponent / unignoreScopeComponent (M14).
 *
 * Strategy: mock prisma.$transaction and the underlying prisma queries so no
 * real DB is touched. Verify the cascade logic, skip conditions, and counts.
 */

import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

const SCOPE_ID = "aaaaaaaa-0000-0000-0000-000000000001";
const COMPONENT_ID = "cccccccc-0000-0000-0000-000000000003";

function makeFakeComponent(overrides: Record<string, unknown> = {}) {
  return {
    id: COMPONENT_ID,
    scopeId: SCOPE_ID,
    name: "lodash",
    dismissedStatus: "active",
    dismissedReason: null,
    dismissedAt: null,
    ...overrides,
  };
}

describe("ignoreScopeComponent", () => {
  it("updates component to ignored and returns cascade count", async () => {
    const { prisma } = await import("../src/db.js");

    // Mock $transaction to run the callback with a fake tx client.
    const fakeTx = {
      scopeComponent: {
        findUnique: vi.fn().mockResolvedValue(makeFakeComponent()),
        update: vi.fn().mockResolvedValue(makeFakeComponent({ dismissedStatus: "ignored" })),
      },
      // $executeRaw returns the number of affected rows.
      $executeRaw: vi.fn().mockResolvedValue(3),
    };
    vi.spyOn(prisma, "$transaction").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cb: any) => cb(fakeTx),
    );

    const { ignoreScopeComponent } = await import("../src/services/scopeComponentService.js");
    const result = await ignoreScopeComponent(COMPONENT_ID, "vendor no longer maintained");

    expect(fakeTx.scopeComponent.findUnique).toHaveBeenCalledWith({
      where: { id: COMPONENT_ID },
      select: { id: true, scopeId: true, name: true },
    });
    expect(fakeTx.scopeComponent.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: COMPONENT_ID },
        data: expect.objectContaining({
          dismissedStatus: "ignored",
          dismissedReason: "vendor no longer maintained",
        }),
      }),
    );
    expect(fakeTx.$executeRaw).toHaveBeenCalledOnce();
    expect(result.suppressed_sca_count).toBe(3);

    vi.restoreAllMocks();
  });

  it("throws ScopeComponentNotFoundError when component does not exist", async () => {
    const { prisma } = await import("../src/db.js");

    const fakeTx = {
      scopeComponent: {
        findUnique: vi.fn().mockResolvedValue(null),
        update: vi.fn(),
      },
      $executeRaw: vi.fn(),
    };
    vi.spyOn(prisma, "$transaction").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cb: any) => cb(fakeTx),
    );

    const { ignoreScopeComponent, ScopeComponentNotFoundError } = await import("../src/services/scopeComponentService.js");
    await expect(ignoreScopeComponent("nonexistent-id")).rejects.toBeInstanceOf(ScopeComponentNotFoundError);
    expect(fakeTx.scopeComponent.update).not.toHaveBeenCalled();
    expect(fakeTx.$executeRaw).not.toHaveBeenCalled();

    vi.restoreAllMocks();
  });

  it("passes null reason when no reason is provided", async () => {
    const { prisma } = await import("../src/db.js");

    const fakeTx = {
      scopeComponent: {
        findUnique: vi.fn().mockResolvedValue(makeFakeComponent()),
        update: vi.fn().mockResolvedValue(makeFakeComponent({ dismissedStatus: "ignored" })),
      },
      $executeRaw: vi.fn().mockResolvedValue(0),
    };
    vi.spyOn(prisma, "$transaction").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cb: any) => cb(fakeTx),
    );

    const { ignoreScopeComponent } = await import("../src/services/scopeComponentService.js");
    await ignoreScopeComponent(COMPONENT_ID);

    expect(fakeTx.scopeComponent.update).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({ dismissedReason: null }),
      }),
    );

    vi.restoreAllMocks();
  });
});

describe("unignoreScopeComponent", () => {
  it("restores component to active and returns restored count", async () => {
    const { prisma } = await import("../src/db.js");

    const fakeTx = {
      scopeComponent: {
        findUnique: vi.fn().mockResolvedValue(makeFakeComponent({ dismissedStatus: "ignored", dismissedReason: "outdated" })),
        update: vi.fn().mockResolvedValue(makeFakeComponent()),
      },
      $executeRaw: vi.fn().mockResolvedValue(2),
    };
    vi.spyOn(prisma, "$transaction").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cb: any) => cb(fakeTx),
    );

    const { unignoreScopeComponent } = await import("../src/services/scopeComponentService.js");
    const result = await unignoreScopeComponent(COMPONENT_ID);

    expect(fakeTx.scopeComponent.update).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: COMPONENT_ID },
        data: expect.objectContaining({
          dismissedStatus: "active",
          dismissedReason: null,
          dismissedAt: null,
        }),
      }),
    );
    // Should have called $executeRaw to restore sca_issues
    expect(fakeTx.$executeRaw).toHaveBeenCalledOnce();
    expect(result.restored_sca_count).toBe(2);

    vi.restoreAllMocks();
  });

  it("throws ScopeComponentNotFoundError when component does not exist", async () => {
    const { prisma } = await import("../src/db.js");

    const fakeTx = {
      scopeComponent: {
        findUnique: vi.fn().mockResolvedValue(null),
        update: vi.fn(),
      },
      $executeRaw: vi.fn(),
    };
    vi.spyOn(prisma, "$transaction").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (cb: any) => cb(fakeTx),
    );

    const { unignoreScopeComponent, ScopeComponentNotFoundError } = await import("../src/services/scopeComponentService.js");
    await expect(unignoreScopeComponent("nonexistent-id")).rejects.toBeInstanceOf(ScopeComponentNotFoundError);
    expect(fakeTx.scopeComponent.update).not.toHaveBeenCalled();

    vi.restoreAllMocks();
  });
});

describe("upsertScaIssueFromDetection — worker sticky cascade (M14)", () => {
  it("new issue for an ignored component lands as suppressed/component_ignored", async () => {
    const { prisma } = await import("../src/db.js");

    // Simulate a new issue (existing = null → isNew = true).
    vi.spyOn(prisma.scaIssue, "findUnique").mockResolvedValue(null);
    vi.spyOn(prisma.scaIssue, "upsert").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (async (args: any) => ({ ...args.create, id: "new-issue-id" })) as never,
    );

    const { upsertScaIssueFromDetection } = await import("../src/services/issueService.js");

    const ignoredNames = new Set(["lodash"]);
    await upsertScaIssueFromDetection(
      prisma,
      "scan-001",
      SCOPE_ID,
      null,
      { name: "lodash", version: "4.17.21", ecosystem: "npm", scope: null, isDevOnly: false },
      {
        osvId: "GHSA-test-1234",
        cveId: "CVE-2024-99999",
        findingType: "cve",
        severity: "high",
        cvssScore: 7.5,
        cvssVector: null,
        summary: "Test vuln",
        aliases: ["GHSA-test-1234"],
        activelyExploited: false,
        eolDate: null,
      },
      ignoredNames,
    );

    const upsertCall = (prisma.scaIssue.upsert as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(upsertCall.create.dismissedStatus).toBe("suppressed");
    expect(upsertCall.create.dismissedReason).toBe("component_ignored");
    expect(upsertCall.create.dismissedAt).toBeInstanceOf(Date);
    // Update path should NOT set dismissedStatus (operator triage preserved).
    expect(upsertCall.update.dismissedStatus).toBeUndefined();

    vi.restoreAllMocks();
  });

  it("new issue for a non-ignored component lands as pending", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scaIssue, "findUnique").mockResolvedValue(null);
    vi.spyOn(prisma.scaIssue, "upsert").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (async (args: any) => ({ ...args.create, id: "new-issue-id" })) as never,
    );

    const { upsertScaIssueFromDetection } = await import("../src/services/issueService.js");

    const ignoredNames = new Set(["other-package"]);
    await upsertScaIssueFromDetection(
      prisma,
      "scan-001",
      SCOPE_ID,
      null,
      { name: "axios", version: "1.6.0", ecosystem: "npm", scope: null, isDevOnly: false },
      {
        osvId: "GHSA-test-5678",
        cveId: "CVE-2024-11111",
        findingType: "cve",
        severity: "medium",
        cvssScore: 5.0,
        cvssVector: null,
        summary: "Test vuln 2",
        aliases: ["GHSA-test-5678"],
        activelyExploited: false,
        eolDate: null,
      },
      ignoredNames,
    );

    const upsertCall = (prisma.scaIssue.upsert as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(upsertCall.create.dismissedStatus).toBe("pending");
    expect(upsertCall.create.dismissedReason).toBeNull();
    expect(upsertCall.create.dismissedAt).toBeNull();

    vi.restoreAllMocks();
  });

  it("new issue when ignoredNames is omitted lands as pending (backward compat)", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scaIssue, "findUnique").mockResolvedValue(null);
    vi.spyOn(prisma.scaIssue, "upsert").mockImplementation(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      (async (args: any) => ({ ...args.create, id: "new-issue-id" })) as never,
    );

    const { upsertScaIssueFromDetection } = await import("../src/services/issueService.js");

    // No ignoredComponentNames passed.
    await upsertScaIssueFromDetection(
      prisma,
      "scan-001",
      SCOPE_ID,
      null,
      { name: "lodash", version: "4.17.21", ecosystem: "npm", scope: null, isDevOnly: false },
      {
        osvId: "GHSA-test-9999",
        cveId: "CVE-2024-22222",
        findingType: "cve",
        severity: "low",
        cvssScore: 3.0,
        cvssVector: null,
        summary: "Test vuln 3",
        aliases: [],
        activelyExploited: false,
        eolDate: null,
      },
    );

    const upsertCall = (prisma.scaIssue.upsert as ReturnType<typeof vi.fn>).mock.calls[0]![0];
    expect(upsertCall.create.dismissedStatus).toBe("pending");

    vi.restoreAllMocks();
  });
});

describe("materializeRecoveredComponents — lockstep SCA recovery", () => {
  it("carries a recovered component's open SCA issues forward so the sweep can't false-fix them", async () => {
    const { prisma } = await import("../src/db.js");
    const SCAN_RUN = "11111111-2222-4333-8444-555555555555";

    vi.spyOn(prisma.scopeComponent, "findMany").mockResolvedValueOnce([
      { scopeId: "scope-1", name: "cuda-runtime" },
      { scopeId: "scope-1", name: "OpenGL" },
    ] as Awaited<ReturnType<typeof prisma.scopeComponent.findMany>>);
    vi.spyOn(prisma.scopeComponent, "updateMany").mockResolvedValueOnce({ count: 2 });
    const scaUpdate = vi
      .spyOn(prisma.scaIssue, "updateMany")
      .mockResolvedValueOnce({ count: 59 });

    const { materializeRecoveredComponents } = await import("../src/services/scopeComponentService.js");
    const res = await materializeRecoveredComponents(["sc-a", "sc-b"], SCAN_RUN);

    expect(res).toEqual({ updated: 2, scaCarried: 59 });
    // The SCA carry-forward must target the recovered components by name,
    // only touch issues NOT already seen this run, and never overwrite a
    // terminal (operator/resolved) decision.
    const where = scaUpdate.mock.calls[0]![0].where as Record<string, unknown>;
    expect(where.scopeId).toBe("scope-1");
    expect(where.packageName).toEqual({ in: ["cuda-runtime", "OpenGL"] });
    expect(where.lastSeenScanRunId).toEqual({ not: SCAN_RUN });
    expect(where.dismissedStatus).toEqual({ notIn: ["fixed", "suppressed", "false_positive"] });
    const data = scaUpdate.mock.calls[0]![0].data as Record<string, unknown>;
    expect(data.lastSeenScanRunId).toBe(SCAN_RUN);

    vi.restoreAllMocks();
  });

  it("is a no-op when nothing was recovered", async () => {
    const { materializeRecoveredComponents } = await import("../src/services/scopeComponentService.js");
    const res = await materializeRecoveredComponents([], "scan-x");
    expect(res).toEqual({ updated: 0, scaCarried: 0 });
  });
});
