/**
 * Unit tests for repoService.updateRepo — specifically the post-update
 * retain_clone purge transition (M9 followups adjacent gap, 2026-05-23).
 *
 * deleteRepo was fixed in v0.9.6 (Issue 12). The same kind of disk-leak
 * exists for the operator-flow where someone toggles retain_clone off via
 * PUT /api/admin/repos/:id — the DB row updates, but the clone path stays.
 * The fix is the same one-liner: call purgeRepoCache after the transaction
 * commits.
 *
 * These tests verify:
 *  - true → false transition triggers purgeRepoCache
 *  - no change (true → true, false → false, or retain_clone omitted) is a no-op
 *  - true → true (idempotent re-save) does not purge
 *  - purge failure does not throw (best-effort posture)
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Mocks (registered before importing the module under test)
// ---------------------------------------------------------------------------

const mockRepoFindFirst = vi.fn();
const mockRepoUpdate = vi.fn();
const mockScanScopeUpsert = vi.fn();
const mockScanScopeUpdateMany = vi.fn();

// $transaction implementation: call the callback with a tx-shaped stub.
const mockTransaction = vi.fn((cb: (tx: TxStub) => Promise<unknown>) =>
  cb({
    repo: { update: mockRepoUpdate },
    scanScope: { upsert: mockScanScopeUpsert, updateMany: mockScanScopeUpdateMany },
  }),
);

interface TxStub {
  repo: { update: typeof mockRepoUpdate };
  scanScope: {
    upsert: typeof mockScanScopeUpsert;
    updateMany: typeof mockScanScopeUpdateMany;
  };
}

vi.mock("../src/db.js", () => ({
  prisma: {
    repo: {
      findFirst: mockRepoFindFirst,
    },
    $transaction: mockTransaction,
  },
}));

const mockPurge = vi.fn();

vi.mock("../src/services/repoCache.js", () => ({
  purge: mockPurge,
}));

// Side-effects from imports — kept inert in tests.
vi.mock("../src/services/artifactStore.js", () => ({
  deleteScanArtifacts: vi.fn(),
}));

vi.mock("../src/services/credentialService.js", () => ({
  createCredential: vi.fn(),
}));

const { updateRepo, RepoNotFoundError } = await import("../src/services/repoService.js");

// ---------------------------------------------------------------------------

const REPO_ID = "11111111-0000-0000-0000-000000000001";
const ORG_ID = "ffffffff-0000-0000-0000-000000000001";

function baseRepo(overrides: Record<string, unknown> = {}) {
  return {
    id: REPO_ID,
    orgId: ORG_ID,
    name: "demo",
    url: "https://example.org/demo.git",
    protocol: "https",
    credentialId: null,
    defaultBranch: "main",
    scanPaths: ["/"],
    ignorePaths: [],
    analysisTypes: ["sca"],
    scheduleCron: null,
    sourceUrlTemplate: null,
    isActive: true,
    retainClone: true,
    reachabilityEnabled: true,
    includeDevDeps: false,
    ...overrides,
  };
}

describe("updateRepo retain_clone transition", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  beforeEach(() => {
    mockRepoFindFirst.mockResolvedValue(baseRepo({ retainClone: true }));
    mockRepoUpdate.mockResolvedValue(baseRepo({ retainClone: false }));
    mockPurge.mockResolvedValue(undefined);
  });

  it("calls purgeRepoCache when retain_clone transitions true → false", async () => {
    await updateRepo(REPO_ID, { retain_clone: false }, ORG_ID, null);

    expect(mockPurge).toHaveBeenCalledTimes(1);
    expect(mockPurge).toHaveBeenCalledWith(REPO_ID);
  });

  it("does not purge when retain_clone is unchanged (true → true)", async () => {
    await updateRepo(REPO_ID, { retain_clone: true }, ORG_ID, null);

    expect(mockPurge).not.toHaveBeenCalled();
  });

  it("does not purge when retain_clone is omitted from the update", async () => {
    await updateRepo(REPO_ID, { name: "renamed" }, ORG_ID, null);

    expect(mockPurge).not.toHaveBeenCalled();
  });

  it("does not purge on false → false (no transition)", async () => {
    mockRepoFindFirst.mockResolvedValueOnce(baseRepo({ retainClone: false }));

    await updateRepo(REPO_ID, { retain_clone: false }, ORG_ID, null);

    expect(mockPurge).not.toHaveBeenCalled();
  });

  it("does not purge on false → true (enabling, not disabling)", async () => {
    mockRepoFindFirst.mockResolvedValueOnce(baseRepo({ retainClone: false }));
    mockRepoUpdate.mockResolvedValueOnce(baseRepo({ retainClone: true }));

    await updateRepo(REPO_ID, { retain_clone: true }, ORG_ID, null);

    expect(mockPurge).not.toHaveBeenCalled();
  });

  it("does not throw when purgeRepoCache fails (best-effort posture)", async () => {
    mockPurge.mockRejectedValueOnce(new Error("EBUSY"));

    await expect(
      updateRepo(REPO_ID, { retain_clone: false }, ORG_ID, null),
    ).resolves.toBeDefined();

    expect(mockPurge).toHaveBeenCalledTimes(1);
  });

  it("throws RepoNotFoundError without touching the cache when the repo is missing", async () => {
    mockRepoFindFirst.mockResolvedValueOnce(null);

    await expect(
      updateRepo(REPO_ID, { retain_clone: false }, ORG_ID, null),
    ).rejects.toBeInstanceOf(RepoNotFoundError);

    expect(mockPurge).not.toHaveBeenCalled();
    expect(mockRepoUpdate).not.toHaveBeenCalled();
  });
});
