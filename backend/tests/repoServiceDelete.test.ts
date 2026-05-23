/**
 * Unit tests for repoService.deleteRepo — specifically the post-delete
 * cleanup side effects.
 *
 * Strategy: mock prisma, deleteScanArtifacts, and purgeRepoCache. Call
 * deleteRepo and assert each cleanup function is invoked once with the
 * right id. Mirrors the scansDelete.test.ts mocking pattern.
 *
 * The behaviour under test is the M9 closure-gate Phase 6.3 finding
 * (Issue 12 in M9_POST_B_FOLLOWUPS.md): deleteRepo previously dropped
 * the DB row + per-scan artifact files but left
 * /app/clones/<repoId> on disk forever.
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Mocks (must be registered before importing the module under test)
// ---------------------------------------------------------------------------

const mockRepoFindFirst = vi.fn();
const mockRepoDelete = vi.fn();
const mockScanRunFindMany = vi.fn();

vi.mock("../src/db.js", () => ({
  prisma: {
    repo: {
      findFirst: mockRepoFindFirst,
      delete: mockRepoDelete,
    },
    scanRun: {
      findMany: mockScanRunFindMany,
    },
  },
}));

const mockDeleteScanArtifacts = vi.fn();

vi.mock("../src/services/artifactStore.js", () => ({
  deleteScanArtifacts: mockDeleteScanArtifacts,
}));

const mockPurge = vi.fn();

vi.mock("../src/services/repoCache.js", () => ({
  purge: mockPurge,
}));

// credentialService is imported at the top of repoService for the createRepo
// path — mock to keep module-load side-effect free.
vi.mock("../src/services/credentialService.js", () => ({
  createCredential: vi.fn(),
}));

const { deleteRepo, RepoNotFoundError } = await import("../src/services/repoService.js");

// ---------------------------------------------------------------------------

const REPO_ID = "11111111-0000-0000-0000-000000000001";
const ORG_ID = "ffffffff-0000-0000-0000-000000000001";
const SCAN_A = "22222222-0000-0000-0000-00000000000a";
const SCAN_B = "22222222-0000-0000-0000-00000000000b";

describe("deleteRepo cleanup", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  beforeEach(() => {
    mockRepoFindFirst.mockResolvedValue({ id: REPO_ID, orgId: ORG_ID });
    mockScanRunFindMany.mockResolvedValue([{ id: SCAN_A }, { id: SCAN_B }]);
    mockRepoDelete.mockResolvedValue({ id: REPO_ID });
    mockDeleteScanArtifacts.mockResolvedValue(undefined);
    mockPurge.mockResolvedValue(undefined);
  });

  it("calls purgeRepoCache(repoId) once after deleting the row", async () => {
    await deleteRepo(REPO_ID, ORG_ID);

    expect(mockRepoDelete).toHaveBeenCalledTimes(1);
    expect(mockPurge).toHaveBeenCalledTimes(1);
    expect(mockPurge).toHaveBeenCalledWith(REPO_ID);
  });

  it("removes per-scan artifact files for every cascaded scan run", async () => {
    await deleteRepo(REPO_ID, ORG_ID);

    expect(mockDeleteScanArtifacts).toHaveBeenCalledTimes(2);
    expect(mockDeleteScanArtifacts).toHaveBeenCalledWith(SCAN_A);
    expect(mockDeleteScanArtifacts).toHaveBeenCalledWith(SCAN_B);
  });

  it("does not throw when purgeRepoCache fails (best-effort)", async () => {
    mockPurge.mockRejectedValueOnce(new Error("EBUSY"));

    await expect(deleteRepo(REPO_ID, ORG_ID)).resolves.toBeUndefined();
    expect(mockRepoDelete).toHaveBeenCalledTimes(1);
  });

  it("throws RepoNotFoundError when the repo does not exist", async () => {
    mockRepoFindFirst.mockResolvedValueOnce(null);

    await expect(deleteRepo(REPO_ID, ORG_ID)).rejects.toBeInstanceOf(RepoNotFoundError);
    expect(mockRepoDelete).not.toHaveBeenCalled();
    expect(mockPurge).not.toHaveBeenCalled();
  });
});
