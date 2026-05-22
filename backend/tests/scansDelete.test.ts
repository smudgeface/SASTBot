/**
 * Unit tests for DELETE /api/scans/:id (service layer).
 *
 * Strategy:
 *  - Mock prisma and deleteScanArtifacts so no real DB or filesystem access happens.
 *  - Test the deleteScanRun service function directly, covering:
 *      1. Happy path: non-latest scan deleted, artifacts cleaned up.
 *      2. 409 guard: scan IS scope.lastScanRunId → ScanIsCurrentLatestError.
 *      3. 404: unknown scan id → ScanRunNotFoundError.
 *      4. 400: scan in pending/running → ScanStillRunningError.
 *      5. Artifact-cleanup failure is swallowed (best-effort).
 */

import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.ARTIFACT_DIR ??= "/tmp/test-artifacts";
});

// ---------------------------------------------------------------------------
// Mock setup — must come before the module imports that trigger them
// ---------------------------------------------------------------------------

const mockFindFirst = vi.fn();
const mockFindUnique = vi.fn();
const mockDelete = vi.fn();

vi.mock("../src/db.js", () => ({
  prisma: {
    scanRun: {
      findFirst: mockFindFirst,
      delete: mockDelete,
    },
    scanScope: {
      findUnique: mockFindUnique,
    },
  },
}));

const mockDeleteScanArtifacts = vi.fn();

vi.mock("../src/services/artifactStore.js", () => ({
  sbomPathFor: (id: string) => `/fake/sbom/${id}.json`,
  sarifPathFor: (id: string) => `/fake/sarif/${id}.sarif.json`,
  deleteScanArtifacts: mockDeleteScanArtifacts,
  tryReadArtifact: vi.fn(),
}));

// getScanQueue is imported by scanService indirectly via cancelScanRun; mock
// so module load doesn't try to connect to Redis.
vi.mock("../src/queue/scanQueue.js", () => ({
  getScanQueue: () => ({ getJobs: vi.fn().mockResolvedValue([]) }),
}));

// ---------------------------------------------------------------------------
// Import under test — after mocks are registered
// ---------------------------------------------------------------------------

const {
  deleteScanRun,
  ScanRunNotFoundError,
  ScanIsCurrentLatestError,
  ScanStillRunningError,
} = await import("../src/services/scanService.js");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCAN_ID = "aaaaaaaa-0000-0000-0000-000000000001";
const OTHER_SCAN_ID = "aaaaaaaa-0000-0000-0000-000000000002";
const SCOPE_ID = "cccccccc-0000-0000-0000-000000000001";
const ORG_ID = "ffffffff-0000-0000-0000-000000000001";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("deleteScanRun", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("happy path — non-latest scan", () => {
    beforeEach(() => {
      // Scan exists, terminal status, scope's lastScanRunId is a DIFFERENT run
      mockFindFirst.mockResolvedValue({
        id: SCAN_ID,
        scopeId: SCOPE_ID,
        status: "success",
      });
      mockFindUnique.mockResolvedValue({
        id: SCOPE_ID,
        lastScanRunId: OTHER_SCAN_ID, // not the scan being deleted
      });
      mockDelete.mockResolvedValue({ id: SCAN_ID });
      mockDeleteScanArtifacts.mockResolvedValue(undefined);
    });

    it("deletes the DB row", async () => {
      await deleteScanRun(SCAN_ID, ORG_ID);
      expect(mockDelete).toHaveBeenCalledWith({ where: { id: SCAN_ID } });
    });

    it("calls deleteScanArtifacts with the correct scan id", async () => {
      await deleteScanRun(SCAN_ID, ORG_ID);
      expect(mockDeleteScanArtifacts).toHaveBeenCalledWith(SCAN_ID);
    });

    it("resolves without error", async () => {
      await expect(deleteScanRun(SCAN_ID, ORG_ID)).resolves.toBeUndefined();
    });

    it("scopes the lookup to the caller's orgId", async () => {
      await deleteScanRun(SCAN_ID, ORG_ID);
      expect(mockFindFirst).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: SCAN_ID, orgId: ORG_ID } }),
      );
    });
  });

  describe("409 — scan is scope.lastScanRunId", () => {
    beforeEach(() => {
      mockFindFirst.mockResolvedValue({
        id: SCAN_ID,
        scopeId: SCOPE_ID,
        status: "success",
      });
      // lastScanRunId points at the scan being deleted
      mockFindUnique.mockResolvedValue({
        id: SCOPE_ID,
        lastScanRunId: SCAN_ID,
      });
    });

    it("throws ScanIsCurrentLatestError", async () => {
      await expect(deleteScanRun(SCAN_ID, ORG_ID)).rejects.toBeInstanceOf(
        ScanIsCurrentLatestError,
      );
    });

    it("does NOT delete the DB row", async () => {
      await deleteScanRun(SCAN_ID, ORG_ID).catch(() => {});
      expect(mockDelete).not.toHaveBeenCalled();
    });

    it("does NOT call deleteScanArtifacts", async () => {
      await deleteScanRun(SCAN_ID, ORG_ID).catch(() => {});
      expect(mockDeleteScanArtifacts).not.toHaveBeenCalled();
    });

    it("error carries scopeId and scanRunId", async () => {
      const err = await deleteScanRun(SCAN_ID, ORG_ID).catch((e) => e);
      expect(err).toBeInstanceOf(ScanIsCurrentLatestError);
      expect((err as ScanIsCurrentLatestError).scopeId).toBe(SCOPE_ID);
      expect((err as ScanIsCurrentLatestError).scanRunId).toBe(SCAN_ID);
    });
  });

  describe("404 — scan not found", () => {
    beforeEach(() => {
      mockFindFirst.mockResolvedValue(null);
    });

    it("throws ScanRunNotFoundError", async () => {
      await expect(deleteScanRun("does-not-exist", ORG_ID)).rejects.toBeInstanceOf(
        ScanRunNotFoundError,
      );
    });

    it("does NOT delete or clean up artifacts", async () => {
      await deleteScanRun("does-not-exist", ORG_ID).catch(() => {});
      expect(mockDelete).not.toHaveBeenCalled();
      expect(mockDeleteScanArtifacts).not.toHaveBeenCalled();
    });
  });

  describe("400 — scan still running/pending", () => {
    for (const status of ["pending", "running"] as const) {
      it(`throws ScanStillRunningError when status is '${status}'`, async () => {
        mockFindFirst.mockResolvedValue({
          id: SCAN_ID,
          scopeId: SCOPE_ID,
          status,
        });
        const err = await deleteScanRun(SCAN_ID, ORG_ID).catch((e) => e);
        expect(err).toBeInstanceOf(ScanStillRunningError);
        expect((err as ScanStillRunningError).status).toBe(status);
      });

      it(`does NOT delete the DB row when status is '${status}'`, async () => {
        mockFindFirst.mockResolvedValue({
          id: SCAN_ID,
          scopeId: SCOPE_ID,
          status,
        });
        await deleteScanRun(SCAN_ID, ORG_ID).catch(() => {});
        expect(mockDelete).not.toHaveBeenCalled();
      });
    }
  });

  describe("artifact-cleanup failure is swallowed (best-effort)", () => {
    beforeEach(() => {
      mockFindFirst.mockResolvedValue({
        id: SCAN_ID,
        scopeId: SCOPE_ID,
        status: "failed",
      });
      mockFindUnique.mockResolvedValue({
        id: SCOPE_ID,
        lastScanRunId: OTHER_SCAN_ID,
      });
      mockDelete.mockResolvedValue({ id: SCAN_ID });
      // Artifact cleanup throws a filesystem error
      mockDeleteScanArtifacts.mockRejectedValue(new Error("EACCES: permission denied"));
    });

    it("resolves successfully even when deleteScanArtifacts rejects", async () => {
      await expect(deleteScanRun(SCAN_ID, ORG_ID)).resolves.toBeUndefined();
    });

    it("still deleted the DB row before the artifact error", async () => {
      await deleteScanRun(SCAN_ID, ORG_ID);
      expect(mockDelete).toHaveBeenCalledWith({ where: { id: SCAN_ID } });
    });
  });
});
