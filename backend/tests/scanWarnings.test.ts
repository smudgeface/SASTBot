/**
 * Unit tests for hasErrorWarnings in backend/src/services/scanWarnings.ts.
 *
 * Covers:
 *   (a) No warnings → false.
 *   (b) Only info-severity warnings → false.
 *   (c) An error-severity warning → true.
 *   (d) Mix of info + error → true.
 */

import { randomBytes, randomUUID } from "node:crypto";

import { beforeAll, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Prisma mock
// ---------------------------------------------------------------------------

const mockScanRunFindUnique = vi.fn();

vi.mock("../src/db.js", () => ({
  prisma: {
    scanRun: {
      findUnique: mockScanRunFindUnique,
    },
  },
}));

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

type ScanWarning = { code: string; message: string; severity: "info" | "error" };

function makeWarning(severity: "info" | "error", code = "test_code"): ScanWarning {
  return { code, message: `test warning (${severity})`, severity };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("hasErrorWarnings", () => {
  it("returns false when the scan run has no warnings (null/undefined)", async () => {
    mockScanRunFindUnique.mockResolvedValue({ warnings: null });

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    expect(await hasErrorWarnings(randomUUID())).toBe(false);

    vi.clearAllMocks();
  });

  it("returns false when the scan run has an empty warnings array", async () => {
    mockScanRunFindUnique.mockResolvedValue({ warnings: [] });

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    expect(await hasErrorWarnings(randomUUID())).toBe(false);

    vi.clearAllMocks();
  });

  it("returns false when all warnings are info severity", async () => {
    mockScanRunFindUnique.mockResolvedValue({
      warnings: [
        makeWarning("info", "cdxgen_slow"),
        makeWarning("info", "osv_rate_limited"),
      ],
    });

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    expect(await hasErrorWarnings(randomUUID())).toBe(false);

    vi.clearAllMocks();
  });

  it("returns true when there is exactly one error-severity warning", async () => {
    mockScanRunFindUnique.mockResolvedValue({
      warnings: [makeWarning("error", "clone_failed")],
    });

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    expect(await hasErrorWarnings(randomUUID())).toBe(true);

    vi.clearAllMocks();
  });

  it("returns true when there is a mix of info and error warnings", async () => {
    mockScanRunFindUnique.mockResolvedValue({
      warnings: [
        makeWarning("info", "cdxgen_slow"),
        makeWarning("error", "osv_all_failed"),
        makeWarning("info", "sbom_large"),
      ],
    });

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    expect(await hasErrorWarnings(randomUUID())).toBe(true);

    vi.clearAllMocks();
  });

  it("returns false when the scan run row does not exist (findUnique returns null)", async () => {
    mockScanRunFindUnique.mockResolvedValue(null);

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    expect(await hasErrorWarnings(randomUUID())).toBe(false);

    vi.clearAllMocks();
  });

  it("queries prisma with the correct scanRunId", async () => {
    const scanRunId = randomUUID();
    mockScanRunFindUnique.mockResolvedValue({ warnings: [] });

    const { hasErrorWarnings } = await import("../src/services/scanWarnings.js");
    await hasErrorWarnings(scanRunId);

    expect(mockScanRunFindUnique).toHaveBeenCalledWith({
      where: { id: scanRunId },
      select: { warnings: true },
    });

    vi.clearAllMocks();
  });
});
