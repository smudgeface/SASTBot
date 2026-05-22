/**
 * Unit tests for emitSbomArtifact (M9 Stream B1).
 *
 * Strategy:
 *  - Mock prisma so the function never touches a real DB.
 *  - Override ARTIFACT_DIR to a tmp directory per test.
 *  - 10 components → assert file exists, parses, 10 components, deterministic.
 *  - Empty scan → assert { written: false } and no file written.
 *  - Round-trip byte equality: calling twice with same data yields identical bytes.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Set required env vars before side-effectful modules load.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Tmp-dir setup / teardown
// ---------------------------------------------------------------------------

let tmpDir: string;
let originalArtifactDir: string | undefined;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-sbom-emit-"));
  originalArtifactDir = process.env["ARTIFACT_DIR"];
  process.env["ARTIFACT_DIR"] = tmpDir;
});

afterEach(async () => {
  if (originalArtifactDir === undefined) {
    delete process.env["ARTIFACT_DIR"];
  } else {
    process.env["ARTIFACT_DIR"] = originalArtifactDir;
  }
  await fs.rm(tmpDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

const SCAN_RUN_ID = "aaaaaaaa-emit-0000-0000-000000000001";
const BASE_DATE = new Date("2026-05-22T10:00:00Z");

/** Build N sbom_components rows with stable, deterministic values. */
function makeSbomComponents(scanRunId: string, count: number) {
  return Array.from({ length: count }, (_, i) => ({
    id: `comp-emit-${String(i).padStart(4, "0")}-000000000001`,
    scanRunId,
    orgId: null,
    name: `library-${String(i).padStart(3, "0")}`,
    version: `1.0.${i}`,
    purl: `pkg:npm/library-${String(i).padStart(3, "0")}@1.0.${i}`,
    ecosystem: "npm",
    licenses: ["MIT"],
    componentType: "library",
    scope: null,
    isDevOnly: false,
    manifestFile: "package-lock.json",
    discoveryMethod: "manifest",
    cpe: null,
    llmEvidence: null,
    occurrences: [{ path: `src/lib${i}.ts`, line: 1 }],
    createdAt: BASE_DATE,
    updatedAt: BASE_DATE,
  }));
}

function makeScanRow(scanRunId: string) {
  return {
    id: scanRunId,
    finishedAt: new Date("2026-05-22T09:00:00Z"),
    createdAt: new Date("2026-05-22T08:00:00Z"),
    repo: { name: "my-repo", defaultBranch: "main" },
    scope: { path: "/" },
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("emitSbomArtifact", () => {
  it("writes a file and returns written=true for a scan with 10 components", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanRun, "findUnique").mockResolvedValue(
      makeScanRow(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.scanRun.findUnique>>,
    );
    vi.spyOn(prisma.sbomComponent, "findMany").mockResolvedValue(
      makeSbomComponents(SCAN_RUN_ID, 10) as unknown as Awaited<ReturnType<typeof prisma.sbomComponent.findMany>>,
    );

    const { emitSbomArtifact } = await import("../src/services/sbomCurated.js");

    const result = await emitSbomArtifact(SCAN_RUN_ID);

    expect(result.written).toBe(true);
    expect(result.path).toContain(SCAN_RUN_ID);

    // File must exist.
    const exists = await fs.access(result.path).then(() => true).catch(() => false);
    expect(exists).toBe(true);

    // Content must parse as valid JSON.
    const raw = await fs.readFile(result.path, "utf8");
    const doc = JSON.parse(raw) as {
      bomFormat: string;
      specVersion: string;
      serialNumber: string;
      components: unknown[];
    };

    // Shape checks.
    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.7");
    expect(doc.serialNumber).toBe(`urn:uuid:${SCAN_RUN_ID}`);

    // Exactly 10 components.
    expect(doc.components).toHaveLength(10);
  });

  it("returns written=false when the scan has no components", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanRun, "findUnique").mockResolvedValue(
      makeScanRow(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.scanRun.findUnique>>,
    );
    // Empty component list → buildCuratedSbomJson returns null.
    vi.spyOn(prisma.sbomComponent, "findMany").mockResolvedValue([]);

    const { emitSbomArtifact } = await import("../src/services/sbomCurated.js");

    const result = await emitSbomArtifact(SCAN_RUN_ID);

    expect(result.written).toBe(false);

    // No file should have been created.
    const exists = await fs.access(result.path).then(() => true).catch(() => false);
    expect(exists).toBe(false);
  });

  it("produces byte-identical output on two consecutive calls (round-trip equality)", async () => {
    const { prisma } = await import("../src/db.js");

    const components = makeSbomComponents(SCAN_RUN_ID, 5);

    // Two calls — each needs its own pair of spies.
    vi.spyOn(prisma.scanRun, "findUnique")
      .mockResolvedValue(
        makeScanRow(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.scanRun.findUnique>>,
      );
    vi.spyOn(prisma.sbomComponent, "findMany")
      .mockResolvedValue(
        components as unknown as Awaited<ReturnType<typeof prisma.sbomComponent.findMany>>,
      );

    const { emitSbomArtifact } = await import("../src/services/sbomCurated.js");
    const { sbomPathFor } = await import("../src/services/artifactStore.js");

    // First emit.
    const result1 = await emitSbomArtifact(SCAN_RUN_ID);
    const bytes1 = await fs.readFile(sbomPathFor(SCAN_RUN_ID));

    // Second emit (spies still return same data).
    const result2 = await emitSbomArtifact(SCAN_RUN_ID);
    const bytes2 = await fs.readFile(sbomPathFor(SCAN_RUN_ID));

    expect(result1.written).toBe(true);
    expect(result2.written).toBe(true);

    // Byte-exact equality.
    expect(bytes1.toString("utf8")).toBe(bytes2.toString("utf8"));
  });

  it("returns written=false when scanRun does not exist", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanRun, "findUnique").mockResolvedValue(null);

    const { emitSbomArtifact } = await import("../src/services/sbomCurated.js");

    const result = await emitSbomArtifact("nonexistent-scan-run-id");
    expect(result.written).toBe(false);
  });
});
