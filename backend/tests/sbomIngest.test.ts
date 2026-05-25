/**
 * Unit tests for sbomIngest.ts (M9 Stream E1 + M11 Step 2).
 *
 * ingestSbomFromArtifact:
 *   - Smoke test: module exports the function.
 *   - Throws "no SBOM artifact found" when no file exists on disk.
 *   (Comprehensive round-trip, idempotency, discoveryMethod, isDevOnly, and
 *    componentCount tests live in sbomFileFirst.test.ts.)
 *
 * persistComponentsFromMemory (new in M11 Step 2):
 *   - Writes the expected row count for a given component list.
 *   - Idempotent: calling twice for the same scanRunId yields the same rows.
 *   - Updates scanRuns.componentCount to the inserted count.
 *   - Returns { inserted: N } where N equals the number of unique components.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// DB mock — registered before any module that transitively imports db.js
// ---------------------------------------------------------------------------

const mockDeleteMany = vi.fn().mockResolvedValue({ count: 0 });
const mockCreateMany = vi.fn().mockResolvedValue({ count: 0 });
const mockScanRunUpdate = vi.fn().mockResolvedValue({});

vi.mock("../src/db.js", () => ({
  prisma: {
    $transaction: vi.fn().mockImplementation(async (cb: (tx: unknown) => Promise<unknown>) => {
      return cb({
        sbomComponent: {
          deleteMany: mockDeleteMany,
          createMany: mockCreateMany,
        },
        scanRun: {
          update: mockScanRunUpdate,
        },
      });
    }),
  },
}));

// ---------------------------------------------------------------------------
// Tmp-dir setup / teardown (needed so ARTIFACT_DIR resolves to a real dir)
// ---------------------------------------------------------------------------

let tmpDir: string;
let originalArtifactDir: string | undefined;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-sbom-ingest-"));
  originalArtifactDir = process.env["ARTIFACT_DIR"];
  process.env["ARTIFACT_DIR"] = tmpDir;
  mockDeleteMany.mockClear();
  mockCreateMany.mockClear();
  mockScanRunUpdate.mockClear();
});

afterEach(async () => {
  if (originalArtifactDir === undefined) {
    delete process.env["ARTIFACT_DIR"];
  } else {
    process.env["ARTIFACT_DIR"] = originalArtifactDir;
  }
  await fs.rm(tmpDir, { recursive: true, force: true });
  vi.clearAllMocks();
});

const SCAN_RUN_ID = randomUUID();

// ---------------------------------------------------------------------------
// ingestSbomFromArtifact — smoke test
// ---------------------------------------------------------------------------

describe("ingestSbomFromArtifact", () => {
  it("throws 'no SBOM artifact found' when no file exists on disk", async () => {
    const { ingestSbomFromArtifact } = await import("../src/services/sbomIngest.js");
    await expect(ingestSbomFromArtifact(SCAN_RUN_ID)).rejects.toThrow(
      `sbom_ingest: no SBOM artifact found for scan ${SCAN_RUN_ID}`,
    );
  });
});

// ---------------------------------------------------------------------------
// persistComponentsFromMemory — new in M11 Step 2
// ---------------------------------------------------------------------------

/** Minimal CdxComponent for manifest-discovered library. */
function makeManifestComponent(name: string, version: string): import("../src/services/sbomService.js").CdxComponent {
  return {
    type: "library",
    name,
    version,
    purl: `pkg:npm/${name}@${version}`,
    licenses: [{ license: { id: "MIT" } }],
    properties: [
      { name: "SrcFile", value: "/workspace/package-lock.json" },
    ],
  };
}

/** Minimal CdxComponent for an LLM-augmented component (no SrcFile). */
function makeLlmComponent(name: string): import("../src/services/sbomService.js").CdxComponent & { discoveryMethod: string } {
  return {
    type: "library",
    name,
    version: "2.0.0",
    purl: `pkg:generic/${name}@2.0.0`,
    discoveryMethod: "llm_augmentation",
  };
}

describe("persistComponentsFromMemory", () => {
  it("writes the expected row count for a given component list", async () => {
    const { persistComponentsFromMemory } = await import("../src/services/sbomIngest.js");
    const scanRunId = randomUUID();
    const components = [
      makeManifestComponent("axios", "1.6.0"),
      makeManifestComponent("lodash", "4.17.21"),
      makeLlmComponent("xenomai"),
    ];

    const result = await persistComponentsFromMemory({
      scanRunId,
      scanDir: tmpDir,
      scopePath: "/",
      components,
      sbomEvidenceMap: new Map(),
      sbomCpeMap: new Map(),
      sbomIdentityMap: new Map(),
    });

    expect(result.inserted).toBe(3);

    // createMany was called with 3 rows.
    expect(mockCreateMany).toHaveBeenCalledOnce();
    const createCall = mockCreateMany.mock.calls[0][0] as { data: unknown[] };
    expect(createCall.data).toHaveLength(3);
  });

  it("updates scanRuns.componentCount to the inserted count", async () => {
    const { persistComponentsFromMemory } = await import("../src/services/sbomIngest.js");
    const scanRunId = randomUUID();
    const components = [
      makeManifestComponent("express", "4.18.0"),
      makeManifestComponent("body-parser", "1.20.0"),
    ];

    await persistComponentsFromMemory({
      scanRunId,
      scanDir: tmpDir,
      scopePath: "/",
      components,
      sbomEvidenceMap: new Map(),
      sbomCpeMap: new Map(),
      sbomIdentityMap: new Map(),
    });

    expect(mockScanRunUpdate).toHaveBeenCalledWith({
      where: { id: scanRunId },
      data: { componentCount: 2 },
    });
  });

  it("is idempotent: calling twice produces the same row count and calls deleteMany both times", async () => {
    const { persistComponentsFromMemory } = await import("../src/services/sbomIngest.js");
    const scanRunId = randomUUID();
    const components = [makeManifestComponent("chalk", "5.0.0")];

    const baseInput = {
      scanRunId,
      scanDir: tmpDir,
      scopePath: "/",
      components,
      sbomEvidenceMap: new Map<string, { path: string; excerpt: string | null; llmReason: string }>(),
      sbomCpeMap: new Map<string, string>(),
      sbomIdentityMap: new Map<string, { componentRoot: string | null; evidence: Array<{ path: string; line: number | null }> }>(),
    };

    // First call.
    const result1 = await persistComponentsFromMemory(baseInput);
    expect(result1.inserted).toBe(1);
    expect(mockDeleteMany).toHaveBeenCalledOnce();

    mockDeleteMany.mockClear();
    mockCreateMany.mockClear();

    // Second call with same input.
    const result2 = await persistComponentsFromMemory(baseInput);
    expect(result2.inserted).toBe(1);
    // deleteMany must be called again on the second call (idempotency guarantee).
    expect(mockDeleteMany).toHaveBeenCalledWith({ where: { scanRunId } });
  });

  it("deduplicates components with the same purl and only inserts unique entries", async () => {
    const { persistComponentsFromMemory } = await import("../src/services/sbomIngest.js");
    const scanRunId = randomUUID();

    // Same purl twice — the second entry should be dropped by the dedup step.
    const dup = makeManifestComponent("react", "18.0.0");
    const components = [dup, { ...dup }];

    const result = await persistComponentsFromMemory({
      scanRunId,
      scanDir: tmpDir,
      scopePath: "/",
      components,
      sbomEvidenceMap: new Map(),
      sbomCpeMap: new Map(),
      sbomIdentityMap: new Map(),
    });

    // Only 1 unique row after dedup.
    expect(result.inserted).toBe(1);
    const createCall = mockCreateMany.mock.calls[0][0] as { data: unknown[] };
    expect(createCall.data).toHaveLength(1);
  });

  it("emits discoveryMethod=llm_augmentation for LLM-added components", async () => {
    const { persistComponentsFromMemory } = await import("../src/services/sbomIngest.js");
    const scanRunId = randomUUID();

    await persistComponentsFromMemory({
      scanRunId,
      scanDir: tmpDir,
      scopePath: "/",
      components: [makeLlmComponent("xenomai")],
      sbomEvidenceMap: new Map(),
      sbomCpeMap: new Map(),
      sbomIdentityMap: new Map(),
    });

    const createCall = mockCreateMany.mock.calls[0][0] as {
      data: Array<{ discoveryMethod: string }>;
    };
    expect(createCall.data[0].discoveryMethod).toBe("llm_augmentation");
  });

  it("returns { inserted: 0 } and still calls deleteMany when component list is empty", async () => {
    const { persistComponentsFromMemory } = await import("../src/services/sbomIngest.js");
    const scanRunId = randomUUID();

    const result = await persistComponentsFromMemory({
      scanRunId,
      scanDir: tmpDir,
      scopePath: "/",
      components: [],
      sbomEvidenceMap: new Map(),
      sbomCpeMap: new Map(),
      sbomIdentityMap: new Map(),
    });

    expect(result.inserted).toBe(0);
    // deleteMany must still run (idempotency: clears any prior rows).
    expect(mockDeleteMany).toHaveBeenCalledWith({ where: { scanRunId } });
    // createMany not called when no rows to insert.
    expect(mockCreateMany).not.toHaveBeenCalled();
  });
});
