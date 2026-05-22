/**
 * sbomFileFirst.test.ts — M9 Stream E1 round-trip and idempotency tests.
 *
 * Tests the file-first SBOM pipeline:
 *   buildAugmentationSbom (in-memory → CycloneDX doc)
 *   → writeArtifact (doc → file)
 *   → ingestSbomFromArtifact (file → sbom_components rows + componentCount)
 *
 * Strategy:
 *  - Mock prisma so the function never touches a real DB.
 *  - Override ARTIFACT_DIR to a tmp directory per test.
 *  - Assert that:
 *      1. Round-trip: all typed fields survive buildAugmentationSbom → ingestSbomFromArtifact.
 *      2. Idempotency: calling ingest twice clears+repopulates (deleteMany called each time).
 *      3. componentCount: scan_runs.componentCount = doc.components.length.
 *      4. discoveryMethod round-trip: manifest vs llm_augmentation preserved.
 *      5. No recheck_recovery rows emitted by buildAugmentationSbom.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes, randomUUID } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// Set required env vars before side-effectful modules load.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// DB mock — must be registered before any imports that depend on db.js
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
// Import modules under test — AFTER mocks are registered
// ---------------------------------------------------------------------------

const { buildAugmentationSbom, stableStringify } = await import("../src/services/sbomCurated.js");
const { writeArtifact, sbomPathFor } = await import("../src/services/artifactStore.js");
const { ingestSbomFromArtifact } = await import("../src/services/sbomIngest.js");

// ---------------------------------------------------------------------------
// Tmp-dir setup / teardown
// ---------------------------------------------------------------------------

let tmpDir: string;
let originalArtifactDir: string | undefined;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-e1-"));
  originalArtifactDir = process.env["ARTIFACT_DIR"];
  process.env["ARTIFACT_DIR"] = tmpDir;
  // Reset mock state for each test.
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
  // Use clearAllMocks (not restoreAllMocks): restoreAllMocks removes mock
  // implementations which would break the $transaction mock across tests.
  vi.clearAllMocks();
});

// ---------------------------------------------------------------------------
// Fixture factories
// ---------------------------------------------------------------------------

/** A representative CdxComponent with manifest discovery. */
function manifestComponent(): import("../src/services/sbomService.js").CdxComponent {
  return {
    type: "library",
    name: "axios",
    version: "1.6.0",
    purl: "pkg:npm/axios@1.6.0",
    licenses: [{ license: { id: "MIT" } }],
    properties: [
      { name: "SrcFile", value: "/workspace/package-lock.json" },
    ],
  };
}

/** A CdxComponent tagged as LLM-added (discoveryMethod on the object). */
function llmAddedComponent(): import("../src/services/sbomService.js").CdxComponent & { discoveryMethod: string } {
  return {
    type: "library",
    name: "xenomai",
    version: "3.2.0",
    purl: "pkg:generic/xenomai@3.2.0",
    discoveryMethod: "llm_augmentation",
  };
}

/** A dev-only npm component. */
function devComponent(): import("../src/services/sbomService.js").CdxComponent {
  return {
    type: "library",
    name: "@types/node",
    group: "@types",
    version: "20.0.0",
    purl: "pkg:npm/%40types%2Fnode@20.0.0",
    properties: [
      { name: "cdx:npm:package:development", value: "true" },
      { name: "SrcFile", value: "/workspace/package-lock.json" },
    ],
  };
}

/** Build a minimal doc using buildAugmentationSbom with the given components. */
async function buildDoc(
  scanRunId: string,
  components: import("../src/services/sbomService.js").CdxComponent[],
  opts?: {
    sbomEvidenceMap?: Map<string, { path: string; excerpt: string | null; llmReason: string }>;
    sbomCpeMap?: Map<string, string>;
    sbomIdentityMap?: Map<string, { componentRoot: string | null; evidence: Array<{ path: string; line: number | null }> }>;
  },
) {
  return buildAugmentationSbom({
    scanRunId,
    scopeId: randomUUID(),
    scopePath: "/",
    scanDir: tmpDir,
    components,
    sbomEvidenceMap: opts?.sbomEvidenceMap ?? new Map(),
    sbomCpeMap: opts?.sbomCpeMap ?? new Map(),
    sbomIdentityMap: opts?.sbomIdentityMap ?? new Map(),
    startedAt: new Date("2026-05-22T10:00:00Z"),
    finishedAt: null,
    repoName: "test-repo",
    repoDefaultBranch: "main",
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("buildAugmentationSbom produces a valid CycloneDX 1.7 document", () => {
  it("emits correct top-level shape", async () => {
    const scanRunId = randomUUID();
    const doc = await buildDoc(scanRunId, [manifestComponent(), llmAddedComponent()]);

    expect(doc.bomFormat).toBe("CycloneDX");
    expect(doc.specVersion).toBe("1.7");
    expect(doc.serialNumber).toBe(`urn:uuid:${scanRunId}`);
    expect(doc.components).toHaveLength(2);
    expect(doc.metadata.component?.name).toBe("test-repo");
    expect(doc.metadata.component?.version).toBe("main");
  });

  it("sorts properties lexicographically (D4 invariant)", async () => {
    const doc = await buildDoc(randomUUID(), [manifestComponent()]);
    const comp = doc.components[0];
    const names = (comp.properties ?? []).map((p) => p.name);
    const sorted = [...names].sort();
    expect(names).toEqual(sorted);
  });
});

describe("discoveryMethod round-trip", () => {
  it("manifest component emits discoveryMethod=manifest", async () => {
    const doc = await buildDoc(randomUUID(), [manifestComponent()]);
    const dmProp = doc.components[0].properties?.find((p) => p.name === "sastbot:discovery_method");
    expect(dmProp?.value).toBe("manifest");
  });

  it("LLM-added component emits discoveryMethod=llm_augmentation", async () => {
    const doc = await buildDoc(randomUUID(), [llmAddedComponent()]);
    const dmProp = doc.components[0].properties?.find((p) => p.name === "sastbot:discovery_method");
    expect(dmProp?.value).toBe("llm_augmentation");
  });

  it("after write+ingest, manifest component has discoveryMethod=manifest", async () => {
    const scanRunId = randomUUID();
    const doc = await buildDoc(scanRunId, [manifestComponent()]);
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    const createCall = mockCreateMany.mock.calls[0][0] as { data: Array<{ discoveryMethod: string }> };
    expect(createCall.data[0].discoveryMethod).toBe("manifest");
  });

  it("after write+ingest, LLM-added component has discoveryMethod=llm_augmentation", async () => {
    const scanRunId = randomUUID();
    const doc = await buildDoc(scanRunId, [llmAddedComponent()]);
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    const createCall = mockCreateMany.mock.calls[0][0] as { data: Array<{ discoveryMethod: string }> };
    expect(createCall.data[0].discoveryMethod).toBe("llm_augmentation");
  });
});

describe("isDevOnly round-trip", () => {
  it("dev component has isDevOnly=true in the CycloneDX doc", async () => {
    const doc = await buildDoc(randomUUID(), [devComponent()]);
    const devProp = doc.components[0].properties?.find((p) => p.name === "cdx:npm:package:development");
    expect(devProp?.value).toBe("true");
  });

  it("after write+ingest, dev component has isDevOnly=true in the row", async () => {
    const scanRunId = randomUUID();
    const doc = await buildDoc(scanRunId, [devComponent()]);
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    const createCall = mockCreateMany.mock.calls[0][0] as { data: Array<{ isDevOnly: boolean }> };
    expect(createCall.data[0].isDevOnly).toBe(true);
  });

  it("non-dev component has isDevOnly=false", async () => {
    const scanRunId = randomUUID();
    const doc = await buildDoc(scanRunId, [manifestComponent()]);
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    const createCall = mockCreateMany.mock.calls[0][0] as { data: Array<{ isDevOnly: boolean }> };
    expect(createCall.data[0].isDevOnly).toBe(false);
  });
});

describe("componentCount written from file", () => {
  it("scanRun.componentCount equals doc.components.length after ingest", async () => {
    const scanRunId = randomUUID();
    const components = [manifestComponent(), llmAddedComponent(), devComponent()];
    const doc = await buildDoc(scanRunId, components);
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    expect(mockScanRunUpdate).toHaveBeenCalledWith({
      where: { id: scanRunId },
      data: { componentCount: doc.components.length },
    });
  });
});

describe("idempotency", () => {
  it("second ingest call also clears rows (deleteMany called each time)", async () => {
    const scanRunId = randomUUID();
    const doc = await buildDoc(scanRunId, [manifestComponent()]);
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));

    // First ingest.
    await ingestSbomFromArtifact(scanRunId);
    const firstRowCount = (mockCreateMany.mock.calls[0][0] as { data: unknown[] }).data.length;

    mockDeleteMany.mockClear();
    mockCreateMany.mockClear();

    // Second ingest — same file.
    await ingestSbomFromArtifact(scanRunId);
    const secondRowCount = (mockCreateMany.mock.calls[0][0] as { data: unknown[] }).data.length;

    // Both ingests produce the same row count.
    expect(firstRowCount).toBe(secondRowCount);
    // deleteMany is called on the second ingest too (clearing the "old" rows).
    expect(mockDeleteMany).toHaveBeenCalledWith({ where: { scanRunId } });
  });
});

describe("no recheck_recovery rows in pipeline output", () => {
  it("buildAugmentationSbom never emits discoveryMethod=recheck_recovery", async () => {
    const doc = await buildDoc(randomUUID(), [manifestComponent(), llmAddedComponent(), devComponent()]);
    for (const comp of doc.components) {
      const dmProp = comp.properties?.find((p) => p.name === "sastbot:discovery_method");
      expect(dmProp?.value).not.toBe("recheck_recovery");
    }
  });
});

describe("CPE and LLM evidence round-trip", () => {
  it("CPE property survives in the CycloneDX doc", async () => {
    const cpe = "cpe:2.3:a:xenomai:xenomai:3.2.0:*:*:*:*:*:*:*";
    const doc = await buildDoc(randomUUID(), [llmAddedComponent()], {
      sbomCpeMap: new Map([["xenomai", cpe]]),
      sbomIdentityMap: new Map([
        ["xenomai", { componentRoot: "extern/xenomai", evidence: [{ path: "extern/xenomai/README", line: null }] }],
      ]),
    });
    const cpeProp = doc.components[0].properties?.find((p) => p.name === "sastbot:cpe");
    expect(cpeProp?.value).toBe(cpe);
  });

  it("after write+ingest, cpe field is populated in the row", async () => {
    const scanRunId = randomUUID();
    const cpe = "cpe:2.3:a:xenomai:xenomai:3.2.0:*:*:*:*:*:*:*";
    const doc = await buildDoc(scanRunId, [llmAddedComponent()], {
      sbomCpeMap: new Map([["xenomai", cpe]]),
      sbomIdentityMap: new Map([
        ["xenomai", { componentRoot: "extern/xenomai", evidence: [] }],
      ]),
    });
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    const createCall = mockCreateMany.mock.calls[0][0] as { data: Array<{ cpe: string | null }> };
    expect(createCall.data[0].cpe).toBe(cpe);
  });

  it("LLM evidence llmReason survives the round-trip", async () => {
    const scanRunId = randomUUID();
    const llmEvidence = { path: "extern/xenomai/README", excerpt: "Xenomai 3.2", llmReason: "vendored RT library" };
    const doc = await buildDoc(scanRunId, [llmAddedComponent()], {
      sbomEvidenceMap: new Map([["xenomai", llmEvidence]]),
      sbomIdentityMap: new Map([
        ["xenomai", { componentRoot: "extern/xenomai", evidence: [] }],
      ]),
    });
    await writeArtifact(sbomPathFor(scanRunId), stableStringify(doc, 2));
    await ingestSbomFromArtifact(scanRunId);

    const createCall = mockCreateMany.mock.calls[0][0] as { data: Array<{ llmEvidence: unknown }> };
    const parsed = createCall.data[0].llmEvidence as typeof llmEvidence;
    expect(parsed.llmReason).toBe("vendored RT library");
  });
});

describe("ingestSbomFromArtifact error handling", () => {
  it("throws when no file exists on disk", async () => {
    const nonExistentId = randomUUID();
    await expect(ingestSbomFromArtifact(nonExistentId)).rejects.toThrow(
      `sbom_ingest: no SBOM artifact found for scan ${nonExistentId}`,
    );
  });

  it("throws when artifact is not valid JSON", async () => {
    const scanRunId = randomUUID();
    await writeArtifact(sbomPathFor(scanRunId), "not-valid-json{{{");
    await expect(ingestSbomFromArtifact(scanRunId)).rejects.toThrow(
      "sbom_ingest: SBOM artifact for scan",
    );
  });
});
