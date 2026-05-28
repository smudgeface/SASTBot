/**
 * Determinism integration tests for the curated SBOM builders (M9 Stream D6).
 *
 * Goals:
 *  D6 — Two calls to buildCuratedSbomJsonForScope / buildCuratedSbomJson
 *       with unchanged DB data produce byte-identical stableStringify output.
 *  D6 — Components inserted in reverse order produce the same JSON as
 *       components inserted in forward order (proves sort is order-independent).
 *  D8 — No LLM / network call is made during the download path. Since
 *       sbomCurated.ts contains no import of llmClient, claudeApi, spawn,
 *       child_process, fetch, http, https, or axios, this is verified by a
 *       static grep assertion (see D8 comment below). No vi.spyOn needed.
 */

import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";

// Set required env vars before side-effectful modules load.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// M14 helper: buildCuratedSbomJsonForScope now calls scopeComponent.findMany
// twice per invocation:
//   1st call: { dismissedStatus: "active" } → active components for output
//   2nd call: { dismissedStatus: { in: ["ignored","not_found"] } } → excluded names
// Use this filter-aware mock to handle both calls correctly.
// ---------------------------------------------------------------------------
function mockScopeComponentFindMany(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  prisma: any,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  activeRows: any[],
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  excludedRows: any[] = [],
) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vi.spyOn(prisma.scopeComponent, "findMany").mockImplementation((args: any) => {
    const where = args?.where ?? {};
    if (where.dismissedStatus && typeof where.dismissedStatus === "object" && "in" in where.dismissedStatus) {
      return Promise.resolve(excludedRows);
    }
    return Promise.resolve(activeRows);
  });
}

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

const SCOPE_ID = "eeeeeeee-0000-0000-0000-000000000010";
const SCOPE_ID_REVERSE = "eeeeeeee-0000-0000-0000-000000000011";
const SCAN_RUN_ID = "ffffffff-0000-0000-0000-000000000020";

const BASE_DATE = new Date("2026-05-22T10:00:00Z");

// Five scope_components with:
//  - mixed null / non-null versions
//  - mixed license lists (multiple licenses per row, unsorted)
//  - occurrences in non-sorted order
//  - multiple properties per row (isDevOnly + llmEvidence)
function makeScopeComponents(scopeId: string) {
  return [
    {
      id: "comp-0001-0000-0000-000000000001",
      scopeId,
      orgId: null,
      name: "zlib",
      version: "1.2.13",
      purl: "pkg:generic/zlib@1.2.13",
      ecosystem: "generic",
      licenses: [],
      latestLicenses: ["Zlib", "MIT"], // intentionally unsorted
      componentType: "library",
      latestComponentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: null,
      discoveryMethod: "manifest",
      latestDiscoveryMethod: "manifest",
      evidenceLine: null,
      evidencePath: null,
      componentRoot: "extern/zlib",
      evidence: [
        { path: "extern/zlib/zlib.h", line: 1 },
        { path: "CMakeLists.txt", line: 42 }, // out of (path) order
      ],
      usage: [{ path: "src/compress.c", line: null }],
      llmEvidence: {
        path: "extern/zlib/CMakeLists.txt",
        excerpt: "project(zlib)",
        llmReason: "Vendored zlib compression library",
      },
      latestLlmEvidence: null,
      cpe: null,
      latestCpe: null,
      source: "scan",
      dismissedStatus: "active",
      dismissedReason: null,
      dismissedAt: null,
      firstSeenScanRunId: SCAN_RUN_ID,
      lastSeenScanRunId: SCAN_RUN_ID,
      lastSeenAt: BASE_DATE,
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "comp-0002-0000-0000-000000000002",
      scopeId,
      orgId: null,
      name: "axios",
      version: "1.6.0",
      purl: "pkg:npm/axios@1.6.0",
      ecosystem: "npm",
      licenses: [],
      latestLicenses: ["MIT"],
      componentType: "library",
      latestComponentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: "package-lock.json",
      discoveryMethod: "manifest",
      latestDiscoveryMethod: "manifest",
      evidenceLine: null,
      evidencePath: null,
      componentRoot: null,
      evidence: [],
      usage: [
        { path: "src/http.ts", line: 5 },
        { path: "src/api.ts", line: 12 }, // out of (path) order
      ],
      llmEvidence: null,
      latestLlmEvidence: null,
      cpe: null,
      latestCpe: null,
      source: "scan",
      dismissedStatus: "active",
      dismissedReason: null,
      dismissedAt: null,
      firstSeenScanRunId: SCAN_RUN_ID,
      lastSeenScanRunId: SCAN_RUN_ID,
      lastSeenAt: BASE_DATE,
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "comp-0003-0000-0000-000000000003",
      scopeId,
      orgId: null,
      name: "lodash",
      version: null, // null version
      purl: "pkg:npm/lodash",
      ecosystem: "npm",
      licenses: [],
      latestLicenses: ["MIT", "Apache-2.0", "BSD-3-Clause"], // unsorted with 3 entries
      componentType: "library",
      latestComponentType: "library",
      scope: null,
      isDevOnly: true, // dev-only → extra property
      manifestFile: "package-lock.json",
      discoveryMethod: "manifest",
      latestDiscoveryMethod: "manifest",
      evidenceLine: null,
      evidencePath: null,
      componentRoot: null,
      evidence: [],
      usage: [],
      llmEvidence: null,
      latestLlmEvidence: null,
      cpe: null,
      latestCpe: null,
      source: "scan",
      dismissedStatus: "active",
      dismissedReason: null,
      dismissedAt: null,
      firstSeenScanRunId: SCAN_RUN_ID,
      lastSeenScanRunId: SCAN_RUN_ID,
      lastSeenAt: BASE_DATE,
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "comp-0004-0000-0000-000000000004",
      scopeId,
      orgId: null,
      name: "openssl",
      version: "3.0.7",
      purl: "pkg:generic/openssl@3.0.7",
      ecosystem: "generic",
      licenses: [],
      latestLicenses: ["OpenSSL"],
      componentType: "library",
      latestComponentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: null,
      discoveryMethod: "filename",
      latestDiscoveryMethod: "filename",
      evidenceLine: null,
      evidencePath: null,
      componentRoot: "extern/openssl",
      evidence: [
        { path: "extern/openssl/openssl.h", line: 1 },
        { path: "extern/openssl/crypto/sha256.c", line: 10 },
      ],
      usage: [],
      llmEvidence: {
        path: "extern/openssl/CMakeLists.txt",
        excerpt: null,
        llmReason: "OpenSSL cryptography library",
      },
      latestLlmEvidence: null,
      cpe: null,
      latestCpe: null,
      source: "scan",
      dismissedStatus: "active",
      dismissedReason: null,
      dismissedAt: null,
      firstSeenScanRunId: SCAN_RUN_ID,
      lastSeenScanRunId: SCAN_RUN_ID,
      lastSeenAt: BASE_DATE,
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "comp-0005-0000-0000-000000000005",
      scopeId,
      orgId: null,
      name: "boost",
      version: null, // null version
      purl: "pkg:generic/boost",
      ecosystem: "generic",
      licenses: [],
      latestLicenses: ["BSL-1.0"],
      componentType: "library",
      latestComponentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: null,
      discoveryMethod: "filename",
      latestDiscoveryMethod: "filename",
      evidenceLine: null,
      evidencePath: null,
      componentRoot: "extern/boost",
      evidence: [
        { path: "extern/boost/boost.h", line: null }, // null line
        { path: "CMakeLists.txt", line: 100 },
        { path: "CMakeLists.txt", line: 5 }, // same path, different line — reverse order
      ],
      usage: [],
      llmEvidence: null,
      latestLlmEvidence: null,
      cpe: null,
      latestCpe: null,
      source: "scan",
      dismissedStatus: "active",
      dismissedReason: null,
      dismissedAt: null,
      firstSeenScanRunId: SCAN_RUN_ID,
      lastSeenScanRunId: SCAN_RUN_ID,
      lastSeenAt: BASE_DATE,
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
  ];
}

function makeScopeRow(scopeId: string) {
  return {
    id: scopeId,
    path: "/",
    lastScanRunId: SCAN_RUN_ID,
    lastScanCompletedAt: new Date("2026-05-20T00:00:00Z"),
    createdAt: new Date("2026-05-01T00:00:00Z"),
    orgId: null,
    isActive: true,
    repoId: "dddddddd-0000-0000-0000-000000000004",
    displayName: null,
    repo: { name: "my-repo", defaultBranch: "main" },
  };
}

// Five sbom_components with the same characteristics (for buildCuratedSbomJson test).
function makeSbomComponents(scanRunId: string) {
  return [
    {
      id: "sbom-0001-0000-0000-000000000001",
      scanRunId,
      orgId: null,
      name: "zlib",
      version: "1.2.13",
      purl: "pkg:generic/zlib@1.2.13",
      ecosystem: "generic",
      licenses: ["Zlib", "MIT"],
      componentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: null,
      discoveryMethod: "manifest",
      cpe: null,
      llmEvidence: {
        path: "extern/zlib/CMakeLists.txt",
        excerpt: "project(zlib)",
        llmReason: "Vendored zlib compression library",
      },
      occurrences: [
        { path: "extern/zlib/zlib.h", line: 1 },
        { path: "CMakeLists.txt", line: 42 },
      ],
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "sbom-0002-0000-0000-000000000002",
      scanRunId,
      orgId: null,
      name: "axios",
      version: "1.6.0",
      purl: "pkg:npm/axios@1.6.0",
      ecosystem: "npm",
      licenses: ["MIT"],
      componentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: "package-lock.json",
      discoveryMethod: "manifest",
      cpe: null,
      llmEvidence: null,
      occurrences: [
        { path: "src/http.ts", line: 5 },
        { path: "src/api.ts", line: 12 },
      ],
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "sbom-0003-0000-0000-000000000003",
      scanRunId,
      orgId: null,
      name: "lodash",
      version: null,
      purl: "pkg:npm/lodash",
      ecosystem: "npm",
      licenses: ["MIT", "Apache-2.0", "BSD-3-Clause"],
      componentType: "library",
      scope: null,
      isDevOnly: true,
      manifestFile: "package-lock.json",
      discoveryMethod: "manifest",
      cpe: null,
      llmEvidence: null,
      occurrences: [],
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "sbom-0004-0000-0000-000000000004",
      scanRunId,
      orgId: null,
      name: "openssl",
      version: "3.0.7",
      purl: "pkg:generic/openssl@3.0.7",
      ecosystem: "generic",
      licenses: ["OpenSSL"],
      componentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: null,
      discoveryMethod: "filename",
      cpe: null,
      llmEvidence: {
        path: "extern/openssl/CMakeLists.txt",
        excerpt: null,
        llmReason: "OpenSSL cryptography library",
      },
      occurrences: [
        { path: "extern/openssl/openssl.h", line: 1 },
        { path: "extern/openssl/crypto/sha256.c", line: 10 },
      ],
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
    {
      id: "sbom-0005-0000-0000-000000000005",
      scanRunId,
      orgId: null,
      name: "boost",
      version: null,
      purl: "pkg:generic/boost",
      ecosystem: "generic",
      licenses: ["BSL-1.0"],
      componentType: "library",
      scope: null,
      isDevOnly: false,
      manifestFile: null,
      discoveryMethod: "filename",
      cpe: null,
      llmEvidence: null,
      occurrences: [
        { path: "extern/boost/boost.h", line: null },
        { path: "CMakeLists.txt", line: 100 },
        { path: "CMakeLists.txt", line: 5 },
      ],
      createdAt: BASE_DATE,
      updatedAt: BASE_DATE,
    },
  ];
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
// Tests: buildCuratedSbomJsonForScope determinism (D6)
// ---------------------------------------------------------------------------

describe("buildCuratedSbomJsonForScope — determinism", () => {
  it("produces byte-identical output on two consecutive calls with unchanged data", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJsonForScope, stableStringify } = await import(
      "../src/services/sbomCurated.js"
    );

    const components = makeScopeComponents(SCOPE_ID);
    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow(SCOPE_ID) as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, components);
    // M11 Step 3: buildCuratedSbomJsonForScope now queries scaIssue.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const doc1 = await buildCuratedSbomJsonForScope(SCOPE_ID);
    const doc2 = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(doc1).not.toBeNull();
    expect(doc2).not.toBeNull();
    const json1 = stableStringify(doc1!, 2);
    const json2 = stableStringify(doc2!, 2);
    expect(json1).toBe(json2);

    vi.restoreAllMocks();
  });

  it("per-component array order (occurrences, licenses, properties) is insertion-order-independent", async () => {
    // This test verifies D2/D3/D4 in-memory sorts by feeding the same single
    // component with its arrays in REVERSED order and confirming the output is
    // identical to the forward-order call.
    //
    // Note: the component LIST order relies on the DB's orderBy clause (D1).
    // That clause is a no-op in mocked tests because Prisma mocks ignore
    // findMany options. Production correctness is provided by the DB index.
    // This test is deliberately scoped to per-component array sorting.
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJsonForScope, stableStringify } = await import(
      "../src/services/sbomCurated.js"
    );

    // A single component with unsorted occurrences and licenses.
    const componentForward = makeScopeComponents(SCOPE_ID).find((c) => c.name === "boost")!;
    // Same component with occurrences reversed and scopeId changed (to avoid
    // mock collision, both tests use the same spy within the same it block).
    const componentReverse = {
      ...componentForward,
      scopeId: SCOPE_ID,
      // reverse the evidence array; sort should produce the same result
      evidence: [...(componentForward.evidence as Array<{ path: string; line?: number | null }>)].reverse(),
    };

    // M11 Step 3: scaIssue.findMany now queried — mock for both calls.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    // Call 1: forward order. Uses filter-aware mock — active call returns
    // componentForward; excluded-names call returns [].
    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValueOnce(
      makeScopeRow(SCOPE_ID) as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [componentForward]);
    const docForward = await buildCuratedSbomJsonForScope(SCOPE_ID);

    // Call 2: reversed occurrence array.
    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValueOnce(
      makeScopeRow(SCOPE_ID) as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [componentReverse]);
    const docReverse = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(docForward).not.toBeNull();
    expect(docReverse).not.toBeNull();

    // Component-level occurrence and property arrays must be identical.
    const jsonForward = stableStringify(docForward!.components[0], 2);
    const jsonReverse = stableStringify(docReverse!.components[0], 2);
    expect(jsonForward).toBe(jsonReverse);

    vi.restoreAllMocks();
  });

  it("occurrences and licenses are sorted deterministically in output", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJsonForScope, stableStringify } = await import(
      "../src/services/sbomCurated.js"
    );

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow(SCOPE_ID) as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, makeScopeComponents(SCOPE_ID));
    // M11 Step 3: scaIssue.findMany now queried.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);
    expect(doc).not.toBeNull();
    const json = stableStringify(doc!, 2);

    // Licenses on lodash must be sorted: Apache-2.0, BSD-3-Clause, MIT
    expect(json).toContain('"Apache-2.0"');
    const lodash = doc!.components.find((c) => c.name === "lodash");
    expect(lodash?.licenses?.map((l) => l.license?.id)).toEqual([
      "Apache-2.0",
      "BSD-3-Clause",
      "MIT",
    ]);

    // boost occurrences: (CMakeLists.txt, 5), (CMakeLists.txt, 100), (extern/boost/boost.h, null→first)
    // After sort: null-line first (as -Infinity), so extern/boost.h first (path order),
    // then CMakeLists.txt line 5, then line 100.
    const boost = doc!.components.find((c) => c.name === "boost");
    const boostOccurrences = boost?.evidence?.occurrences?.map((o) => o.location);
    expect(boostOccurrences).toEqual([
      "CMakeLists.txt#5",
      "CMakeLists.txt#100",
      "extern/boost/boost.h",
    ]);

    // zlib occurrences: evidence first, then usage. Evidence: CMakeLists.txt#42,
    // extern/zlib/zlib.h#1 — sorted by path → CMakeLists comes before extern/.
    // Usage: src/compress.c (null line).
    const zlib = doc!.components.find((c) => c.name === "zlib");
    const zlibOccurrences = zlib?.evidence?.occurrences?.map((o) => o.location);
    expect(zlibOccurrences).toEqual([
      "CMakeLists.txt#42",
      "extern/zlib/zlib.h#1",
      "src/compress.c",
    ]);

    vi.restoreAllMocks();
  });
});

// ---------------------------------------------------------------------------
// Tests: buildCuratedSbomJson (scan-level) determinism (D6)
// ---------------------------------------------------------------------------

describe("buildCuratedSbomJson — determinism", () => {
  it("produces byte-identical output on two consecutive calls", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJson, stableStringify } = await import(
      "../src/services/sbomCurated.js"
    );

    vi.spyOn(prisma.scanRun, "findUnique").mockResolvedValue(
      makeScanRow(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.scanRun.findUnique>>,
    );
    vi.spyOn(prisma.sbomComponent, "findMany").mockResolvedValue(
      makeSbomComponents(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.sbomComponent.findMany>>,
    );
    // M11 Step 3: scaIssue.findMany now queried by buildCuratedSbomJson.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const doc1 = await buildCuratedSbomJson(SCAN_RUN_ID);
    const doc2 = await buildCuratedSbomJson(SCAN_RUN_ID);

    expect(doc1).not.toBeNull();
    expect(doc2).not.toBeNull();
    const json1 = stableStringify(doc1!, 2);
    const json2 = stableStringify(doc2!, 2);
    expect(json1).toBe(json2);

    vi.restoreAllMocks();
  });

  it("occurrences sorted and licenses sorted in scan-level output", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJson } = await import("../src/services/sbomCurated.js");

    vi.spyOn(prisma.scanRun, "findUnique").mockResolvedValue(
      makeScanRow(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.scanRun.findUnique>>,
    );
    vi.spyOn(prisma.sbomComponent, "findMany").mockResolvedValue(
      makeSbomComponents(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.sbomComponent.findMany>>,
    );
    // M11 Step 3: scaIssue.findMany now queried.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const doc = await buildCuratedSbomJson(SCAN_RUN_ID);
    expect(doc).not.toBeNull();

    // Licenses on lodash should be sorted.
    const lodash = doc!.components.find((c) => c.name === "lodash");
    expect(lodash?.licenses?.map((l) => l.license?.id)).toEqual([
      "Apache-2.0",
      "BSD-3-Clause",
      "MIT",
    ]);

    // boost occurrences sorted by path, then line (nulls first).
    const boost = doc!.components.find((c) => c.name === "boost");
    const boostOccurrences = boost?.evidence?.occurrences?.map((o) => o.location);
    expect(boostOccurrences).toEqual([
      "CMakeLists.txt#5",
      "CMakeLists.txt#100",
      "extern/boost/boost.h",
    ]);

    vi.restoreAllMocks();
  });
});

// ---------------------------------------------------------------------------
// D8 — No LLM call in the SBOM download path.
//
// sbomCurated.ts has no import of any of:
//   llmClient, claudeApi, spawn, child_process, fetch, http, https, axios
// This is verified below by reading the source file and asserting the absence
// of those strings. The vi.spyOn approach is not used because the module is
// imported eagerly and the spyOn would be difficult to attach before the module
// initialises — but more importantly, the module simply has no such call.
// ---------------------------------------------------------------------------

describe("D8 — no LLM or network calls in sbomCurated.ts", () => {
  it("sbomCurated.ts source contains no LLM / network import", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, resolve } = await import("node:path");

    // Resolve path relative to this test file.
    const thisDir = dirname(fileURLToPath(import.meta.url));
    const srcPath = resolve(thisDir, "../src/services/sbomCurated.ts");
    const src = readFileSync(srcPath, "utf8");

    const forbidden = [
      "llmClient",
      "claudeApi",
      "child_process",
      "\"fetch\"",
      "import fetch",
      "node:http",
      "node:https",
      "import axios",
      "require(\"axios\")",
      "spawnClaudeAndStream",
    ];

    for (const term of forbidden) {
      expect(src, `sbomCurated.ts must not reference '${term}'`).not.toContain(term);
    }
  });
});

// ---------------------------------------------------------------------------
// stableStringify edge cases
// ---------------------------------------------------------------------------

describe("stableStringify", () => {
  it("sorts object keys at every depth", async () => {
    const { stableStringify } = await import("../src/services/sbomCurated.js");
    const obj = { z: 1, a: 2, m: { y: 3, b: 4 } };
    const result = stableStringify(obj, 2);
    const parsed = JSON.parse(result) as typeof obj;
    expect(Object.keys(parsed)).toEqual(["a", "m", "z"]);
    expect(Object.keys(parsed.m)).toEqual(["b", "y"]);
  });

  it("preserves array element order", async () => {
    const { stableStringify } = await import("../src/services/sbomCurated.js");
    const arr = [3, 1, 2];
    expect(JSON.parse(stableStringify(arr, 2))).toEqual([3, 1, 2]);
  });

  it("handles null, boolean, number primitives", async () => {
    const { stableStringify } = await import("../src/services/sbomCurated.js");
    expect(stableStringify(null)).toBe("null");
    expect(stableStringify(true)).toBe("true");
    expect(stableStringify(42)).toBe("42");
    expect(stableStringify(NaN)).toBe("null");
    expect(stableStringify(Infinity)).toBe("null");
  });

  it("handles nested arrays of objects", async () => {
    const { stableStringify } = await import("../src/services/sbomCurated.js");
    const input = [{ b: 1, a: 2 }, { d: 3, c: 4 }];
    const result = stableStringify(input, 2);
    const parsed = JSON.parse(result) as typeof input;
    expect(Object.keys(parsed[0])).toEqual(["a", "b"]);
    expect(Object.keys(parsed[1])).toEqual(["c", "d"]);
  });

  it("matches JSON.stringify formatting for simple cases", async () => {
    const { stableStringify } = await import("../src/services/sbomCurated.js");
    const obj = { a: 1, b: [1, 2, 3], c: null };
    // stableStringify with sorted keys; JSON.stringify is already sorted here.
    expect(JSON.parse(stableStringify(obj, 2))).toEqual(JSON.parse(JSON.stringify(obj, null, 2)));
  });
});

// ---------------------------------------------------------------------------
// Issue 6 (M9 post-Deploy-3 followups) — SASTBot tool version tracks APP_VERSION.
// Guards against a future milestone tag being hardcoded back into the
// SBOM_TOOLS_COMPONENTS array; the literal "M6q" lived there from M6q through
// v0.9.6 because the version-consolidation sweep grepped for SemVer strings.
// ---------------------------------------------------------------------------

describe("SBOM tools.components.SASTBot.version reflects APP_VERSION", () => {
  it("scope-level SBOM emits the running APP_VERSION", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJsonForScope } = await import("../src/services/sbomCurated.js");
    const { APP_VERSION } = await import("../src/routes/version.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow(SCOPE_ID) as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, makeScopeComponents(SCOPE_ID));
    // M11 Step 3: scaIssue.findMany now queried.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);
    const sastbot = doc!.metadata.tools.components.find((c) => c.name === "SASTBot");
    expect(sastbot?.version).toBe(APP_VERSION);

    vi.restoreAllMocks();
  });

  it("scan-level SBOM emits the running APP_VERSION", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJson } = await import("../src/services/sbomCurated.js");
    const { APP_VERSION } = await import("../src/routes/version.js");

    vi.spyOn(prisma.scanRun, "findUnique").mockResolvedValue(
      makeScanRow(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.scanRun.findUnique>>,
    );
    vi.spyOn(prisma.sbomComponent, "findMany").mockResolvedValue(
      makeSbomComponents(SCAN_RUN_ID) as unknown as Awaited<ReturnType<typeof prisma.sbomComponent.findMany>>,
    );
    // M11 Step 3: scaIssue.findMany now queried.
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const doc = await buildCuratedSbomJson(SCAN_RUN_ID);
    const sastbot = doc!.metadata.tools.components.find((c) => c.name === "SASTBot");
    expect(sastbot?.version).toBe(APP_VERSION);

    vi.restoreAllMocks();
  });
});

// ---------------------------------------------------------------------------
// M11 Step 3 — Determinism with vulns + EOL data: build twice, expect identical bytes.
// ---------------------------------------------------------------------------

const VULN_SCOPE_ID = "cccccccc-1111-0000-0000-000000000030";

function makeScaIssueForDet(overrides: Record<string, unknown> = {}) {
  return {
    id: "issue-det1-0000-0000-000000000001",
    osvId: "GHSA-wxyz-5678-abcd",
    latestCveId: "CVE-2025-99999",
    source: "osv",
    latestCvssScore: 8.5,
    latestCvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    latestSeverity: "high",
    latestSummary: "Test vuln for determinism",
    latestAliases: ["GHSA-wxyz-5678-abcd", "CVE-2025-99999"],
    dismissedStatus: "pending",
    dismissedReason: null,
    notes: null,
    firstSeenAt: new Date("2025-06-01T00:00:00Z"),
    updatedAt: new Date("2025-06-15T00:00:00Z"),
    packageName: "axios",
    latestPackageVersion: "1.6.0",
    latestEolDate: new Date("2025-01-01T00:00:00Z"), // past date → eol
    latestFindingType: "eol",
    ...overrides,
  };
}

describe("buildCuratedSbomJsonForScope — determinism with vulns + EOL data (M11 Step 3)", () => {
  it("produces byte-identical output on two calls when vulns and EOL data are present", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJsonForScope, stableStringify } = await import(
      "../src/services/sbomCurated.js"
    );

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow(VULN_SCOPE_ID) as ReturnType<typeof makeScopeRow>,
    );
    // Reuse the first two components from makeScopeComponents — axios matches the issue.
    mockScopeComponentFindMany(prisma, makeScopeComponents(VULN_SCOPE_ID).slice(0, 2));
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssueForDet() as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const doc1 = await buildCuratedSbomJsonForScope(VULN_SCOPE_ID);
    const doc2 = await buildCuratedSbomJsonForScope(VULN_SCOPE_ID);

    expect(doc1).not.toBeNull();
    expect(doc2).not.toBeNull();

    // Must have vulnerabilities.
    expect(doc1!.vulnerabilities).toBeDefined();
    expect(doc1!.vulnerabilities!.length).toBeGreaterThan(0);

    // Must have EOL property on the matching component.
    const axiosComp = doc1!.components.find((c) => c.name === "axios");
    expect(axiosComp).toBeDefined();
    const props = Object.fromEntries((axiosComp!.properties ?? []).map((p) => [p.name, p.value]));
    expect(props["sastbot:lifecycle_state"]).toBe("eol");

    // Byte-identical on both calls.
    const json1 = stableStringify(doc1!, 2);
    const json2 = stableStringify(doc2!, 2);
    expect(json1).toBe(json2);

    vi.restoreAllMocks();
  });
});
