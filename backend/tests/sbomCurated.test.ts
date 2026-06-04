/**
 * Unit tests for buildCuratedSbomJsonForScope (M9 Stream C3 + M11 Step 3 + M14).
 *
 * Strategy:
 *   - Mock prisma so the function never touches a real DB.
 *   - Assert the function reads scope_components, not sbom_components.
 *   - Assert operator-edited name appears in the JSON output.
 *   - Assert serialNumber derives from the scope id.
 *
 * M11 Step 3 additions:
 *   - Vulnerability emitted with all required fields when sca_issue has full CVSS data.
 *   - analysis.state mapped correctly for each dismissedStatus (table-driven).
 *   - affects[].ref populated when (name, version) matches a component; empty when no match.
 *   - references[] populated and sorted lex when latestAliases non-empty; absent otherwise.
 *   - Per-component EOL properties: eol_date + lifecycle_state=eol for past dates,
 *     active for future, deprecated when latestFindingType==='deprecated' and no eol date.
 *
 * M14 additions:
 *   - buildCuratedSbomJsonForScope now makes two scopeComponent.findMany calls:
 *     1) where: { dismissedStatus: "active" } → active components for the components[] list.
 *     2) where: { dismissedStatus: { in: ["ignored", "not_found"] } } → excluded names for
 *        filtering sca_issues.
 *   - Mocks use mockImplementation to differentiate the two calls by their where filter.
 *   - Ignored/not_found components' SCA issues are excluded from vulnerabilities[].
 */

import { randomBytes } from "node:crypto";
import { beforeAll, describe, expect, it, vi } from "vitest";

// Set required env vars before any module with side-effects loads.
beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
});

// ---------------------------------------------------------------------------
// Minimal type helpers matching the Prisma return shapes we care about.
// ---------------------------------------------------------------------------

const SCOPE_ID = "aaaaaaaa-0000-0000-0000-000000000001";
const SCOPE_RUN_ID = "bbbbbbbb-0000-0000-0000-000000000002";

function makeScopeComponentBase(overrides: Record<string, unknown> = {}) {
  return {
    id: "cccccccc-0000-0000-0000-000000000003",
    scopeId: SCOPE_ID,
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
    usage: [],
    llmEvidence: null,
    latestLlmEvidence: null,
    cpe: null,
    latestCpe: null,
    source: "scan",
    dismissedStatus: "active",
    dismissedReason: null,
    dismissedAt: null,
    firstSeenScanRunId: SCOPE_RUN_ID,
    lastSeenScanRunId: SCOPE_RUN_ID,
    lastSeenAt: new Date("2026-05-22T00:00:00Z"),
    createdAt: new Date("2026-05-01T00:00:00Z"),
    updatedAt: new Date("2026-05-22T00:00:00Z"),
    ...overrides,
  };
}

function makeScopeRow() {
  return {
    id: SCOPE_ID,
    path: "/",
    lastScanRunId: SCOPE_RUN_ID,
    lastScanCompletedAt: new Date("2026-05-20T00:00:00Z"),
    createdAt: new Date("2026-05-01T00:00:00Z"),
    orgId: null,
    isActive: true,
    repoId: "dddddddd-0000-0000-0000-000000000004",
    displayName: null,
    repo: { name: "my-repo", defaultBranch: "main" },
  };
}

type ScopeComponentRow = Awaited<ReturnType<typeof import("../src/db.js").prisma.scopeComponent.findMany>>[number];

/**
 * Helper: mock scopeComponent.findMany to handle the two calls made by
 * buildCuratedSbomJsonForScope (M14):
 *   1st call: { dismissedStatus: "active" } → activeRows
 *   2nd call: { dismissedStatus: { in: [...] } } → excludedRows (default [])
 */
function mockScopeComponentFindMany(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  prisma: any,
  activeRows: ScopeComponentRow[],
  excludedRows: ScopeComponentRow[] = [],
) {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  vi.spyOn(prisma.scopeComponent, "findMany").mockImplementation((args: any) => {
    const where = args?.where ?? {};
    // Second call uses { dismissedStatus: { in: [...] } }
    if (where.dismissedStatus && typeof where.dismissedStatus === "object" && "in" in where.dismissedStatus) {
      return Promise.resolve(excludedRows) as ReturnType<typeof prisma.scopeComponent.findMany>;
    }
    // First call uses { dismissedStatus: "active" } or unset
    return Promise.resolve(activeRows) as ReturnType<typeof prisma.scopeComponent.findMany>;
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("buildCuratedSbomJsonForScope", () => {
  it("returns doc with operator-edited name and never reads sbom_components", async () => {
    // Spy on prisma BEFORE the function module loads.
    const { prisma } = await import("../src/db.js");

    // Spy on sbomComponent.findMany — it must never be called.
    const sbomSpy = vi.spyOn(prisma.sbomComponent, "findMany").mockResolvedValue([]);

    // Stub scanScope.findUnique and scopeComponent.findMany.
    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );

    const operatorRenamedName = "axios-operator-renamed";
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase({ name: operatorRenamedName, source: "manual_override" }) as ScopeComponentRow,
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );

    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    // The function must not read sbom_components.
    expect(sbomSpy).not.toHaveBeenCalled();

    // Basic structure.
    expect(doc).not.toBeNull();
    expect(doc!.serialNumber).toBe(`urn:uuid:${SCOPE_ID}`);
    expect(doc!.bomFormat).toBe("CycloneDX");
    expect(doc!.specVersion).toBe("1.7");

    // Operator-edited name is present.
    const names = doc!.components.map((c) => c.name);
    expect(names).toContain(operatorRenamedName);

    // Metadata version is scope's lastScanRunId.
    expect(doc!.metadata.component?.version).toBe(SCOPE_RUN_ID);

    // Licenses come from latestLicenses.
    const axiosComp = doc!.components.find((c) => c.name === operatorRenamedName)!;
    expect(axiosComp.licenses).toEqual([{ license: { id: "MIT" } }]);

    vi.restoreAllMocks();
  });

  it("returns null when scope has no active components", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, []);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );

    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);
    expect(doc).toBeNull();

    vi.restoreAllMocks();
  });

  it("returns null when scope does not exist", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(null);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );

    const doc = await buildCuratedSbomJsonForScope("nonexistent-id");
    expect(doc).toBeNull();

    vi.restoreAllMocks();
  });
});

// ---------------------------------------------------------------------------
// M11 Step 3 — vulnerability + EOL property assertions
// ---------------------------------------------------------------------------

/** Minimal ScaIssue shape accepted by the buildCuratedSbomJsonForScope spy. */
function makeScaIssue(overrides: Record<string, unknown> = {}) {
  return {
    id: "issue-0001-0000-0000-000000000001",
    osvId: "GHSA-abcd-1234-efgh",
    latestCveId: "CVE-2024-12345",
    source: "osv",
    latestCvssScore: 9.1,
    latestCvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    latestSeverity: "critical",
    latestSummary: "Remote code execution in axios",
    latestAliases: ["GHSA-abcd-1234-efgh", "CVE-2024-12345"],
    dismissedStatus: "pending",
    dismissedReason: null,
    notes: null,
    firstSeenAt: new Date("2026-01-01T00:00:00Z"),
    updatedAt: new Date("2026-05-01T00:00:00Z"),
    packageName: "axios",
    latestPackageVersion: "1.6.0",
    latestEolDate: null,
    latestFindingType: "vulnerability",
    ...overrides,
  };
}

describe("buildCuratedSbomJsonForScope — vulnerabilities[] (M11 Step 3)", () => {
  it("emits a vulnerability entry with all required CycloneDX 1.7 fields", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue() as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(doc).not.toBeNull();
    expect(doc!.vulnerabilities).toBeDefined();
    expect(doc!.vulnerabilities!).toHaveLength(1);

    const vuln = doc!.vulnerabilities![0];
    // Required fields per CycloneDX 1.7
    expect(vuln["bom-ref"]).toBe("CVE-2024-12345");
    expect(vuln.id).toBe("CVE-2024-12345");
    expect(vuln.source).toBeDefined();
    expect(vuln.source.name).toBe("OSV.dev");
    expect(vuln.analysis).toBeDefined();
    expect(vuln.analysis.state).toBe("in_triage");
    expect(vuln.analysis.firstIssued).toBe("2026-01-01T00:00:00.000Z");
    expect(vuln.analysis.lastUpdated).toBe("2026-05-01T00:00:00.000Z");
    // Optional but populated
    expect(vuln.ratings).toBeDefined();
    expect(vuln.ratings![0].score).toBe(9.1);
    expect(vuln.ratings![0].method).toBe("CVSSv31");
    expect(vuln.description).toBe("Remote code execution in axios");

    vi.restoreAllMocks();
  });

  it("analysis.state is mapped correctly for every dismissedStatus value", async () => {
    const { prisma } = await import("../src/db.js");
    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );

    const cases: Array<{ dismissedStatus: string; expectedState: string }> = [
      { dismissedStatus: "fixed", expectedState: "resolved" },
      { dismissedStatus: "suppressed", expectedState: "not_affected" },
      { dismissedStatus: "false_positive", expectedState: "false_positive" },
      { dismissedStatus: "pending", expectedState: "in_triage" },
      // confirmed/planned = operator-affirmed affected & unremediated → VEX exploitable
      { dismissedStatus: "confirmed", expectedState: "exploitable" },
      { dismissedStatus: "planned", expectedState: "exploitable" },
    ];

    for (const { dismissedStatus, expectedState } of cases) {
      vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValueOnce(
        makeScopeRow() as ReturnType<typeof makeScopeRow>,
      );
      mockScopeComponentFindMany(prisma, [
        makeScopeComponentBase() as ScopeComponentRow,
      ]);
      vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValueOnce([
        makeScaIssue({ dismissedStatus }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
      ]);

      const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);
      const state = doc!.vulnerabilities![0].analysis.state;
      expect(state, `dismissedStatus=${dismissedStatus}`).toBe(expectedState);
      vi.restoreAllMocks();
    }
  });

  it("affects[].ref matches the component purl when name+version aligns", async () => {
    const { prisma } = await import("../src/db.js");

    // Component is axios@1.6.0 with purl pkg:npm/axios@1.6.0.
    // ScaIssue packageName=axios, latestPackageVersion=1.6.0 → should match.
    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue() as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const affects = doc!.vulnerabilities![0].affects;
    expect(affects).toHaveLength(1);
    expect(affects[0].ref).toBe("pkg:npm/axios@1.6.0");

    vi.restoreAllMocks();
  });

  it("affects[] is empty when component name+version does not match any component", async () => {
    const { prisma } = await import("../src/db.js");

    // Issue references lodash@4.0.0 but the only component is axios@1.6.0.
    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({ packageName: "lodash", latestPackageVersion: "4.0.0" }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const affects = doc!.vulnerabilities![0].affects;
    expect(affects).toHaveLength(0);

    vi.restoreAllMocks();
  });

  it("references[] is sorted lexicographically when latestAliases is non-empty", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({
        latestAliases: ["CVE-2024-12345", "GHSA-abcd-1234-efgh"],
      }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const refs = doc!.vulnerabilities![0].references;
    expect(refs).toBeDefined();
    const ids = refs!.map((r) => r.id);
    // CVE sorts before GHSA lexicographically
    expect(ids).toEqual([...ids].sort());
    expect(ids).toContain("CVE-2024-12345");
    expect(ids).toContain("GHSA-abcd-1234-efgh");

    vi.restoreAllMocks();
  });

  it("references[] is absent when latestAliases is empty", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({ latestAliases: [] }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(doc!.vulnerabilities![0].references).toBeUndefined();

    vi.restoreAllMocks();
  });

  it("no vulnerabilities[] key when scaIssues list is empty", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(doc).not.toBeNull();
    expect(doc!.vulnerabilities).toBeUndefined();

    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // M14: ignored/not_found component SCA issue exclusion
  // ---------------------------------------------------------------------------

  it("(M14) excludes vulnerabilities for ignored components from scope SBOM", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    // Active component: axios. Excluded: lodash (ignored).
    mockScopeComponentFindMany(
      prisma,
      [makeScopeComponentBase() as ScopeComponentRow],
      [makeScopeComponentBase({ name: "lodash", dismissedStatus: "ignored" }) as ScopeComponentRow],
    );
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({ packageName: "axios" }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
      makeScaIssue({ id: "issue-0002", osvId: "CVE-2023-99999", latestCveId: "CVE-2023-99999", packageName: "lodash" }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(doc).not.toBeNull();
    // Only axios vulnerability should appear — lodash is ignored
    expect(doc!.vulnerabilities).toHaveLength(1);
    expect(doc!.vulnerabilities![0].id).toBe("CVE-2024-12345");

    vi.restoreAllMocks();
  });

  it("(M14) excludes vulnerabilities for not_found components from scope SBOM", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    // Active: axios. Not_found: zlib.
    mockScopeComponentFindMany(
      prisma,
      [makeScopeComponentBase() as ScopeComponentRow],
      [makeScopeComponentBase({ name: "zlib", dismissedStatus: "not_found" }) as ScopeComponentRow],
    );
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({ packageName: "axios" }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
      makeScaIssue({ id: "issue-0003", osvId: "CVE-2022-77777", latestCveId: "CVE-2022-77777", packageName: "zlib" }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    expect(doc).not.toBeNull();
    // Only axios vulnerability should appear — zlib is not_found
    expect(doc!.vulnerabilities).toHaveLength(1);
    expect(doc!.vulnerabilities![0].id).toBe("CVE-2024-12345");

    vi.restoreAllMocks();
  });
});

describe("buildCuratedSbomJsonForScope — per-component EOL properties (M11 Step 3)", () => {
  it("emits sastbot:eol_date and lifecycle_state=eol for a past EOL date", async () => {
    const { prisma } = await import("../src/db.js");
    const pastDate = new Date("2025-01-01T00:00:00Z"); // in the past

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({
        latestEolDate: pastDate,
        latestFindingType: "eol",
      }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const comp = doc!.components.find((c) => c.name === "axios")!;
    const props = Object.fromEntries((comp.properties ?? []).map((p) => [p.name, p.value]));
    expect(props["sastbot:eol_date"]).toBe("2025-01-01");
    expect(props["sastbot:lifecycle_state"]).toBe("eol");

    vi.restoreAllMocks();
  });

  it("emits lifecycle_state=active for a future EOL date", async () => {
    const { prisma } = await import("../src/db.js");
    const futureDate = new Date("2099-12-31T00:00:00Z");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({
        latestEolDate: futureDate,
        latestFindingType: "eol",
      }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const comp = doc!.components.find((c) => c.name === "axios")!;
    const props = Object.fromEntries((comp.properties ?? []).map((p) => [p.name, p.value]));
    expect(props["sastbot:eol_date"]).toBe("2099-12-31");
    expect(props["sastbot:lifecycle_state"]).toBe("active");

    vi.restoreAllMocks();
  });

  it("emits lifecycle_state=deprecated when latestFindingType=deprecated and no eol date", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({
        latestEolDate: null,
        latestFindingType: "deprecated",
      }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const comp = doc!.components.find((c) => c.name === "axios")!;
    const props = Object.fromEntries((comp.properties ?? []).map((p) => [p.name, p.value]));
    expect(props["sastbot:lifecycle_state"]).toBe("deprecated");
    expect(props["sastbot:eol_date"]).toBeUndefined();

    vi.restoreAllMocks();
  });

  it("emits no EOL properties for a component with only a plain vulnerability issue", async () => {
    const { prisma } = await import("../src/db.js");

    vi.spyOn(prisma.scanScope, "findUnique").mockResolvedValue(
      makeScopeRow() as ReturnType<typeof makeScopeRow>,
    );
    mockScopeComponentFindMany(prisma, [
      makeScopeComponentBase() as ScopeComponentRow,
    ]);
    vi.spyOn(prisma.scaIssue, "findMany").mockResolvedValue([
      makeScaIssue({
        latestEolDate: null,
        latestFindingType: "vulnerability",
      }) as Awaited<ReturnType<typeof prisma.scaIssue.findMany>>[number],
    ]);

    const { buildCuratedSbomJsonForScope } = await import(
      "../src/services/sbomCurated.js"
    );
    const doc = await buildCuratedSbomJsonForScope(SCOPE_ID);

    const comp = doc!.components.find((c) => c.name === "axios")!;
    const propNames = (comp.properties ?? []).map((p) => p.name);
    expect(propNames).not.toContain("sastbot:eol_date");
    expect(propNames).not.toContain("sastbot:lifecycle_state");

    vi.restoreAllMocks();
  });
});
