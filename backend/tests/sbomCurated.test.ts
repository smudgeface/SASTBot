/**
 * Unit tests for buildCuratedSbomJsonForScope (M9 Stream C3).
 *
 * Strategy:
 *   - Mock prisma so the function never touches a real DB.
 *   - Assert the function reads scope_components, not sbom_components.
 *   - Assert operator-edited name appears in the JSON output.
 *   - Assert serialNumber derives from the scope id.
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
    vi.spyOn(prisma.scopeComponent, "findMany").mockResolvedValue([
      makeScopeComponentBase({ name: operatorRenamedName, source: "manual_override" }) as Parameters<
        typeof prisma.scopeComponent.findMany
      >[0] extends undefined ? never : Awaited<ReturnType<typeof prisma.scopeComponent.findMany>>[number],
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
    vi.spyOn(prisma.scopeComponent, "findMany").mockResolvedValue([]);

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
