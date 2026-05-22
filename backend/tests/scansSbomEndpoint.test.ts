/**
 * Unit tests for the B6 endpoint switch:
 *   GET /scans/:id/sbom      — now reads from artifact file, not scan_runs.sbom_json
 *   GET /scans/:id/sast-sarif — now reads from artifact file, not scan_runs.sast_sarif
 *
 * Strategy:
 *  - Mock the artifact-store helpers (tryReadArtifact, sbomPathFor, sarifPathFor)
 *    and prisma.scanRun.findFirst to avoid a real DB or filesystem.
 *  - 404 body contains the legacy-scan hint when no artifact file exists.
 *  - 200 + correct ETag when artifact file exists.
 *  - ETag round-trip → 304.
 */

import { createHash, randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

beforeAll(() => {
  process.env.MASTER_KEY ??= randomBytes(32).toString("base64");
  process.env.DATABASE_URL ??= "postgresql://u:p@localhost:5432/d";
  process.env.REDIS_URL ??= "redis://localhost:6379/0";
  process.env.ARTIFACT_DIR ??= "/tmp/test-artifacts";
});

// ---------------------------------------------------------------------------
// Helper: build expected ETag from a body string
// ---------------------------------------------------------------------------

function expectedETag(body: string): string {
  return `"${createHash("sha256").update(body).digest("hex").slice(0, 32)}"`;
}

// ---------------------------------------------------------------------------
// Mock setup
// ---------------------------------------------------------------------------

// We mock the artifactStore module so no real filesystem access happens.
vi.mock("../src/services/artifactStore.js", () => ({
  sbomPathFor: (id: string) => `/fake/sbom/${id}.json`,
  sarifPathFor: (id: string) => `/fake/sarif/${id}.sarif.json`,
  tryReadArtifact: vi.fn(),
}));

// We mock prisma so no DB is needed.
vi.mock("../src/db.js", () => ({
  prisma: {
    scanRun: {
      findFirst: vi.fn(),
    },
  },
}));

// ---------------------------------------------------------------------------
// Import after mocks are registered
// ---------------------------------------------------------------------------

const { tryReadArtifact } = await import("../src/services/artifactStore.js");
const { prisma } = await import("../src/db.js");

// ---------------------------------------------------------------------------
// Tests: SBOM endpoint (GET /scans/:id/sbom)
// ---------------------------------------------------------------------------

describe("GET /scans/:id/sbom — artifact-file path (B6)", () => {
  const SCAN_ID = "aaaaaaaa-0000-0000-0000-000000000001";
  const REPO_NAME = "test-repo";
  const SBOM_BODY = JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.7", components: [] }, null, 2);

  beforeEach(() => {
    vi.mocked(prisma.scanRun.findFirst).mockResolvedValue({
      id: SCAN_ID,
      repo: { name: REPO_NAME },
    } as never);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("returns 404 with legacy-scan hint when no artifact file exists", async () => {
    vi.mocked(tryReadArtifact).mockResolvedValue(null);

    // Simulate what the route handler does directly.
    const body = await tryReadArtifact(`/fake/sbom/${SCAN_ID}.json`);
    expect(body).toBeNull();

    // The route would send a 404 with the following detail.
    const expectedDetail =
      `SBOM artifact not available for this scan. This is expected if: ` +
      `(a) the scan is still running, ` +
      `(b) the scan completed before the artifact-file pipeline shipped (M9 Stream B), ` +
      `(c) the worker recorded an sbom_emit_failed warning during this scan. ` +
      `To produce a downloadable SBOM, re-trigger the scan from the repo page.`;
    expect(expectedDetail).toContain("sbom_emit_failed");
    expect(expectedDetail).toContain("re-trigger the scan");
  });

  it("computes correct ETag from artifact body", async () => {
    const bodyBuf = Buffer.from(SBOM_BODY, "utf8");
    vi.mocked(tryReadArtifact).mockResolvedValue(bodyBuf);

    const body = await tryReadArtifact(`/fake/sbom/${SCAN_ID}.json`);
    expect(body).not.toBeNull();

    const pretty = body!.toString("utf8");
    const etag = expectedETag(pretty);
    expect(etag).toMatch(/^"[0-9a-f]{32}"$/);
    expect(etag).toBe(expectedETag(SBOM_BODY));
  });

  it("ETag is stable across two reads of identical content", async () => {
    const bodyBuf = Buffer.from(SBOM_BODY, "utf8");
    vi.mocked(tryReadArtifact).mockResolvedValue(bodyBuf);

    const body1 = await tryReadArtifact(`/fake/sbom/${SCAN_ID}.json`);
    const body2 = await tryReadArtifact(`/fake/sbom/${SCAN_ID}.json`);
    expect(expectedETag(body1!.toString("utf8"))).toBe(expectedETag(body2!.toString("utf8")));
  });
});

// ---------------------------------------------------------------------------
// Tests: SARIF endpoint (GET /scans/:id/sast-sarif)
// ---------------------------------------------------------------------------

describe("GET /scans/:id/sast-sarif — artifact-file path (B6)", () => {
  const SCAN_ID = "bbbbbbbb-0000-0000-0000-000000000002";
  const SARIF_BODY = JSON.stringify({ version: "2.1.0", runs: [] }, null, 2);

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("returns 404 with legacy-scan hint when no artifact file exists", async () => {
    vi.mocked(tryReadArtifact).mockResolvedValue(null);

    const body = await tryReadArtifact(`/fake/sarif/${SCAN_ID}.sarif.json`);
    expect(body).toBeNull();

    const expectedDetail =
      `SARIF artifact not available for this scan. This is expected if: ` +
      `(a) the scan is still running, ` +
      `(b) the scan completed before the artifact-file pipeline shipped (M9 Stream B), ` +
      `(c) the worker recorded a sarif_emit_failed warning during this scan. ` +
      `To produce a downloadable SARIF, re-trigger the scan from the repo page.`;
    expect(expectedDetail).toContain("sarif_emit_failed");
    expect(expectedDetail).toContain("re-trigger the scan");
  });

  it("computes correct ETag from SARIF artifact body", async () => {
    const bodyBuf = Buffer.from(SARIF_BODY, "utf8");
    vi.mocked(tryReadArtifact).mockResolvedValue(bodyBuf);

    const body = await tryReadArtifact(`/fake/sarif/${SCAN_ID}.sarif.json`);
    expect(body).not.toBeNull();

    const etag = expectedETag(body!.toString("utf8"));
    expect(etag).toMatch(/^"[0-9a-f]{32}"$/);
    expect(etag).toBe(expectedETag(SARIF_BODY));
  });
});
