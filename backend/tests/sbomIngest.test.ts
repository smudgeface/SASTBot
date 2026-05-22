/**
 * Unit tests for ingestSbomFromArtifact (M9 Stream E1).
 *
 * The comprehensive round-trip, idempotency, discoveryMethod, isDevOnly,
 * componentCount, and error-handling tests live in sbomFileFirst.test.ts.
 *
 * This file retains a smoke test that the module exports the function and
 * the no-file-found error message is correct, so the test suite still has
 * a file here for backwards-compat with any CI selectors that reference it.
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

let tmpDir: string;
let originalArtifactDir: string | undefined;

beforeEach(async () => {
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-sbom-ingest-"));
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

// Minimal DB mock so the module loads cleanly.
vi.mock("../src/db.js", () => ({
  prisma: {
    $transaction: vi.fn(),
  },
}));

const SCAN_RUN_ID = randomUUID();

describe("ingestSbomFromArtifact", () => {
  it("throws 'no SBOM artifact found' when no file exists on disk", async () => {
    const { ingestSbomFromArtifact } = await import("../src/services/sbomIngest.js");
    await expect(ingestSbomFromArtifact(SCAN_RUN_ID)).rejects.toThrow(
      `sbom_ingest: no SBOM artifact found for scan ${SCAN_RUN_ID}`,
    );
  });
});
