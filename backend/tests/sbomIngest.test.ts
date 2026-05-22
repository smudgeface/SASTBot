/**
 * Unit tests for ingestSbomFromArtifact (M9 Stream B2 skeleton).
 *
 * Strategy:
 *  - The cdxgen short-circuit happens in worker.ts, not in the service.
 *  - The service body is a skeleton that always throws with a documented message.
 *  - Test 1: no artifact file on disk → throws "no SBOM artifact found".
 *  - Test 2: artifact file exists → throws the B7 "not yet implemented" message.
 *
 * When B7 (upload route) ships, these tests should be replaced with real
 * component-ingestion assertions. The skeleton-throw tests are intentionally
 * the ONLY tests here — testing the worker's cdxgen short-circuit is an
 * integration concern, not a unit-test concern for this service.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { randomBytes } from "node:crypto";

import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";

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
});

const SCAN_RUN_ID = "bbbbbbbb-ingest-0000-0000-000000000001";

describe("ingestSbomFromArtifact", () => {
  it("throws 'no SBOM artifact found' when no file exists on disk", async () => {
    const { ingestSbomFromArtifact } = await import("../src/services/sbomIngest.js");

    await expect(ingestSbomFromArtifact(SCAN_RUN_ID)).rejects.toThrow(
      `sbom_ingest: no SBOM artifact found for scan ${SCAN_RUN_ID}`,
    );
  });

  it("throws the B7 not-yet-implemented message when the artifact file exists", async () => {
    const { writeArtifact, sbomPathFor } = await import("../src/services/artifactStore.js");
    const { ingestSbomFromArtifact } = await import("../src/services/sbomIngest.js");

    // Write a minimal stub SBOM artifact so the no-file guard passes.
    await writeArtifact(
      sbomPathFor(SCAN_RUN_ID),
      JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.7", components: [] }),
    );

    await expect(ingestSbomFromArtifact(SCAN_RUN_ID)).rejects.toThrow(
      "sbom_ingest: external-upload flow not yet implemented (B7)",
    );
  });
});
