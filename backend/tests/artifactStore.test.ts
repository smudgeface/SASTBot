/**
 * artifactStore smoke tests.
 *
 * Strategy:
 *   - Create a tmp directory and point process.env.ARTIFACT_DIR at it so the
 *     module reads the overridden value at call time.
 *   - Verify write → read round-trip for string and Buffer bodies.
 *   - Verify atomic write: no .tmp file left behind after writeArtifact.
 *   - Verify deleteArtifact and tryReadArtifact return null on missing file.
 *   - Verify deleteScanArtifacts removes both canonical paths.
 */

import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  deleteArtifact,
  deleteScanArtifacts,
  readArtifact,
  sarifPathFor,
  sbomPathFor,
  tryReadArtifact,
  writeArtifact,
} from "../src/services/artifactStore.js";

describe("artifactStore", () => {
  let tmpDir: string;
  let originalArtifactDir: string | undefined;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "sastbot-art-"));
    originalArtifactDir = process.env["ARTIFACT_DIR"];
    process.env["ARTIFACT_DIR"] = tmpDir;
  });

  afterEach(async () => {
    // Restore original env
    if (originalArtifactDir === undefined) {
      delete process.env["ARTIFACT_DIR"];
    } else {
      process.env["ARTIFACT_DIR"] = originalArtifactDir;
    }
    // Clean up tmp dir
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  // ---------------------------------------------------------------------------
  // Path helpers
  // ---------------------------------------------------------------------------

  it("sbomPathFor returns the expected path", () => {
    const id = "test-scan-id-123";
    expect(sbomPathFor(id)).toBe(path.join(tmpDir, "sbom", `${id}.json`));
  });

  it("sarifPathFor returns the expected path", () => {
    const id = "test-scan-id-456";
    expect(sarifPathFor(id)).toBe(path.join(tmpDir, "sarif", `${id}.sarif.json`));
  });

  // ---------------------------------------------------------------------------
  // writeArtifact + readArtifact round-trip
  // ---------------------------------------------------------------------------

  it("writes a string body and reads it back", async () => {
    const filePath = path.join(tmpDir, "sbom", "run1.json");
    const content = JSON.stringify({ cyclonedxVersion: "1.7", components: [] });

    await writeArtifact(filePath, content);

    const result = await readArtifact(filePath);
    expect(result.toString("utf8")).toBe(content);
  });

  it("writes a Buffer body and reads it back", async () => {
    const filePath = path.join(tmpDir, "sarif", "run2.sarif.json");
    const content = Buffer.from(JSON.stringify({ version: "2.1.0", runs: [] }));

    await writeArtifact(filePath, content);

    const result = await readArtifact(filePath);
    expect(result).toStrictEqual(content);
  });

  it("creates parent directories automatically", async () => {
    const filePath = path.join(tmpDir, "nested", "deep", "file.json");

    await writeArtifact(filePath, "hello");

    const result = await readArtifact(filePath);
    expect(result.toString("utf8")).toBe("hello");
  });

  // ---------------------------------------------------------------------------
  // Atomic write: no .tmp file left behind
  // ---------------------------------------------------------------------------

  it("leaves no .tmp file after a successful write", async () => {
    const filePath = path.join(tmpDir, "sbom", "run3.json");
    const tmpPath = `${filePath}.tmp`;

    await writeArtifact(filePath, "atomic-test");

    // The .tmp sibling must not exist after rename completes
    const tmpExists = await fs.access(tmpPath).then(() => true).catch(() => false);
    expect(tmpExists).toBe(false);

    // But the real file must be there
    const exists = await fs.access(filePath).then(() => true).catch(() => false);
    expect(exists).toBe(true);
  });

  // ---------------------------------------------------------------------------
  // tryReadArtifact
  // ---------------------------------------------------------------------------

  it("tryReadArtifact returns null for a missing file", async () => {
    const result = await tryReadArtifact(path.join(tmpDir, "nonexistent.json"));
    expect(result).toBeNull();
  });

  it("tryReadArtifact returns the content for an existing file", async () => {
    const filePath = path.join(tmpDir, "sbom", "run4.json");
    await writeArtifact(filePath, "exists");

    const result = await tryReadArtifact(filePath);
    expect(result).not.toBeNull();
    expect(result!.toString("utf8")).toBe("exists");
  });

  // ---------------------------------------------------------------------------
  // deleteArtifact
  // ---------------------------------------------------------------------------

  it("deleteArtifact removes a file", async () => {
    const filePath = path.join(tmpDir, "sbom", "run5.json");
    await writeArtifact(filePath, "to-be-deleted");

    await deleteArtifact(filePath);

    const result = await tryReadArtifact(filePath);
    expect(result).toBeNull();
  });

  it("deleteArtifact does not throw for a missing file", async () => {
    await expect(
      deleteArtifact(path.join(tmpDir, "does-not-exist.json"))
    ).resolves.toBeUndefined();
  });

  // ---------------------------------------------------------------------------
  // deleteScanArtifacts
  // ---------------------------------------------------------------------------

  it("deleteScanArtifacts removes both SBOM and SARIF files", async () => {
    const scanRunId = "scan-run-abc123";
    const sbomPath = sbomPathFor(scanRunId);
    const sarifPath = sarifPathFor(scanRunId);

    await writeArtifact(sbomPath, '{"sbom":true}');
    await writeArtifact(sarifPath, '{"sarif":true}');

    // Confirm they exist
    expect(await tryReadArtifact(sbomPath)).not.toBeNull();
    expect(await tryReadArtifact(sarifPath)).not.toBeNull();

    await deleteScanArtifacts(scanRunId);

    // Both should be gone
    expect(await tryReadArtifact(sbomPath)).toBeNull();
    expect(await tryReadArtifact(sarifPath)).toBeNull();
  });

  it("deleteScanArtifacts is idempotent when files do not exist", async () => {
    await expect(
      deleteScanArtifacts("scan-run-nonexistent")
    ).resolves.toBeUndefined();
  });
});
