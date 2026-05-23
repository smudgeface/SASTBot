/**
 * artifactStore.ts — filesystem storage for canonical scan artifacts.
 *
 * Provides stable on-disk paths for the two artifact types produced per scan run:
 *   - SBOM:  ${ARTIFACT_DIR}/sbom/${scanRunId}.json
 *   - SARIF: ${ARTIFACT_DIR}/sarif/${scanRunId}.sarif.json
 *
 * Reads ARTIFACT_DIR from process.env at call time (not module-init) so that
 * tests can set process.env.ARTIFACT_DIR before importing or calling any function.
 *
 * Writes are atomic: data is first written to a `.tmp` sibling then renamed
 * into place, so a reader never observes a partially-written file.
 *
 * No Prisma dependency — this module is pure filesystem I/O.
 */

import * as fs from "node:fs/promises";
import * as path from "node:path";

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

function artifactDir(): string {
  return process.env["ARTIFACT_DIR"] ?? "/var/lib/sastbot/artifacts";
}

/** Canonical path for the per-scan SBOM artifact. */
export function sbomPathFor(scanRunId: string): string {
  return path.join(artifactDir(), "sbom", `${scanRunId}.json`);
}

/** Canonical path for the per-scan SARIF artifact. */
export function sarifPathFor(scanRunId: string): string {
  return path.join(artifactDir(), "sarif", `${scanRunId}.sarif.json`);
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/**
 * Write `body` to `filePath` atomically.
 *
 * Strategy:
 *   1. Ensure the parent directory exists (recursive mkdir, idempotent).
 *   2. Write to `${filePath}.tmp`.
 *   3. Rename into place (atomic on POSIX when src and dst are on the same fs).
 *
 * UTF-8 string bodies are written with the `'utf8'` encoding.
 * Buffer bodies are written as raw bytes.
 */
export async function writeArtifact(filePath: string, body: string | Buffer): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });

  const tmp = `${filePath}.tmp`;
  if (typeof body === "string") {
    await fs.writeFile(tmp, body, "utf8");
  } else {
    await fs.writeFile(tmp, body);
  }
  await fs.rename(tmp, filePath);
}

/**
 * Read `filePath` and return its raw bytes.
 * Throws the native ENOENT error unmodified when the file does not exist —
 * callers that serve this over HTTP should map it to a 404.
 */
export async function readArtifact(filePath: string): Promise<Buffer> {
  return fs.readFile(filePath);
}

/**
 * Like `readArtifact` but returns `null` instead of throwing on ENOENT.
 * Other errors (EACCES, etc.) are still rethrown.
 */
export async function tryReadArtifact(filePath: string): Promise<Buffer | null> {
  try {
    return await fs.readFile(filePath);
  } catch (err) {
    if (isEnoent(err)) return null;
    throw err;
  }
}

/**
 * Delete the file at `filePath`. A missing file is silently ignored
 * (`force: true` semantics — equivalent to `rm -f`).
 */
export async function deleteArtifact(filePath: string): Promise<void> {
  await fs.rm(filePath, { force: true });
}

/**
 * Delete both artifact files (SBOM + SARIF) for a scan run.
 * Should be called after the corresponding `scan_runs` row is deleted from
 * the DB. Missing files are silently ignored.
 */
export async function deleteScanArtifacts(scanRunId: string): Promise<void> {
  await Promise.all([
    deleteArtifact(sbomPathFor(scanRunId)),
    deleteArtifact(sarifPathFor(scanRunId)),
  ]);
}

/**
 * Empty a directory without unlinking the directory itself.
 *
 * The dir-rm + mkdir pattern is unsafe when `dir` is a mount point: Linux
 * returns EBUSY on `rmdir` of a mount root (different from ENOTEMPTY, so
 * `fs.rm`'s recursive walk bails without removing children). Restore endpoints
 * need "clear it" semantics regardless of whether the path is a plain dir or
 * a volume mount.
 *
 * Creates the dir if it does not exist. ENOENT children are tolerated.
 */
export async function clearDirContents(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
  const entries = await fs.readdir(dir);
  for (const entry of entries) {
    await fs.rm(path.join(dir, entry), { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function isEnoent(err: unknown): boolean {
  return (
    err instanceof Error &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === "ENOENT"
  );
}
