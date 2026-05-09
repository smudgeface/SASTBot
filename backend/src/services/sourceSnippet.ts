// File-read snippet extraction for SAST findings + reachability call sites.
//
// The LLM identifies WHERE a problem is (file + line range). The worker is
// then responsible for reading the source from disk and producing a snippet
// of exactly N context lines above the problem, the problem region itself,
// and N context lines below — the canonical layout assumed by the frontend
// `ContextSnippet` and the SARIF `contextRegion` builder.
//
// Why not let the LLM emit the snippet directly:
//   - The LLM is inconsistent about how many context lines it includes
//     (M6i: anywhere from 0 to 20+), forcing the frontend to guess where
//     the actual match line sits within the snippet via keyword search.
//   - File contents are authoritative — no transcription drift, no escape
//     mishandling, no token cost.
//   - Wins token budget on every detection (snippets are bulky).

import { readFile } from "node:fs/promises";
import { resolve as resolvePath } from "node:path";

/** Default lines of context above and below the problem region. Mirrors
 *  the frontend `STORED_CONTEXT_LINES` so the two stay in sync. */
export const SOURCE_CONTEXT_LINES = 3;

export interface SourceSnippet {
  text: string;
  /** 1-indexed file line that the snippet's first row corresponds to.
   *  Less than `startLine` whenever the file has at least N lines above. */
  firstFileLine: number;
}

/**
 * Read `(startLine - context) .. (endLine + context)` from `filePath`,
 * relative to `scopeDir`. Returns null on any I/O error or if the path
 * tries to escape `scopeDir`.
 *
 * `endLine` defaults to `startLine` (single-line region).
 */
export async function readSourceSnippet(
  scopeDir: string,
  filePath: string,
  startLine: number,
  endLine?: number,
  contextLines: number = SOURCE_CONTEXT_LINES,
): Promise<SourceSnippet | null> {
  if (!Number.isInteger(startLine) || startLine < 1) return null;
  const lastLine = Math.max(startLine, endLine ?? startLine);

  // Path-traversal guard: refuse anything that resolves outside scopeDir
  // even if the LLM emitted "../" tricks.
  const resolved = resolvePath(scopeDir, filePath);
  const scopeRoot = resolvePath(scopeDir);
  if (!resolved.startsWith(scopeRoot + "/") && resolved !== scopeRoot) {
    return null;
  }

  let text: string;
  try {
    text = await readFile(resolved, "utf8");
  } catch {
    return null;
  }
  const allLines = text.split("\n");
  if (allLines.length === 0) return null;

  const firstFileLine = Math.max(1, startLine - contextLines);
  const lastFileLine = Math.min(allLines.length, lastLine + contextLines);
  // Slice is 0-indexed; file lines are 1-indexed.
  const slice = allLines.slice(firstFileLine - 1, lastFileLine);
  return { text: slice.join("\n"), firstFileLine };
}
