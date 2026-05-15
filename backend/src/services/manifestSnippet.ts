// Resolve the line + ±3-line snippet of a package's declaration inside a
// manifest file (package-lock.json, requirements.txt, Cargo.toml, …).
//
// Used by:
//   - osvService's SCA-issue backfill (latest_manifest_line / _snippet).
//   - sbomService.persistAugmentedComponents to populate sbom_components
//     and scope_components `evidence` with identity-shaped data
//     ({path, line, snippet}) at scan time.
//   - worker backfillScopeComponentEvidenceSnippets, which fills line +
//     snippet on existing scope_components rows whose evidence was
//     written by the M7→split-evidence-usage migration with path only.
//
// Heuristic: the first line containing the package name (quoted or
// unquoted) is treated as the declaration. Matches `"<name>": {` in
// package-lock.json, `name = "<name>"` in Cargo.toml, `<name>==` in
// requirements.txt — good enough for the common manifest formats. Binary
// jar/dll "manifests" return null (no useful snippet).

import { readFile } from "node:fs/promises";
import { join } from "node:path";

export const MANIFEST_CONTEXT_LINES = 3;

export interface ManifestSnippet {
  line: number | null;
  snippet: string | null;
}

export async function readManifestSnippet(
  scopeDir: string,
  manifestPath: string,
  packageName: string,
): Promise<ManifestSnippet> {
  try {
    const content = await readFile(join(scopeDir, manifestPath), "utf8");
    const lines = content.split("\n");
    const patterns = [
      `"${packageName}"`,
      `'${packageName}'`,
      `${packageName}==`,
      `${packageName}~=`,
      packageName,
    ];
    let matchIdx = -1;
    for (const p of patterns) {
      matchIdx = lines.findIndex((l) => l.includes(p));
      if (matchIdx !== -1) break;
    }
    if (matchIdx === -1) return { line: null, snippet: null };

    const from = Math.max(0, matchIdx - MANIFEST_CONTEXT_LINES);
    const to = Math.min(lines.length, matchIdx + MANIFEST_CONTEXT_LINES + 1);
    const snippet = lines.slice(from, to).join("\n");
    return { line: matchIdx + 1, snippet };
  } catch {
    return { line: null, snippet: null };
  }
}
