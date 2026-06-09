import { prisma } from "../db.js";

/** Normalize a repo-relative dir fragment: trim, strip leading slashes, ensure
 *  a single trailing slash so it matches as a path *segment* (e.g. `extern/`,
 *  `extern/Xenomai/`). Returns null for an empty value. */
function normalizeDirFragment(raw: string): string | null {
  const t = raw.trim().replace(/^\/+/, "").replace(/\/+$/, "");
  return t.length > 0 ? `${t}/` : null;
}

/**
 * Build the set of repo-relative paths the SAST detection pass should treat as
 * third-party / vendored and NOT audit (covered by SCA/CVE instead).
 *
 * Unions two signals:
 *  - the repo's configured `vendoredDirs` fragments (`extern/`, `third-party/`,
 *    `vendor/`) — coarse, catches conventionally-placed libs even if SCA missed
 *    them;
 *  - the SCA SBOM's per-component `componentRoot` for this scan run — precise,
 *    knows exactly where each detected vendored lib sits, including ones outside
 *    the conventional dirs. `componentRoot` is null for manifest-based deps
 *    (their code isn't vendored in-repo), so those drop out naturally.
 *
 * Fail-safe in both directions: a vendored lib SCA missed may still be caught by
 * the configured fragments; if neither catches it, SAST simply scans it
 * (auditing unknown code is the safe error).
 *
 * `scanRunId` should be a run whose `sbom_components` are already persisted — in
 * the live pipeline the `sbom_persist` phase runs before `llm_detection`, so the
 * current run qualifies; the dry-run CLI passes a recent prior run.
 */
export async function buildThirdPartyPaths(
  scanRunId: string,
  vendoredDirs: string[],
): Promise<string[]> {
  const components = await prisma.sbomComponent.findMany({
    where: { scanRunId, componentRoot: { not: null } },
    select: { componentRoot: true },
  });

  const set = new Set<string>();
  for (const d of vendoredDirs) {
    const norm = normalizeDirFragment(d);
    if (norm) set.add(norm);
  }
  for (const c of components) {
    const norm = normalizeDirFragment(c.componentRoot ?? "");
    if (norm) set.add(norm);
  }
  return [...set].sort();
}
