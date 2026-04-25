/**
 * Path translation between scope-relative and repo-rooted forms.
 *
 * Scope-relative paths (no leading slash, relative to the scope's working
 * directory) are what tools natively emit:
 *   - cdxgen reports `package-lock.json` for a /GoWeb scope
 *   - the LLM SAST agent runs cwd=scopeDir and emits `src/routes/app.js`
 *
 * Repo-rooted paths (no leading slash, relative to the repo root) are what
 * we want to PERSIST and DISPLAY:
 *   - clickable file links via `repos.source_url_template` need a path the
 *     git source viewer can resolve
 *   - the same finding's path looks consistent regardless of which scope
 *     it was discovered under
 *
 * Translation is purely string-based — we never resolve symlinks or touch
 * the filesystem. Callers must already know the scope's path on the repo
 * (e.g. "/", "/GoWeb", "/Sub/Path") and pass it in.
 */

function strippedScopePath(scopePath: string): string {
  return scopePath.replace(/^\/+/, "").replace(/\/+$/, "");
}

/**
 * Convert a scope-relative path to its repo-rooted form.
 * `toRepoRelative("/GoWeb", "src/foo.js") === "GoWeb/src/foo.js"`
 * `toRepoRelative("/",      "src/foo.js") === "src/foo.js"`
 */
export function toRepoRelative(scopePath: string, scopeRelativeFile: string): string {
  const prefix = strippedScopePath(scopePath);
  if (!prefix) return scopeRelativeFile;
  return `${prefix}/${scopeRelativeFile}`;
}

/**
 * Convert a repo-rooted path to its scope-relative form. Idempotent — if
 * the input is already scope-relative (no scope prefix), it's returned
 * unchanged. Used at the LLM input boundary so the agent (running with
 * cwd=scopeDir) gets paths it can read.
 *
 * `toScopeRelative("/GoWeb", "GoWeb/src/foo.js") === "src/foo.js"`
 * `toScopeRelative("/GoWeb", "src/foo.js")       === "src/foo.js"` (defensive)
 * `toScopeRelative("/",      "src/foo.js")       === "src/foo.js"`
 */
export function toScopeRelative(scopePath: string, repoRootedFile: string): string {
  const prefix = strippedScopePath(scopePath);
  if (!prefix) return repoRootedFile;
  const withSep = `${prefix}/`;
  return repoRootedFile.startsWith(withSep) ? repoRootedFile.slice(withSep.length) : repoRootedFile;
}
