/**
 * Persistent per-repo clone cache.
 *
 * When a repo has `retain_clone=true`, the scan worker keeps its working
 * copy on a durable volume (CLONE_CACHE_DIR) and refreshes with
 * `git fetch` + `git reset --hard origin/<default_branch>` on subsequent
 * scans. That's much faster than re-cloning a large monorepo every run.
 *
 * Directory layout:
 *   $CLONE_CACHE_DIR/<repoId>/<working-tree>
 *
 * This module owns the filesystem side. Consumers:
 *   - workers call `cloneOrRefresh()` each scan
 *   - the backend's `POST /admin/repos/:id/purge-cache` calls `purge()`
 *     to free space or force a clean next run
 */
import { spawn } from "node:child_process";
import { mkdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { loadConfig } from "../config.js";
import { prisma } from "../db.js";
import { gitClone, type GitCloneOptions } from "./gitClone.js";

/** Directory reserved for a given repo's cached clone. Safe to call
 *  before the path actually exists on disk. */
export function repoCachePath(repoId: string): string {
  return join(loadConfig().cloneCacheDir, repoId);
}

async function isDir(path: string): Promise<boolean> {
  try {
    const s = await stat(path);
    return s.isDirectory();
  } catch {
    return false;
  }
}

/** True when *path* already contains a git working tree (has a .git dir). */
async function isGitWorkingTree(path: string): Promise<boolean> {
  return isDir(join(path, ".git"));
}

export interface CloneOrRefreshInput {
  repoId: string;
  url: string;
  defaultBranch: string;
  credentialId?: string | null;
  retainClone: boolean;
}

export interface CloneOrRefreshResult {
  /** Where the working tree is. Caller treats as read-only except for
   *  nested tools that need to write into it (e.g. cdxgen in M3). */
  workingDir: string;
  /** True when we reused a cached clone (fetch+reset), false for fresh. */
  fromCache: boolean;
  /** True when the caller is responsible for removing workingDir. */
  ephemeral: boolean;
}

/**
 * Ensure a working copy of *repo* exists on disk and is up to date with
 * `origin/<defaultBranch>`. Callers should treat the returned directory
 * as the canonical "latest" tree for this scan.
 *
 * Honours `retainClone`:
 *   - false → always clones into a fresh tmp dir (caller removes after scan)
 *   - true  → uses CLONE_CACHE_DIR/<repoId>; fetches+resets if the cache
 *             is valid, falls back to fresh clone if it's missing/corrupt.
 *
 * Updates `repos.last_cloned_at` on success.
 */
export async function cloneOrRefresh(
  input: CloneOrRefreshInput,
): Promise<CloneOrRefreshResult> {
  const { repoId, url, defaultBranch, credentialId, retainClone } = input;

  if (!retainClone) {
    // Ephemeral — brand-new tmp dir, caller cleans up after the scan.
    const dest = join(tmpdir(), `sastbot-repo-${repoId}-${Date.now()}`);
    await gitClone({ url, destDir: dest, credentialId, branch: defaultBranch });
    await prisma.repo
      .update({ where: { id: repoId }, data: { lastClonedAt: new Date() } })
      .catch(() => undefined);
    return { workingDir: dest, fromCache: false, ephemeral: true };
  }

  // Retained path — use the persistent cache dir.
  const cacheDir = repoCachePath(repoId);
  const parent = loadConfig().cloneCacheDir;
  await mkdir(parent, { recursive: true });

  const reusable = await isGitWorkingTree(cacheDir);
  if (reusable) {
    try {
      await refreshCache({ cacheDir, defaultBranch, credentialId });
      await prisma.repo
        .update({ where: { id: repoId }, data: { lastClonedAt: new Date() } })
        .catch(() => undefined);
      return { workingDir: cacheDir, fromCache: true, ephemeral: false };
    } catch {
      // Cache is corrupted or the remote's changed shape — fall back to
      // a fresh clone. Purge first so the clone target is empty.
      await rm(cacheDir, { recursive: true, force: true });
    }
  }

  await gitClone({
    url,
    destDir: cacheDir,
    credentialId,
    branch: defaultBranch,
  });
  await prisma.repo
    .update({ where: { id: repoId }, data: { lastClonedAt: new Date() } })
    .catch(() => undefined);
  return { workingDir: cacheDir, fromCache: false, ephemeral: false };
}

interface RefreshInput {
  cacheDir: string;
  defaultBranch: string;
  credentialId?: string | null;
}

/** Run `git fetch --prune` then `git reset --hard origin/<branch>` in an
 *  existing cache dir. Honours the same credential plumbing as gitClone
 *  (we build a GIT_ASKPASS / GIT_SSH_COMMAND env and reuse it). */
async function refreshCache(input: RefreshInput): Promise<void> {
  const { decodeCredential } = await import("./credentialService.js");
  const { applyCredentialToEnv } = await import("./gitClone.js");
  const { mkdtemp } = await import("node:fs/promises");

  const helperDir = await mkdtemp(join(tmpdir(), "sastbot-git-refresh-"));
  try {
    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
    };
    env.GIT_TERMINAL_PROMPT = "0";

    if (input.credentialId) {
      const cred = await decodeCredential(input.credentialId);
      await applyCredentialToEnv(cred, helperDir, env);
    }

    await runGit(["fetch", "--prune", "--quiet"], input.cacheDir, env);
    await runGit(
      ["reset", "--hard", `origin/${input.defaultBranch}`, "--quiet"],
      input.cacheDir,
      env,
    );
  } finally {
    await rm(helperDir, { recursive: true, force: true }).catch(() => undefined);
  }
}

function runGit(
  args: string[],
  cwd: string,
  env: Record<string, string>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn("git", args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    proc.stderr.on("data", (c) => (stderr += c.toString()));
    proc.on("error", reject);
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new Error(`git ${args.join(" ")} failed (${code}): ${stderr}`));
    });
  });
}

/** Remove the cached clone (if any). Idempotent. */
export async function purge(repoId: string): Promise<void> {
  const path = repoCachePath(repoId);
  await rm(path, { recursive: true, force: true });
  await prisma.repo
    .update({ where: { id: repoId }, data: { lastClonedAt: null } })
    .catch(() => undefined);
}
