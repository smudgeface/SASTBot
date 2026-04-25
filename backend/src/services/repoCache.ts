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

/**
 * Thrown when the git remote can't be reached at all (DNS failure,
 * connection timeout, refused, etc.). Distinct from generic git
 * failures so callers can preserve the local cache rather than
 * destroying it on a transient network blip.
 */
export class RemoteUnreachableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RemoteUnreachableError";
  }
}

/**
 * Heuristic — true when a git error looks like a network/connectivity
 * issue versus a true git problem (corrupt repo, bad ref, auth fail,
 * etc.). Pattern set is conservative; widen as we observe new strings
 * in the wild.
 */
function isNetworkError(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return [
    "Failed to connect",
    "Couldn't connect",
    "Could not resolve host",
    "Operation timed out",
    "Connection refused",
    "Connection timed out",
    "Network is unreachable",
    "Temporary failure in name resolution",
  ].some((s) => msg.includes(s));
}

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

  // Pre-flight reachability probe BEFORE any destructive op. Cheap
  // (a few KB at most) and prevents a network blip from wiping a
  // working cache.
  await probeRemote({ url, credentialId });

  const reusable = await isGitWorkingTree(cacheDir);
  if (reusable) {
    try {
      await refreshCache({ cacheDir, defaultBranch, credentialId });
      await prisma.repo
        .update({ where: { id: repoId }, data: { lastClonedAt: new Date() } })
        .catch(() => undefined);
      return { workingDir: cacheDir, fromCache: true, ephemeral: false };
    } catch (err) {
      if (err instanceof RemoteUnreachableError) {
        // Don't wipe — propagate so the caller can retry with the cache
        // still intact once the network comes back.
        throw err;
      }
      // True cache corruption (bad refs, missing objects, etc.) — wipe
      // and re-clone from scratch.
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

/**
 * Pre-flight check: `git ls-remote --heads <url>` with a hard timeout.
 * Throws `RemoteUnreachableError` on network failure. Other git errors
 * (auth fail, bad ref, etc.) propagate as plain Error so the caller can
 * fail-fast on real problems instead of silently swallowing them.
 */
async function probeRemote(input: { url: string; credentialId?: string | null }): Promise<void> {
  const { decodeCredential } = await import("./credentialService.js");
  const { applyCredentialToEnv } = await import("./gitClone.js");
  const { mkdtemp } = await import("node:fs/promises");

  const helperDir = await mkdtemp(join(tmpdir(), "sastbot-git-probe-"));
  try {
    const env: Record<string, string> = {
      ...(process.env as Record<string, string>),
    };
    env.GIT_TERMINAL_PROMPT = "0";
    if (input.credentialId) {
      const cred = await decodeCredential(input.credentialId);
      await applyCredentialToEnv(cred, helperDir, env);
    }

    try {
      await runGit(["ls-remote", "--heads", "--exit-code", input.url], helperDir, env, 10_000);
    } catch (err) {
      if (isNetworkError(err)) {
        throw new RemoteUnreachableError(
          `Cannot reach git remote ${input.url}: ${(err as Error).message}`,
        );
      }
      throw err;
    }
  } finally {
    await rm(helperDir, { recursive: true, force: true }).catch(() => undefined);
  }
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

    try {
      await runGit(["fetch", "--prune", "--quiet"], input.cacheDir, env);
    } catch (err) {
      if (isNetworkError(err)) {
        throw new RemoteUnreachableError(
          `git fetch failed — remote unreachable: ${(err as Error).message}`,
        );
      }
      throw err;
    }
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
  timeoutMs?: number,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn("git", args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    let timer: NodeJS.Timeout | undefined;
    if (timeoutMs && timeoutMs > 0) {
      timer = setTimeout(() => {
        proc.kill("SIGKILL");
      }, timeoutMs);
    }
    proc.stderr.on("data", (c) => (stderr += c.toString()));
    proc.on("error", (err) => {
      if (timer) clearTimeout(timer);
      reject(err);
    });
    proc.on("close", (code, signal) => {
      if (timer) clearTimeout(timer);
      if (code === 0) {
        resolve();
      } else if (signal === "SIGKILL" && timeoutMs) {
        reject(new Error(`git ${args.join(" ")} Operation timed out after ${timeoutMs}ms`));
      } else {
        reject(new Error(`git ${args.join(" ")} failed (${code}): ${stderr}`));
      }
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
