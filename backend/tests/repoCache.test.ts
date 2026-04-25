/**
 * repoCache tests: verify that transient network failures don't destroy the
 * cached clone, and that the pre-flight probe and refresh-time fetch both
 * surface a RemoteUnreachableError instead of bubbling up a generic git error.
 *
 * Strategy: point cloneOrRefresh at a TCP endpoint that refuses connections
 * immediately (port 1 on loopback). git emits "Connection refused" within
 * milliseconds, which matches our network-error heuristic, so the test is
 * fast and deterministic without needing to mock the spawn helper.
 */
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { _resetConfigForTests } from "../src/config.js";
import { RemoteUnreachableError, cloneOrRefresh } from "../src/services/repoCache.js";

const GIT = "git";

function hasGit(): boolean {
  try {
    execFileSync(GIT, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const REFUSED_URL = "http://127.0.0.1:1/repo.git"; // port 1 refuses immediately

describe("cloneOrRefresh — network error handling", () => {
  if (!hasGit()) {
    it.skip("skipped: git not on PATH", () => undefined);
    return;
  }

  let cacheRoot: string;
  let bareRepo: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeAll(() => {
    // Build a real local bare repo so the "happy path" + "network failure
    // after a working cache exists" test can use it.
    const wd = mkdtempSync(join(tmpdir(), "sastbot-repocache-test-"));
    bareRepo = join(wd, "origin.git");
    const work = join(wd, "work");
    mkdirSync(work, { recursive: true });
    execFileSync(GIT, ["init", "--bare", bareRepo], { stdio: "ignore" });
    execFileSync(GIT, ["init", work], { stdio: "ignore" });
    writeFileSync(join(work, "README.md"), "hi\n");
    execFileSync(GIT, ["add", "."], { cwd: work, stdio: "ignore" });
    execFileSync(GIT, ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-m", "init"], { cwd: work, stdio: "ignore" });
    execFileSync(GIT, ["branch", "-M", "main"], { cwd: work, stdio: "ignore" });
    execFileSync(GIT, ["remote", "add", "origin", bareRepo], { cwd: work, stdio: "ignore" });
    execFileSync(GIT, ["push", "-u", "origin", "main"], { cwd: work, stdio: "ignore" });
  });

  beforeEach(() => {
    cacheRoot = mkdtempSync(join(tmpdir(), "sastbot-cachedir-"));
    originalEnv = { ...process.env };
    process.env.MASTER_KEY = randomBytes(32).toString("base64");
    process.env.DATABASE_URL = "postgresql://u:p@localhost:5432/db";
    process.env.REDIS_URL = "redis://localhost:6379/0";
    process.env.CLONE_CACHE_DIR = cacheRoot;
    _resetConfigForTests();
  });

  afterAll(() => {
    process.env = originalEnv ?? process.env;
    _resetConfigForTests();
  });

  it("throws RemoteUnreachableError on connection refused", async () => {
    await expect(
      cloneOrRefresh({
        repoId: "00000000-0000-0000-0000-000000000001",
        url: REFUSED_URL,
        defaultBranch: "main",
        retainClone: true,
      }),
    ).rejects.toBeInstanceOf(RemoteUnreachableError);
  });

  it("preserves cached clone when fetch fails (does not wipe)", async () => {
    const repoId = "00000000-0000-0000-0000-000000000002";
    // Step 1: succeed once with a reachable URL to populate the cache.
    const result = await cloneOrRefresh({
      repoId,
      url: `file://${bareRepo}`,
      defaultBranch: "main",
      retainClone: true,
    });
    expect(result.fromCache).toBe(false);
    expect(existsSync(join(result.workingDir, "README.md"))).toBe(true);
    const cacheDir = result.workingDir;

    // Step 2: re-trigger with an unreachable URL. The pre-flight probe
    // hits REFUSED_URL first and throws RemoteUnreachableError. The
    // existing cache must not be touched.
    await expect(
      cloneOrRefresh({
        repoId,
        url: REFUSED_URL,
        defaultBranch: "main",
        retainClone: true,
      }),
    ).rejects.toBeInstanceOf(RemoteUnreachableError);

    // Cache dir + working file still on disk.
    expect(existsSync(cacheDir)).toBe(true);
    expect(existsSync(join(cacheDir, "README.md"))).toBe(true);
    expect(existsSync(join(cacheDir, ".git"))).toBe(true);
  });
});
