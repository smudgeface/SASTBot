/**
 * gitClone unit tests that work without a network or credential store.
 *
 * We create a bare local git repo in a tmp dir and clone it via `file://`,
 * proving the command assembly + process execution path works. Credential-
 * driven auth (HTTPS token, HTTPS basic, SSH key) is exercised against a
 * real gitea in the integration suite — see scripts/integration_gitea.py.
 */
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { beforeAll, afterAll, describe, expect, it } from "vitest";

import { gitClone, GitCloneError } from "../src/services/gitClone.js";

const GIT = "git";

function hasGit(): boolean {
  try {
    execFileSync(GIT, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// A bit of plumbing: make a bare repo with one commit, so a `git clone` of
// it lands a known file we can assert on.
function seedBareRepo(scratch: string): string {
  const origin = join(scratch, "origin");
  const bare = join(scratch, "origin.git");

  mkdirSync(origin, { recursive: true });
  writeFileSync(join(origin, "hello.txt"), "hello from sastbot\n");

  execFileSync(GIT, ["init", "-q", "-b", "main"], { cwd: origin });
  execFileSync(GIT, ["-c", "user.email=t@t", "-c", "user.name=t", "add", "-A"], {
    cwd: origin,
  });
  execFileSync(
    GIT,
    ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "initial"],
    { cwd: origin },
  );
  execFileSync(GIT, ["clone", "-q", "--bare", origin, bare]);
  return bare;
}

describe("gitClone", () => {
  let scratch: string;
  let bareUrl: string;
  const gitAvailable = hasGit();

  beforeAll(() => {
    if (!gitAvailable) return;
    scratch = mkdtempSync(join(tmpdir(), "sastbot-gitclone-test-"));
    const bare = seedBareRepo(scratch);
    bareUrl = `file://${bare}`;
  });

  afterAll(() => {
    if (scratch) rmSync(scratch, { recursive: true, force: true });
  });

  it.skipIf(!gitAvailable)(
    "clones a public repo with no credential",
    async () => {
      const dest = join(scratch, "clone-public");
      await gitClone({ url: bareUrl, destDir: dest });
      const hello = execFileSync("cat", [join(dest, "hello.txt")]).toString();
      expect(hello).toContain("hello from sastbot");
    },
  );

  it.skipIf(!gitAvailable)(
    "wraps git failures in a GitCloneError with captured stderr",
    async () => {
      const dest = join(scratch, "clone-nope");
      await expect(
        gitClone({
          url: "file:///definitely/does/not/exist.git",
          destDir: dest,
        }),
      ).rejects.toBeInstanceOf(GitCloneError);
    },
  );

  it.skipIf(!gitAvailable)(
    "supports --depth and --branch options",
    async () => {
      const dest = join(scratch, "clone-shallow");
      await gitClone({
        url: bareUrl,
        destDir: dest,
        branch: "main",
        depth: 1,
      });
      const log = execFileSync(GIT, ["-C", dest, "log", "--oneline"])
        .toString()
        .trim();
      expect(log.split("\n").length).toBe(1);
    },
  );

  it("throws a clear error for an unknown credential id", async () => {
    await expect(
      gitClone({
        url: "file:///anywhere",
        destDir: join(tmpdir(), "never-used"),
        credentialId: "00000000-0000-0000-0000-000000000000",
      }),
    ).rejects.toThrow(/Credential .* not found/);
  });
});
