/**
 * Git-clone wrapper that uses a stored SASTBot credential.
 *
 * Shells out to the `git` binary (not a JS reimplementation) so the
 * behaviour matches `git clone` anywhere else. Authentication is supplied
 * via standard git env vars — no secrets ever land in the URL or on the
 * command line:
 *
 *   - https_token / https_basic → `GIT_ASKPASS` helper script that prints
 *     the username or password based on what git prompts for.
 *   - ssh_key → `GIT_SSH_COMMAND` with `-i <tempkey>` and an explicit
 *     `UserKnownHostsFile` when the credential carries known_hosts.
 *
 * Temporary files (askpass script, ssh key, known_hosts) are written under
 * a per-invocation tmp dir and removed in a `finally` block.
 */
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { DecodedCredential } from "./credentialService.js";
import {
  CredentialNotFoundError,
  decodeCredential,
} from "./credentialService.js";

export interface GitCloneOptions {
  /** Clone URL. Can be HTTPS (`https://…`) or SSH (`git@host:…` / `ssh://…`). */
  url: string;
  /**
   * Where to clone into. Must not exist or be an empty dir — git's own
   * behaviour applies.
   */
  destDir: string;
  /** Credential row id to authenticate with, or null for public clones. */
  credentialId?: string | null;
  /** Optional branch to check out (passed to `--branch`). */
  branch?: string | null;
  /** Optional shallow-clone depth. */
  depth?: number;
  /**
   * Optional override of the git binary path. Defaults to `git` on PATH.
   * Tests use this to point at a specific binary.
   */
  gitBin?: string;
}

/** Thrown for any non-zero git exit code. Carries the stderr tail so
 *  callers can surface useful diagnostics. */
export class GitCloneError extends Error {
  readonly exitCode: number | null;
  readonly stderr: string;
  constructor(exitCode: number | null, stderr: string) {
    super(
      `git clone failed (exit ${exitCode}): ${stderr.trim().split("\n").slice(-5).join(" | ")}`,
    );
    this.name = "GitCloneError";
    this.exitCode = exitCode;
    this.stderr = stderr;
  }
}

/** Clone a repo using the given (optional) stored credential. */
export async function gitClone(options: GitCloneOptions): Promise<void> {
  const bin = options.gitBin ?? "git";
  const workdir = await mkdtemp(join(tmpdir(), "sastbot-git-"));
  try {
    let cred: DecodedCredential | null = null;
    if (options.credentialId) {
      try {
        cred = await decodeCredential(options.credentialId);
      } catch (err) {
        if (err instanceof CredentialNotFoundError) {
          throw new Error(
            `Credential ${options.credentialId} not found — cannot authenticate clone`,
          );
        }
        throw err;
      }
    }

    const env: Record<string, string> = { ...(process.env as Record<string, string>) };
    // Refuse any interactive prompts — in prod we're a daemon, and letting
    // git hang waiting for a tty is a worse failure mode than erroring.
    env.GIT_TERMINAL_PROMPT = "0";

    if (cred) {
      await applyCredentialToEnv(cred, workdir, env);
    }

    const args: string[] = ["clone"];
    if (options.depth) args.push("--depth", String(options.depth));
    if (options.branch) {
      args.push("--branch", options.branch);
      args.push("--single-branch");
    }
    args.push(options.url, options.destDir);

    await runGit(bin, args, env);
  } finally {
    await rm(workdir, { recursive: true, force: true }).catch(() => undefined);
  }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/**
 * Populate *env* with the right GIT_ASKPASS / GIT_SSH_COMMAND for *cred*,
 * writing any required helper files into *workdir*. Exported so the
 * persistent-cache refresh path (repoCache.ts) uses the exact same
 * credential plumbing as a fresh clone — any divergence is a bug.
 */
export async function applyCredentialToEnv(
  cred: DecodedCredential,
  workdir: string,
  env: Record<string, string>,
): Promise<void> {
  switch (cred.kind) {
    case "https_token": {
      // Most git hosts accept any username when a token is presented as
      // the password. GitHub recommends `x-access-token`; others ignore it.
      const askpass = await writeAskpassScript(workdir, "x-access-token", cred.value);
      env.GIT_ASKPASS = askpass;
      return;
    }
    case "https_basic": {
      const askpass = await writeAskpassScript(workdir, cred.username, cred.password);
      env.GIT_ASKPASS = askpass;
      return;
    }
    case "ssh_key": {
      if (cred.passphrase) {
        throw new Error(
          "Passphrase-protected SSH keys are not yet supported. Re-export the key without a passphrase or add ssh-agent integration (M3+).",
        );
      }
      const keyPath = join(workdir, "id_key");
      await writeFile(keyPath, ensureTrailingNewline(cred.private_key), {
        mode: 0o600,
      });

      const sshOpts = [
        "-i",
        shellQuote(keyPath),
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
      ];

      if (cred.known_hosts) {
        const khPath = join(workdir, "known_hosts");
        await writeFile(khPath, ensureTrailingNewline(cred.known_hosts));
        sshOpts.push("-o", `UserKnownHostsFile=${shellQuote(khPath)}`);
        sshOpts.push("-o", "StrictHostKeyChecking=yes");
      } else {
        // TODO (security): M3+ should require a known_hosts entry. For now
        // accept-new trusts the first-seen host key and rejects mismatches
        // thereafter — weaker than pinning but stronger than blind accept.
        sshOpts.push("-o", "StrictHostKeyChecking=accept-new");
      }

      env.GIT_SSH_COMMAND = `ssh ${sshOpts.join(" ")}`;
      return;
    }
    case "jira_token":
    case "llm_api_key":
      throw new Error(
        `Credential kind ${cred.kind} is not valid for git clone — use https_token, https_basic, or ssh_key.`,
      );
    default: {
      const _exhaustive: never = cred;
      throw new Error(`Unhandled credential kind: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

async function writeAskpassScript(
  workdir: string,
  username: string,
  password: string,
): Promise<string> {
  const scriptPath = join(workdir, "askpass.sh");
  // Wrap values in single quotes, escaping any literal single quotes.
  const q = (s: string) => `'${s.replace(/'/g, "'\\''")}'`;
  const script = `#!/bin/sh
# GIT_ASKPASS helper for SASTBot. Git calls this with the full prompt text
# as $1; we answer Username prompts with the credential's username and
# anything else (password prompts) with the secret.
case "$1" in
  Username*) printf %s ${q(username)} ;;
  *)         printf %s ${q(password)} ;;
esac
`;
  await writeFile(scriptPath, script, { mode: 0o700 });
  return scriptPath;
}

function ensureTrailingNewline(s: string): string {
  return s.endsWith("\n") ? s : `${s}\n`;
}

/** Minimal shell-quote for option values inside GIT_SSH_COMMAND. Strings
 *  we write are tmpdir paths we control, so this is conservative. */
function shellQuote(s: string): string {
  if (/^[A-Za-z0-9@%+=:,./_-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, "'\\''")}'`;
}

function runGit(
  bin: string,
  args: string[],
  env: Record<string, string>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const proc = spawn(bin, args, { env, stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    proc.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    proc.on("error", reject);
    proc.on("close", (code) => {
      if (code === 0) resolve();
      else reject(new GitCloneError(code, stderr));
    });
  });
}
