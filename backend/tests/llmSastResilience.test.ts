/**
 * Stream C — scan resilience tests.
 *
 * Tests the watchdog timers (wall-clock cap, stdout-staleness kill) and
 * retry-on-zero-records logic implemented in spawnClaudeAndStream /
 * runDetection / runRecheck.
 *
 * Strategy: mock `node:child_process.spawn` so the test controls exactly what
 * the fake "claude" subprocess does.  The mocked spawn returns a FakeProcess
 * whose stdout/stderr are PassThrough streams — test code can push data or
 * close them to simulate real subprocess output.
 *
 * We use real timers (not vi.useFakeTimers) for the watchdog paths and pass
 * 1 ms timeout values so the watchdogs fire essentially immediately, making
 * the tests fast without fake-timer complexity.
 */
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Shared fake-process registry (cleared before each test).
// ---------------------------------------------------------------------------

const fakeProcs: FakeProcess[] = [];

class FakeProcess extends EventEmitter {
  stdout = new PassThrough();
  stderr = new PassThrough();
  killed = false;
  killSignals: string[] = [];

  kill(signal?: string): boolean {
    this.killed = true;
    this.killSignals.push(signal ?? "SIGTERM");
    // On the final kill, close the streams and emit the close event.
    // Use setImmediate so the event fires after the current call stack.
    setImmediate(() => {
      if (!this.stdout.destroyed) this.stdout.end();
      if (!this.stderr.destroyed) this.stderr.end();
      // Emit a non-zero close code to simulate abnormal termination.
      this.emit("close", signal === "SIGKILL" ? 9 : 1);
    });
    return true;
  }

  /** Push a JSON line to stdout. */
  pushLine(text: string): void {
    this.stdout.push(text + "\n");
  }

  /** Close the process with a given exit code. */
  end(code: number): void {
    setImmediate(() => {
      if (!this.stdout.destroyed) this.stdout.end();
      if (!this.stderr.destroyed) this.stderr.end();
      this.emit("close", code);
    });
  }
}

// ---------------------------------------------------------------------------
// Mock child_process.spawn
// ---------------------------------------------------------------------------

vi.mock("node:child_process", async (importOriginal) => {
  const orig = await importOriginal<typeof import("node:child_process")>();
  return {
    ...orig,
    spawn: (..._args: unknown[]) => {
      const proc = new FakeProcess();
      fakeProcs.push(proc);
      return proc;
    },
  };
});

// ---------------------------------------------------------------------------
// Mock heavy dependencies of runDetection / runRecheck
// ---------------------------------------------------------------------------

vi.mock("../src/services/credentialService.js", () => ({
  decodeCredential: async () => ({ kind: "llm_api_key", value: "test-key" }),
}));
vi.mock("../src/services/settingsService.js", () => ({
  getOrCreateSettings: async () => ({
    llmBaseUrl: "http://localhost:9999",
    llmModel: "claude-test",
    llmCredentialId: "cred-1",
    llmApiFormat: "anthropic-messages",
  }),
}));
vi.mock("../src/services/promptLoader.js", () => ({
  loadPrompt: (_name: string, _vars: Record<string, string>) => "test-prompt",
}));
vi.mock("node:fs/promises", async (importOriginal) => {
  const orig = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...orig,
    mkdir: async () => undefined,
    chown: async () => undefined,
    writeFile: async () => undefined,
    rm: async () => undefined,
  };
});

// ---------------------------------------------------------------------------
// Import module under test AFTER mocks are established.
// ---------------------------------------------------------------------------

import { runDetection, runRecheck } from "../src/services/llmSastService.js";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

const SCAN_ID = "test-scan-1";

function baseDetectionInput(
  overrides: Partial<Parameters<typeof runDetection>[0]> = {},
): Parameters<typeof runDetection>[0] {
  return {
    scanRunId: SCAN_ID,
    scopeId: "scope-1",
    scopeDir: "/tmp/test-scope",
    repoName: "test-repo",
    repoBranch: "main",
    ignorePaths: [],
    scaHints: [],
    tokenBudget: 10_000,
    effortLevel: "medium",
    orgId: null,
    ...overrides,
  };
}

function baseRecheckInput(
  overrides: Partial<Parameters<typeof runRecheck>[0]> = {},
): Parameters<typeof runRecheck>[0] {
  return {
    scanRunId: SCAN_ID,
    scopeDir: "/tmp/test-scope",
    scopePath: "/",
    issues: [
      {
        id: "issue-1",
        file_path: "/test.ts",
        start_line: 1,
        summary: "test",
        snippet: "code",
        cwe: "CWE-79",
      },
    ],
    duplicateTargets: [],
    tokenBudget: 10_000,
    effortLevel: "medium",
    orgId: null,
    ...overrides,
  };
}

/** Wait for the next spawned process (poll until available, up to a timeout). */
async function waitForProc(
  prevCount: number,
  timeoutMs = 2000,
): Promise<FakeProcess> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fakeProcs.length > prevCount) return fakeProcs[fakeProcs.length - 1]!;
    await new Promise<void>((r) => setImmediate(r));
  }
  throw new Error(`waitForProc timed out after ${timeoutMs}ms (found ${fakeProcs.length - prevCount} new procs)`);
}

/** Small sleep that yields to the event loop. */
function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

beforeEach(() => {
  fakeProcs.length = 0;
});
afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Wall-clock timeout
// ---------------------------------------------------------------------------

describe("wall-clock timeout", () => {
  it("kills the subprocess and reports killedReason=timeout after the cap elapses", async () => {
    // Use a very short cap (5 ms) so the watchdog fires almost immediately.
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 5,
      stdoutStalenessMs: 0,
    }));

    // Wait for the spawn to happen, then do nothing — let the wall-clock timer fire.
    const proc = await waitForProc(0);

    // Sleep past the wall-clock cap.
    await sleep(20);

    // The proc should have been killed by SIGTERM (then close event was emitted).
    const result = await promise;

    expect(result.killedReason).toBe("timeout");
    expect(proc.killed).toBe(true);
    expect(proc.killSignals).toContain("SIGTERM");
    // A watchdog kill must NOT trigger a retry.
    expect(result.wasRetry).toBe(false);
  }, 10_000);
});

// ---------------------------------------------------------------------------
// Stdout staleness
// ---------------------------------------------------------------------------

describe("stdout staleness", () => {
  it("kills the subprocess when no stdout arrives within the staleness window", async () => {
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 5,
    }));

    const proc = await waitForProc(0);

    // Do NOT push any stdout — let the staleness timer fire.
    await sleep(20);

    const result = await promise;

    expect(result.killedReason).toBe("staleness");
    expect(proc.killed).toBe(true);
    expect(result.wasRetry).toBe(false);
  }, 10_000);

  it("resets the staleness countdown when stdout arrives", async () => {
    // 50 ms staleness window.
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 50,
    }));

    const proc = await waitForProc(0);

    // Push stdout at 20 ms — before the 50 ms threshold.
    await sleep(20);
    proc.pushLine(JSON.stringify({ type: "result", usage: {}, total_cost_usd: 0 }));

    // Push again at 40 ms (still within the reset window).
    await sleep(20);
    proc.pushLine(JSON.stringify({ type: "result", usage: {}, total_cost_usd: 0 }));

    // Let the process exit cleanly before the staleness timer fires.
    await sleep(10);
    proc.end(0);

    const result = await promise;

    expect(result.killedReason).toBeNull();
    expect(result.exitCode).toBe(0);
  }, 10_000);
});

// ---------------------------------------------------------------------------
// Retry on zero records / non-zero exit
// ---------------------------------------------------------------------------

describe("retry on non-zero exit with no records", () => {
  it("retries exactly once and reports wasRetry=true", async () => {
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 0,
    }));

    // Attempt 1: exit with code 1, no output.
    const proc1 = await waitForProc(0);
    proc1.end(1);

    // Attempt 2 (retry): also fails.
    const proc2 = await waitForProc(1);
    proc2.end(1);

    const result = await promise;

    expect(result.wasRetry).toBe(true);
    expect(result.exitCode).toBe(1);
    expect(fakeProcs.length).toBe(2); // exactly two spawns
  }, 10_000);

  it("does NOT retry on a clean exit (exitCode=0)", async () => {
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 0,
    }));

    const proc = await waitForProc(0);
    proc.end(0);

    const result = await promise;

    expect(result.wasRetry).toBe(false);
    expect(result.exitCode).toBe(0);
    expect(fakeProcs.length).toBe(1);
  }, 10_000);

  it("does NOT retry when subprocess was killed by the wall-clock watchdog", async () => {
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 5,
      stdoutStalenessMs: 0,
    }));

    await waitForProc(0);
    await sleep(20); // let the cap fire

    const result = await promise;

    expect(result.killedReason).toBe("timeout");
    expect(result.wasRetry).toBe(false);
    expect(fakeProcs.length).toBe(1);
  }, 10_000);

  it("does NOT retry more than once even if the retry also fails", async () => {
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 0,
    }));

    // Fail attempt 1.
    const proc1 = await waitForProc(0);
    proc1.end(1);

    // Fail attempt 2 (the retry).
    const proc2 = await waitForProc(1);
    proc2.end(1);

    const result = await promise;

    expect(fakeProcs.length).toBe(2);
    expect(result.wasRetry).toBe(true);
    // No third spawn — we do at most one retry.
    expect(proc2).not.toBe(proc1);
  }, 10_000);

  it("does NOT retry if the first attempt succeeded with records", async () => {
    const promise = runDetection(baseDetectionInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 0,
    }));

    const proc = await waitForProc(0);

    // claude -p emits stream-json format: SAST records appear as text content
    // inside an `assistant` message event.
    const sastLine = JSON.stringify({
      kind: "sast",
      cwe: "CWE-79",
      severity: "high",
      file_path: "src/main.ts",
      start_line: 10,
      end_line: 10,
      summary: "XSS",
      confidence: 0.9,
      reasoning: "test",
    });
    // Wrap in a stream-json `assistant` event.
    proc.pushLine(
      JSON.stringify({
        type: "assistant",
        message: {
          content: [{ type: "text", text: sastLine + "\n" }],
          usage: { input_tokens: 100, output_tokens: 50 },
        },
      }),
    );
    proc.end(0);

    const result = await promise;

    expect(result.wasRetry).toBe(false);
    expect(result.records.length).toBe(1);
    expect(fakeProcs.length).toBe(1);
  }, 10_000);
});

// ---------------------------------------------------------------------------
// runRecheck retry
// ---------------------------------------------------------------------------

describe("runRecheck — retry on non-zero exit with no verdicts", () => {
  it("returns immediately without spawning when issues list is empty", async () => {
    const result = await runRecheck({
      ...baseRecheckInput({ issues: [] }),
      wallClockTimeoutMs: 5,
      stdoutStalenessMs: 5,
    });
    expect(result.exitCode).toBe(0);
    expect(result.killedReason).toBeNull();
    expect(result.wasRetry).toBe(false);
    expect(fakeProcs.length).toBe(0);
  });

  it("retries exactly once on non-zero exit with no verdicts", async () => {
    const promise = runRecheck(baseRecheckInput({
      wallClockTimeoutMs: 0,
      stdoutStalenessMs: 0,
    }));

    const proc1 = await waitForProc(0);
    proc1.end(1);

    const proc2 = await waitForProc(1);
    proc2.end(1);

    const result = await promise;

    expect(result.wasRetry).toBe(true);
    expect(fakeProcs.length).toBe(2);
  }, 10_000);

  it("does NOT retry recheck when subprocess was killed by a watchdog", async () => {
    const promise = runRecheck(baseRecheckInput({
      wallClockTimeoutMs: 5,
      stdoutStalenessMs: 0,
    }));

    await waitForProc(0);
    await sleep(20);

    const result = await promise;

    expect(result.killedReason).toBe("timeout");
    expect(result.wasRetry).toBe(false);
    expect(fakeProcs.length).toBe(1);
  }, 10_000);
});
