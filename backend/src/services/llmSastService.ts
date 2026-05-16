/**
 * M6 — LLM-mode SAST orchestrator.
 *
 * Phase 6b: skeleton only. `runDetection` shells out to `claude -p` against
 * a cloned scope, parses the stream-json output, validates each emitted
 * record against its Zod schema, and returns the parsed records. No
 * persistence yet — that comes in 6c.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { Prisma, type PrismaClient } from "@prisma/client";
import { pino } from "pino";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { decodeCredential } from "./credentialService.js";
import { upsertSastIssueFromDetection } from "./issueService.js";
import { readSourceSnippet } from "./sourceSnippet.js";
import { toRepoRelative, toScopeRelative } from "./scopePath.js";
import { getOrCreateSettings } from "./settingsService.js";
import { loadPrompt } from "./promptLoader.js";

type Tx = PrismaClient | Prisma.TransactionClient;

const logger = pino({ level: loadConfig().logLevel, name: "llmSastService" });

// Matches the `claudeuser` row created in docker/backend.Dockerfile.
const CLAUDE_UID = 1001;
const CLAUDE_GID = 1001;

// ---------------------------------------------------------------------------
// Output record schemas
// ---------------------------------------------------------------------------

const SeverityEnum = z.enum(["critical", "high", "medium", "low", "info"]);

const SastRecord = z.object({
  kind: z.literal("sast"),
  cwe: z.string(),
  severity: SeverityEnum,
  cvss_vector: z.string().optional(),
  file_path: z.string(),
  start_line: z.number().int().nonnegative(),
  end_line: z.number().int().nonnegative(),
  summary: z.string(),
  // M6k: snippet is now built by the worker from the file on disk so we
  // can guarantee a canonical N-line context window. Accept the field if
  // the model emits it (back-compat / chatty models) but never trust it.
  snippet: z.string().optional(),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
});
export type SastRecord = z.infer<typeof SastRecord>;

const SastAbsenceRecord = z.object({
  kind: z.literal("sast_absence"),
  cwe: z.string(),
  severity: SeverityEnum,
  summary: z.string(),
  evidence_file: z.string(),
  evidence_line: z.number().int().nonnegative(),
  confidence: z.number().min(0).max(1),
  reasoning: z.string(),
});
export type SastAbsenceRecord = z.infer<typeof SastAbsenceRecord>;

const ReachabilityRecord = z.object({
  kind: z.literal("reachability"),
  sca_issue_id: z.string(),
  reachable: z.boolean(),
  confidence: z.number().min(0).max(1),
  call_sites: z
    .array(
      z.object({
        file: z.string(),
        line: z.number().int().nonnegative(),
        // Worker-built post-detection (M6k); model may still emit it.
        snippet: z.string().optional(),
      }),
    )
    .default([]),
  reasoning: z.string(),
});
export type ReachabilityRecord = z.infer<typeof ReachabilityRecord>;

const CompleteRecord = z.object({
  kind: z.literal("complete"),
  sast_count: z.number().int().nonnegative().optional(),
  sast_absence_count: z.number().int().nonnegative().optional(),
  reachability_count: z.number().int().nonnegative().optional(),
  summary: z.string().optional(),
});
export type CompleteRecord = z.infer<typeof CompleteRecord>;

const DetectionRecord = z.discriminatedUnion("kind", [
  SastRecord,
  SastAbsenceRecord,
  ReachabilityRecord,
  CompleteRecord,
]);
export type DetectionRecord = z.infer<typeof DetectionRecord>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface ScaHintInput {
  id: string;
  package: string;
  version: string | null;
  cve_id: string | null;
  osv_id: string;
  cvss_score: number | null;
  summary: string | null;
}

export interface RunDetectionInput {
  scanRunId: string;
  scopeId: string;
  scopeDir: string;
  repoName: string;
  repoBranch: string;
  ignorePaths: string[];
  scaHints: ScaHintInput[];
  tokenBudget: number;
  /** Effort level for `claude -p --effort`. */
  effortLevel: string;
  orgId: string | null;
  /** Live token-usage callback for setPhase progress. See SpawnClaudeInput. */
  onProgress?: (usage: TokenUsage) => void;
}

export interface RunDetectionResult {
  records: DetectionRecord[];
  parseErrors: ParseError[];
  exitCode: number | null;
  durationMs: number;
  usage: TokenUsage;
}

export interface ParseError {
  raw: string;
  reason: string;
}

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
  /** When claude-p reports it. Independent of underlying model billing. */
  estimatedUsdCost: number | null;
  /** Number of assistant messages in the session — proxy for "request count" in the existing schema. */
  requestCount: number;
}

/**
 * Loads + validates LLM auth/config that both detection and recheck need.
 * Throws with a clear message on misconfiguration so the caller can fail
 * the scan loudly rather than silently producing empty results.
 */
async function resolveLlmConfig(orgId: string | null): Promise<{
  baseUrl: string;
  modelName: string;
  apiKey: string;
}> {
  const settings = await getOrCreateSettings(orgId);
  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    throw new Error(
      "LLM-mode SAST requires AppSettings.llmBaseUrl, llmModel, and llmCredentialId to be configured.",
    );
  }
  if (settings.llmApiFormat && settings.llmApiFormat !== "anthropic-messages") {
    throw new Error(
      `LLM-mode SAST requires llmApiFormat='anthropic-messages'; current value is '${settings.llmApiFormat}'. ` +
        "Claude Code CLI does not speak OpenAI-format protocols.",
    );
  }
  const credential = await decodeCredential(settings.llmCredentialId);
  if (credential.kind !== "llm_api_key") {
    throw new Error(
      `LLM-mode SAST expects an llm_api_key credential; got ${credential.kind}.`,
    );
  }
  return {
    baseUrl: settings.llmBaseUrl,
    modelName: settings.llmModel,
    apiKey: credential.value,
  };
}

/**
 * Sets up the per-scan tmp directory layout. Returns the paths the caller
 * needs (claudeHome for $HOME, tmpDir for arbitrary input files). The
 * caller writes input files into tmpDir and passes their paths to the
 * model via the rendered prompt.
 */
async function ensureTmpDir(scanRunId: string): Promise<{ tmpDir: string; claudeHome: string }> {
  const tmpDir = `/tmp/sastbot-${scanRunId}`;
  const claudeHome = path.join(tmpDir, "home");
  await fs.mkdir(tmpDir, { recursive: true, mode: 0o755 });
  await fs.mkdir(claudeHome, { recursive: true, mode: 0o755 });
  await fs.chown(claudeHome, CLAUDE_UID, CLAUDE_GID).catch(() => {
    /* non-fatal on filesystems without chown support */
  });
  return { tmpDir, claudeHome };
}

/**
 * Spawns `claude -p` with the given prompts and streams stdout. Each
 * complete JSON-Lines line emitted by the model in assistant-text events
 * is passed to `onLine`. Returns the session's token usage.
 *
 * The function does not interpret the model output beyond splitting on
 * newlines — schema validation is the caller's job.
 */
interface SpawnClaudeInput {
  scanRunId: string;
  scopeDir: string;
  systemPrompt: string;
  userPrompt: string;
  modelName: string;
  apiKey: string;
  baseUrl: string;
  claudeHome: string;
  /** `--effort` value passed to claude-p. low | medium | high | xhigh | max.
   *  Required so we never silently inherit the Claude Code product default
   *  (which differs by model — xhigh on Opus 4.7, high on Sonnet 4.6 — and
   *  could change again in a future release). */
  effortLevel: string;
  /** Called once per assistant-text line (already trimmed of the trailing newline). */
  onLine: (line: string) => void;
  /**
   * Called on each `assistant` stream event with the running session usage.
   * Per-message token counts are accumulated; the terminal `result` event
   * later overwrites with claude-p's authoritative session totals. Use this
   * to surface live progress (e.g. setPhase) — the values are best-effort
   * during the run and exact at the end.
   */
  onProgress?: (usage: TokenUsage) => void;
}

interface SpawnClaudeResult {
  exitCode: number | null;
  usage: TokenUsage;
}

async function spawnClaudeAndStream(input: SpawnClaudeInput): Promise<SpawnClaudeResult> {
  const args = [
    "-p",
    input.userPrompt,
    "--model",
    input.modelName,
    "--effort",
    input.effortLevel,
    "--allowed-tools",
    "Bash Read Glob Grep",
    "--permission-mode",
    "bypassPermissions",
    "--output-format",
    "stream-json",
    "--verbose",
    "--append-system-prompt",
    input.systemPrompt,
  ];

  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ANTHROPIC_API_KEY: input.apiKey,
    ANTHROPIC_BASE_URL: input.baseUrl,
    HOME: input.claudeHome,
    USER: "claudeuser",
  };

  const usage: TokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
    estimatedUsdCost: null,
    requestCount: 0,
  };

  const exitCode: number | null = await new Promise((resolve, reject) => {
    const proc = spawn("claude", args, {
      cwd: input.scopeDir,
      env: childEnv,
      stdio: ["ignore", "pipe", "pipe"],
      uid: CLAUDE_UID,
      gid: CLAUDE_GID,
    });

    let stdoutBuf = "";
    let stderrBuf = "";
    let assistantTextBuf = "";

    const flushAssistantLines = (final: boolean): void => {
      const lines = assistantTextBuf.split("\n");
      const tail = final ? "" : (lines.pop() ?? "");
      assistantTextBuf = tail;
      for (const raw of lines) {
        const trimmed = raw.trim();
        if (!trimmed) continue;
        input.onLine(trimmed);
      }
    };

    const handleStreamEvent = (event: unknown): void => {
      if (!event || typeof event !== "object" || !("type" in event)) return;
      const t = (event as { type: string }).type;

      if (t === "assistant") {
        const msg = (event as {
          message?: {
            content?: Array<{ type?: string; text?: string }>;
            usage?: {
              input_tokens?: number;
              output_tokens?: number;
              cache_read_input_tokens?: number;
              cache_creation_input_tokens?: number;
            };
          };
        }).message;
        const u = msg?.usage ?? {};
        usage.inputTokens += u.input_tokens ?? 0;
        usage.outputTokens += u.output_tokens ?? 0;
        usage.cacheReadInputTokens += u.cache_read_input_tokens ?? 0;
        usage.cacheCreationInputTokens += u.cache_creation_input_tokens ?? 0;
        const content = msg?.content ?? [];
        for (const block of content) {
          if (block.type === "text" && typeof block.text === "string") {
            assistantTextBuf += block.text;
          }
        }
        usage.requestCount += 1;
        flushAssistantLines(false);
        if (input.onProgress) input.onProgress(usage);
        return;
      }

      if (t === "result") {
        const ev = event as {
          usage?: {
            input_tokens?: number;
            output_tokens?: number;
            cache_read_input_tokens?: number;
            cache_creation_input_tokens?: number;
          };
          total_cost_usd?: number;
          cost_usd?: number;
        };
        const u = ev.usage ?? {};
        usage.inputTokens = u.input_tokens ?? 0;
        usage.outputTokens = u.output_tokens ?? 0;
        usage.cacheReadInputTokens = u.cache_read_input_tokens ?? 0;
        usage.cacheCreationInputTokens = u.cache_creation_input_tokens ?? 0;
        usage.estimatedUsdCost = ev.total_cost_usd ?? ev.cost_usd ?? null;
      }
    };

    proc.stdout.setEncoding("utf8");
    proc.stdout.on("data", (chunk: string) => {
      stdoutBuf += chunk;
      const lines = stdoutBuf.split("\n");
      stdoutBuf = lines.pop() ?? "";
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          handleStreamEvent(JSON.parse(trimmed));
        } catch (err) {
          logger.debug({ line: trimmed.slice(0, 200), err: (err as Error).message }, "non-JSON stream line");
        }
      }
    });

    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => {
      stderrBuf += chunk;
    });

    proc.on("error", (err) => {
      logger.error({ err: err.message }, "[llmSastService] claude spawn error");
      reject(err);
    });

    proc.on("close", (code) => {
      flushAssistantLines(true);
      if (stderrBuf.trim().length > 0) {
        logger.info({ stderr: stderrBuf.slice(0, 2000) }, "[llmSastService] claude stderr");
      }
      resolve(code);
    });
  });

  return { exitCode, usage };
}

/**
 * Run the LLM SAST detection pass.
 *
 * Spawns `claude -p` with the rendered prompts, streams stdout, splits
 * assistant text into JSON-Lines, validates each line against the
 * detection record schema. Returns the structured result. Does not
 * persist anything — caller does that with persistDetection.
 */
export async function runDetection(input: RunDetectionInput): Promise<RunDetectionResult> {
  const startedAt = Date.now();
  const { baseUrl, modelName, apiKey } = await resolveLlmConfig(input.orgId);
  const { tmpDir, claudeHome } = await ensureTmpDir(input.scanRunId);

  const scaInputPath = path.join(tmpDir, "sca_high_critical.jsonl");
  const scaJsonl = input.scaHints.map((h) => JSON.stringify(h)).join("\n") + "\n";
  await fs.writeFile(scaInputPath, scaJsonl, { encoding: "utf8", mode: 0o644 });

  const ignorePathsBlock = input.ignorePaths.length > 0
    ? input.ignorePaths.map((p) => `  - ${p}`).join("\n")
    : "  (none)";
  const systemPrompt = loadPrompt("sast_system", {});
  const userPrompt = loadPrompt("sast_detection", {
    SCOPE_PATH: input.scopeDir,
    REPO_NAME: input.repoName,
    REPO_BRANCH: input.repoBranch,
    IGNORE_PATHS: ignorePathsBlock,
    TOKEN_BUDGET: String(input.tokenBudget),
    SCA_INPUT_PATH: scaInputPath,
  });

  logger.info(
    {
      scanRunId: input.scanRunId,
      scopeDir: input.scopeDir,
      tokenBudget: input.tokenBudget,
      scaHintCount: input.scaHints.length,
      model: modelName,
      baseUrl,
    },
    "[llmSastService] starting detection",
  );

  const records: DetectionRecord[] = [];
  const parseErrors: ParseError[] = [];

  const { exitCode, usage } = await spawnClaudeAndStream({
    scanRunId: input.scanRunId,
    scopeDir: input.scopeDir,
    systemPrompt,
    userPrompt,
    modelName,
    apiKey,
    baseUrl,
    claudeHome,
    effortLevel: input.effortLevel,
    onProgress: input.onProgress,
    onLine: (line) => {
      if (!line.startsWith("{")) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        parseErrors.push({ raw: line, reason: `JSON parse: ${(err as Error).message}` });
        return;
      }
      const result = DetectionRecord.safeParse(parsed);
      if (!result.success) {
        parseErrors.push({
          raw: line,
          reason: `schema: ${result.error.errors.map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")}`,
        });
        return;
      }
      records.push(result.data);
    },
  });

  const durationMs = Date.now() - startedAt;
  logger.info(
    {
      scanRunId: input.scanRunId,
      exitCode,
      durationMs,
      recordCount: records.length,
      parseErrorCount: parseErrors.length,
      usage,
    },
    "[llmSastService] detection finished",
  );

  return { records, parseErrors, exitCode, durationMs, usage };
}

/**
 * Idempotent cleanup of the per-scan tmp directory used for SCA / recheck
 * input files. Caller invokes after the scan completes (success or failure).
 */
export async function cleanupTmp(scanRunId: string): Promise<void> {
  const tmpDir = `/tmp/sastbot-${scanRunId}`;
  await fs.rm(tmpDir, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Recheck pass — Phase 6d
// ---------------------------------------------------------------------------

const RecheckVerdictRecord = z.object({
  id: z.string(),
  verdict: z.enum(["still_present", "fixed", "file_deleted", "duplicate_of"]),
  reasoning: z.string(),
  current_snippet: z.string().optional(),
  /** Required when verdict === "duplicate_of"; the SastIssue.id of the target
   *  the candidate is being folded into. Ignored on other verdicts. */
  duplicate_of: z.string().optional(),
});
export type RecheckVerdictRecord = z.infer<typeof RecheckVerdictRecord>;

const RecheckCompleteRecord = z.object({
  kind: z.literal("complete"),
  verified: z.number().int().nonnegative().optional(),
  still_present: z.number().int().nonnegative().optional(),
  fixed: z.number().int().nonnegative().optional(),
  file_deleted: z.number().int().nonnegative().optional(),
  duplicate_of: z.number().int().nonnegative().optional(),
});
export type RecheckCompleteRecord = z.infer<typeof RecheckCompleteRecord>;

/** Reference list the recheck LLM consults when deciding whether a candidate
 *  is actually a relocated / re-labeled variant of an issue already alive in
 *  this scope. Issues that ARE in the latest detection (re-emitted this run)
 *  plus the recheck candidates themselves are all valid duplicate targets. */
export interface RecheckDuplicateTarget {
  id: string;
  file: string;
  line: number;
  cwe: string;
  summary: string;
}

export interface RecheckIssueInput {
  /** SastIssue.id — round-trips through the LLM so we can map verdict back. */
  id: string;
  file: string;
  line: number;
  summary: string;
  snippet: string;
  cwe: string;
}

export interface RunRecheckInput {
  scanRunId: string;
  scopeDir: string;
  /** Repo-rooted scope path. Issue paths in `issues` are stored repo-rooted;
   *  we translate them to scope-relative form for the LLM (which runs with
   *  cwd=scopeDir and needs paths it can read directly). */
  scopePath: string;
  issues: RecheckIssueInput[];
  /** Active SAST issues in this scope that the candidate could be a duplicate
   *  of (after relocation / re-labeling). Includes the re-emitted issues from
   *  the latest detection AND the recheck candidates themselves — both are
   *  valid merge targets. Paths are repo-rooted; runRecheck translates them
   *  before writing the prompt input file. */
  duplicateTargets: RecheckDuplicateTarget[];
  tokenBudget: number;
  /** Effort level for `claude -p --effort`. Recheck is narrow verification
   *  and typically wants a lower effort than detection. */
  effortLevel: string;
  orgId: string | null;
  /** Called on each assistant stream event with the running session usage.
   *  Same semantics as RunDetectionInput.onProgress — used for live phase
   *  progress (verdicts arrive batched at the end of the run, so they're a
   *  poor unit of progress; tokens advance per LLM round-trip). */
  onProgress?: (usage: TokenUsage) => void;
}

export interface RunRecheckResult {
  verdicts: RecheckVerdictRecord[];
  parseErrors: ParseError[];
  exitCode: number | null;
  durationMs: number;
  usage: TokenUsage;
}

/**
 * Run the targeted re-check pass against issues the latest detection didn't
 * re-emit. Returns one verdict per input issue (in the order the model emits
 * them; orchestrator does the id→issue mapping).
 *
 * Skips and returns empty when `issues` is empty.
 */
export async function runRecheck(input: RunRecheckInput): Promise<RunRecheckResult> {
  if (input.issues.length === 0) {
    return {
      verdicts: [],
      parseErrors: [],
      exitCode: 0,
      durationMs: 0,
      usage: {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadInputTokens: 0,
        cacheCreationInputTokens: 0,
        estimatedUsdCost: null,
        requestCount: 0,
      },
    };
  }

  const startedAt = Date.now();
  const { baseUrl, modelName, apiKey } = await resolveLlmConfig(input.orgId);
  const { tmpDir, claudeHome } = await ensureTmpDir(input.scanRunId);

  const issuesInputPath = path.join(tmpDir, "recheck_issues.jsonl");
  // The model reads files with cwd=scopeDir, so input file paths must be
  // scope-relative. DB stores repo-rooted; translate per-issue.
  const issuesForModel = input.issues.map((i) => ({
    ...i,
    file: toScopeRelative(input.scopePath, i.file),
  }));
  const jsonl = issuesForModel.map((i) => JSON.stringify(i)).join("\n") + "\n";
  await fs.writeFile(issuesInputPath, jsonl, { encoding: "utf8", mode: 0o644 });

  // Duplicate-target reference list — what the LLM consults when deciding
  // whether a candidate is a relocated variant of a still-alive issue.
  const duplicateTargetsPath = path.join(tmpDir, "recheck_duplicate_targets.jsonl");
  const candidateIds = new Set(input.issues.map((i) => i.id));
  const targetsForModel = input.duplicateTargets
    // Don't list a candidate as its own duplicate target — the candidate is
    // already being inspected and would otherwise look at itself.
    .filter((t) => !candidateIds.has(t.id))
    .map((t) => ({
      ...t,
      file: toScopeRelative(input.scopePath, t.file),
    }));
  const targetsJsonl = targetsForModel.length > 0
    ? targetsForModel.map((t) => JSON.stringify(t)).join("\n") + "\n"
    : "";
  await fs.writeFile(duplicateTargetsPath, targetsJsonl, { encoding: "utf8", mode: 0o644 });

  const systemPrompt = loadPrompt("sast_system", {});
  const userPrompt = loadPrompt("sast_recheck", {
    SCOPE_PATH: input.scopeDir,
    TOKEN_BUDGET: String(input.tokenBudget),
    ISSUES_INPUT_PATH: issuesInputPath,
    DUPLICATE_TARGETS_PATH: duplicateTargetsPath,
    DUPLICATE_TARGETS_COUNT: String(targetsForModel.length),
  });

  logger.info(
    {
      scanRunId: input.scanRunId,
      issueCount: input.issues.length,
      tokenBudget: input.tokenBudget,
      model: modelName,
    },
    "[llmSastService] starting recheck",
  );

  const verdicts: RecheckVerdictRecord[] = [];
  const parseErrors: ParseError[] = [];

  const { exitCode, usage } = await spawnClaudeAndStream({
    scanRunId: input.scanRunId,
    scopeDir: input.scopeDir,
    systemPrompt,
    userPrompt,
    modelName,
    apiKey,
    baseUrl,
    claudeHome,
    effortLevel: input.effortLevel,
    onProgress: input.onProgress,
    onLine: (line) => {
      if (!line.startsWith("{")) return;
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        parseErrors.push({ raw: line, reason: `JSON parse: ${(err as Error).message}` });
        return;
      }
      // Try verdict first (lacks `kind`). Fall back to complete record.
      const verdict = RecheckVerdictRecord.safeParse(parsed);
      if (verdict.success) {
        verdicts.push(verdict.data);
        return;
      }
      const complete = RecheckCompleteRecord.safeParse(parsed);
      if (complete.success) return; // info-only; not persisted
      parseErrors.push({
        raw: line,
        reason: `schema: ${verdict.error.errors.map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")}`,
      });
    },
  });

  const durationMs = Date.now() - startedAt;
  logger.info(
    {
      scanRunId: input.scanRunId,
      exitCode,
      durationMs,
      verdictCount: verdicts.length,
      parseErrorCount: parseErrors.length,
      usage,
    },
    "[llmSastService] recheck finished",
  );

  return { verdicts, parseErrors, exitCode, durationMs, usage };
}

// ---------------------------------------------------------------------------
// Recheck verdict persistence
// ---------------------------------------------------------------------------

export interface ApplyRecheckInput {
  scanRunId: string;
  scopeId: string;
  /** Absolute path to the scope's working dir on disk — used to refresh the
   *  snippet from the file system on `still_present` verdicts (M6k). */
  scopeDir: string;
  /** Repo-rooted scope path ("/" or "/GoWeb") — needed to translate the
   *  issue's repo-rooted file path back to scope-relative when reading. */
  scopePath: string;
  /** Issues that were sent into the recheck pass — needed to detect "no verdict
   *  emitted" cases where the model silently dropped one. */
  inputIssues: RecheckIssueInput[];
  verdicts: RecheckVerdictRecord[];
}

export interface ApplyRecheckResult {
  stillPresent: number;
  fixed: number;
  fileDeleted: number;
  duplicatesMerged: number;
  /** Issues we sent in but got no verdict for — left as-is (no false closure). */
  missingVerdict: number;
}

/** Triage states the recheck merger refuses to delete from. Operator-curated
 *  rows stay even if the LLM flags them as a duplicate — the operator's
 *  verdict is the source of truth, just like in the same-scope merger. */
const RECHECK_NON_MERGEABLE_STATUSES = new Set([
  "confirmed",
  "planned",
  "fixed",
  "suppressed",
  "false_positive",
]);

/**
 * Apply recheck verdicts to SastIssue rows.
 *
 * - still_present: advance lastSeenScanRunId to current; preserve triageStatus.
 * - fixed: triageStatus = "fixed"; advance lastSeenScanRunId.
 * - file_deleted: same as fixed; reasoning prefixed with "[file deleted]".
 *
 * Issues with no matching verdict are left untouched (the conservative
 * default — better to keep an open issue around than to silently close it).
 */
export async function applyRecheckVerdicts(
  client: Tx,
  input: ApplyRecheckInput,
): Promise<ApplyRecheckResult> {
  const db = client as PrismaClient;
  const verdictsById = new Map(input.verdicts.map((v) => [v.id, v]));
  const result: ApplyRecheckResult = {
    stillPresent: 0,
    fixed: 0,
    fileDeleted: 0,
    duplicatesMerged: 0,
    missingVerdict: 0,
  };

  for (const issue of input.inputIssues) {
    const v = verdictsById.get(issue.id);
    if (!v) {
      result.missingVerdict++;
      continue;
    }

    // Defensive scope check — refuse to mutate an issue from another scope.
    const row = await db.sastIssue.findFirst({
      where: { id: issue.id, scopeId: input.scopeId },
      select: {
        id: true,
        fingerprint: true,
        latestFilePath: true,
        latestStartLine: true,
        latestEndLine: true,
        latestCweIds: true,
        latestSeverity: true,
        triageStatus: true,
        jiraTicketId: true,
      },
    });
    if (!row) {
      logger.warn(
        { issueId: issue.id, scopeId: input.scopeId },
        "[llmSastService] recheck verdict references unknown SastIssue — skipped",
      );
      continue;
    }

    if (v.verdict === "still_present") {
      // Refresh the snippet from disk so it reflects the canonical 7-line
      // layout (M6k). The recheck only confirms presence — the line itself
      // hasn't moved (the model would emit a "fixed" verdict otherwise),
      // so we read at row.latestStartLine. Fall back to the LLM-supplied
      // current_snippet only if the file isn't readable.
      const scopeRelPath = toScopeRelative(input.scopePath, row.latestFilePath);
      const fileSnippet = await readSourceSnippet(
        input.scopeDir,
        scopeRelPath,
        row.latestStartLine,
        row.latestEndLine ?? undefined,
      );
      await db.sastIssue.update({
        where: { id: issue.id },
        data: {
          lastSeenAt: new Date(),
          lastSeenScanRunId: input.scanRunId,
          // Preserve triageStatus — recheck does not flip pending/error/etc.
          latestSnippet: fileSnippet?.text ?? v.current_snippet ?? undefined,
        },
      });
      result.stillPresent++;
    } else if (v.verdict === "fixed") {
      await db.sastIssue.update({
        where: { id: issue.id },
        data: {
          lastSeenAt: new Date(),
          lastSeenScanRunId: input.scanRunId,
          triageStatus: "fixed",
          triageReasoning: v.reasoning,
        },
      });
      result.fixed++;
    } else if (v.verdict === "file_deleted") {
      await db.sastIssue.update({
        where: { id: issue.id },
        data: {
          lastSeenAt: new Date(),
          lastSeenScanRunId: input.scanRunId,
          triageStatus: "fixed",
          triageReasoning: `[file deleted] ${v.reasoning}`,
        },
      });
      result.fileDeleted++;
    } else if (v.verdict === "duplicate_of") {
      // Refuse to merge an operator-curated row away — the same-scope
      // merger applies the same rule. Treat as still_present instead.
      if (RECHECK_NON_MERGEABLE_STATUSES.has(row.triageStatus)) {
        logger.info(
          { issueId: row.id, triageStatus: row.triageStatus },
          "[llmSastService] duplicate_of verdict ignored — row is operator-curated",
        );
        await db.sastIssue.update({
          where: { id: row.id },
          data: { lastSeenAt: new Date(), lastSeenScanRunId: input.scanRunId },
        });
        result.stillPresent++;
        continue;
      }
      const targetId = v.duplicate_of;
      if (!targetId) {
        logger.warn(
          { issueId: row.id },
          "[llmSastService] duplicate_of verdict missing target id — treated as still_present",
        );
        await db.sastIssue.update({
          where: { id: row.id },
          data: { lastSeenAt: new Date(), lastSeenScanRunId: input.scanRunId },
        });
        result.stillPresent++;
        continue;
      }
      if (targetId === row.id) {
        logger.warn({ issueId: row.id }, "[llmSastService] duplicate_of points at self — ignored");
        result.stillPresent++;
        continue;
      }
      const target = await db.sastIssue.findFirst({
        where: { id: targetId, scopeId: input.scopeId },
        select: {
          id: true,
          fingerprint: true,
          latestCweIds: true,
          latestLlmSummary: true,
          latestRuleMessage: true,
          jiraTicketId: true,
          triageStatus: true,
          latestFilePath: true,
          latestStartLine: true,
          latestEndLine: true,
        },
      });
      // Target may have been deleted earlier in this loop (cycles, or another
      // candidate already merged into it then merged itself elsewhere).
      // Conservative: leave the candidate alive.
      if (!target) {
        logger.info(
          { issueId: row.id, targetId },
          "[llmSastService] duplicate_of target no longer present — treated as still_present",
        );
        await db.sastIssue.update({
          where: { id: row.id },
          data: { lastSeenAt: new Date(), lastSeenScanRunId: input.scanRunId },
        });
        result.stillPresent++;
        continue;
      }

      const cweUnion = new Set<string>(target.latestCweIds);
      for (const c of row.latestCweIds) cweUnion.add(c);
      const cwePart = row.latestCweIds.join(",") || "CWE-?";
      const range = row.latestEndLine != null && row.latestEndLine !== row.latestStartLine
        ? `L${row.latestStartLine}-${row.latestEndLine}`
        : `L${row.latestStartLine}`;
      const baseSummary = (target.latestLlmSummary ?? target.latestRuleMessage ?? "").trim();
      const newSummary = `${baseSummary}\n\nSee also: ${cwePart} ${row.latestFilePath} ${range} (merged by recheck)`.trim();

      await db.scaIssue.updateMany({
        where: { scopeId: input.scopeId, reachableViaSastFingerprint: row.fingerprint },
        data: { reachableViaSastFingerprint: target.fingerprint },
      });
      await db.sastIssue.update({
        where: { id: target.id },
        data: {
          latestCweIds: Array.from(cweUnion),
          latestLlmSummary: newSummary,
          ...(target.jiraTicketId == null && row.jiraTicketId != null
            ? { jiraTicketId: row.jiraTicketId }
            : {}),
          lastSeenAt: new Date(),
          lastSeenScanRunId: input.scanRunId,
        },
      });
      await db.sastIssue.delete({ where: { id: row.id } });

      logger.info(
        {
          scopeId: input.scopeId,
          mergedId: row.id,
          targetId: target.id,
          cweUnion: Array.from(cweUnion),
        },
        "[llmSastService] recheck merged duplicate",
      );
      result.duplicatesMerged++;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Persistence — Phase 6c
// ---------------------------------------------------------------------------

export interface PersistDetectionInput {
  scanRunId: string;
  scopeId: string;
  scopeDir: string;
  /** Repo-rooted scope path ("/" for root scopes, "/GoWeb" etc. otherwise).
   *  Used to translate the LLM's scope-relative paths into repo-rooted
   *  paths before persisting, so file links work correctly across scopes. */
  scopePath: string;
  orgId: string | null;
  records: DetectionRecord[];
  modelName: string;
}

export interface PersistDetectionResult {
  sastUpserted: number;
  sastAbsenceUpserted: number;
  reachabilityUpdated: number;
  reachabilitySkipped: number;
}

/** Whitespace-collapse normalization shared with sastService.normalizeSnippet
 *  (kept local here to avoid coupling the two engines). */
function normalizeSnippet(s: string): string {
  return s.replace(/\s+/g, " ").trim();
}

/**
 * Read line N (1-indexed) from a file under scopeDir. Returns "" on any
 * error — caller falls back to the LLM-supplied snippet. We never trust
 * file paths to escape scopeDir even if the LLM emits "../" tricks.
 */
async function readMatchLine(
  scopeDir: string,
  filePath: string,
  lineNumber: number,
): Promise<string> {
  try {
    const resolved = path.resolve(scopeDir, filePath);
    if (!resolved.startsWith(path.resolve(scopeDir))) {
      // Path traversal — refuse silently, fall back to LLM snippet.
      return "";
    }
    const text = await fs.readFile(resolved, "utf8");
    const lines = text.split("\n");
    return lines[lineNumber - 1] ?? "";
  } catch {
    return "";
  }
}

/**
 * Build a stable fingerprint for a per-location SAST finding.
 *
 * We read the actual source line from disk and hash it (after whitespace
 * normalization). Hashing the LLM-emitted `snippet` directly is too
 * brittle — minor textual drift run-to-run produced duplicate Issue rows
 * during 6c verification.
 *
 * Falls back to hashing a normalized version of the LLM snippet when the
 * file isn't readable (deleted, race, etc.) — that's still stable for the
 * absence/recheck pass that follows.
 */
async function computeSastFingerprint(
  scopeDir: string,
  filePath: string,
  startLine: number,
  fallbackSnippet: string,
): Promise<string> {
  const matchLine = await readMatchLine(scopeDir, filePath, startLine);
  const basis = matchLine.length > 0 ? matchLine : fallbackSnippet;
  return createHash("sha256").update(normalizeSnippet(basis)).digest("hex").slice(0, 16);
}

function computeAbsenceFingerprint(cwe: string): string {
  return createHash("sha256").update(`__absence__:${cwe}`).digest("hex").slice(0, 16);
}

export async function persistDetection(
  client: Tx,
  input: PersistDetectionInput,
): Promise<PersistDetectionResult> {
  const db = client as PrismaClient;
  const result: PersistDetectionResult = {
    sastUpserted: 0,
    sastAbsenceUpserted: 0,
    reachabilityUpdated: 0,
    reachabilitySkipped: 0,
  };

  // The LLM emits paths relative to scopeDir (its cwd). Translate them to
  // repo-rooted form for persistence so the FE's <FileLink> works across
  // scopes consistently. The fingerprint helper reads the file from disk
  // and so still wants the scope-relative form — it gets the LLM's raw
  // r.file_path before translation.
  for (const r of input.records) {
    if (r.kind === "sast") {
      const fingerprint = await computeSastFingerprint(
        input.scopeDir,
        r.file_path,
        r.start_line,
        r.snippet ?? "",
      );
      // Build the snippet from disk; fall back to the LLM-supplied one only
      // if the file isn't readable (deleted, race, etc.). Honors r.end_line
      // so multi-line problems (e.g. paired #define blocks) get all the
      // problem rows + 3 lines of context on each side.
      const fileSnippet = await readSourceSnippet(
        input.scopeDir,
        r.file_path,
        r.start_line,
        r.end_line,
      );
      await upsertSastIssueFromDetection(db, input.scanRunId, input.scopeId, input.orgId, {
        fingerprint,
        ruleId: `llm:${r.cwe}`,
        ruleName: null,
        ruleMessage: r.summary,
        severity: r.severity,
        cweIds: [r.cwe],
        filePath: toRepoRelative(input.scopePath, r.file_path),
        startLine: r.start_line,
        endLine: r.end_line,
        snippet: fileSnippet?.text ?? r.snippet ?? null,
      });
      result.sastUpserted++;
    } else if (r.kind === "sast_absence") {
      const fingerprint = computeAbsenceFingerprint(r.cwe);
      await upsertSastIssueFromDetection(db, input.scanRunId, input.scopeId, input.orgId, {
        fingerprint,
        ruleId: `llm:${r.cwe}:absence`,
        ruleName: null,
        ruleMessage: r.summary,
        severity: r.severity,
        cweIds: [r.cwe],
        filePath: toRepoRelative(input.scopePath, r.evidence_file),
        startLine: r.evidence_line,
        endLine: null,
        snippet: `__absence__:${r.cwe}`,
      });
      result.sastAbsenceUpserted++;
    } else if (r.kind === "reachability") {
      // Only update if the ScaIssue belongs to this scope (defense against the
      // model fabricating an id from a different scope).
      const scaIssue = await db.scaIssue.findFirst({
        where: { id: r.sca_issue_id, scopeId: input.scopeId },
        select: { id: true },
      });
      if (!scaIssue) {
        result.reachabilitySkipped++;
        logger.warn(
          { sca_issue_id: r.sca_issue_id, scopeId: input.scopeId },
          "[llmSastService] reachability record references unknown ScaIssue — skipped",
        );
        continue;
      }
      // M6k: build call-site snippets from disk so they match the canonical
      // 7-line layout. The LLM-supplied snippet is fallback only.
      const repoRootedSites = await Promise.all(
        r.call_sites.map(async (s) => {
          const fileSnippet = await readSourceSnippet(input.scopeDir, s.file, s.line);
          return {
            file: toRepoRelative(input.scopePath, s.file),
            line: s.line,
            snippet: fileSnippet?.text ?? s.snippet ?? "",
          };
        }),
      );
      await db.scaIssue.update({
        where: { id: r.sca_issue_id },
        data: {
          confirmedReachable: r.reachable,
          reachableConfidence: r.confidence,
          reachableReasoning: r.reasoning,
          reachableCallSites: repoRootedSites.length > 0
            ? (repoRootedSites as unknown as Prisma.InputJsonValue)
            : Prisma.DbNull,
          reachableAssessedAt: new Date(),
          reachableModel: input.modelName,
        },
      });
      result.reachabilityUpdated++;
    }
    // kind === "complete" — caller logs separately, no persistence.
  }

  return result;
}
