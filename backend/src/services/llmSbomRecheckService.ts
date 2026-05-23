/**
 * SBOM Component Recheck — Stage 2.
 *
 * The `llm_sbom_recheck` worker phase. Compares the set of `scope_components`
 * rows that are `active` but NOT surfaced in the current scan run's
 * augmentation pass against the clone on disk.
 *
 * Two-tier check (per the plan in docs/SBOM_COMPONENT_RECHECK_PLAN.md):
 *
 *   Tier 1 — filesystem evidence check (free):
 *     If the row has an evidencePath: stat the file. Missing → mark removed.
 *     File still there → fall through to Tier 2.
 *     No evidencePath → fall straight through to Tier 2.
 *
 *   Tier 2 — focused LLM recheck (bounded cost):
 *     One `claude -p` call with the candidate list. Each line of the response
 *     is a verdict:
 *       {"component_id":"...","verdict":"present","rationale":"..."}
 *       {"component_id":"...","verdict":"removed","rationale":"..."}
 *     Recoveries are written back as scan_run_components join rows and the
 *     scope_component's lastSeenScanRunId / lastSeenAt are advanced.
 *
 * Architecture mirrors llmSastService.ts / llmSbomService.ts — same
 * spawnClaudeAndStream helper pattern, same error-handling conventions.
 */

import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";
import { appendBlockText, extractJsonObjects } from "./llmSastService.js";
import { pino } from "pino";
import { z } from "zod";

import { loadConfig } from "../config.js";
import { prisma } from "../db.js";
import { decodeCredential } from "./credentialService.js";
import { getOrCreateSettings } from "./settingsService.js";
import { loadPrompt } from "./promptLoader.js";

const logger = pino({ level: loadConfig().logLevel, name: "llmSbomRecheckService" });

// Matches the `claudeuser` row created in docker/backend.Dockerfile.
const CLAUDE_UID = 1001;
const CLAUDE_GID = 1001;

/**
 * Hard cap on recheck candidates passed to Tier-2 verification. Defends
 * against bug-induced runaway sets (e.g. a join-table misalignment that
 * causes the candidate set to incorrectly include the whole scope) and
 * bounds worst-case cost / wall-clock. Token budget (50k) is the secondary
 * limit — practically allows ~165 candidates per call, so this cap is the
 * binding constraint for typical scans. Set high enough that normal
 * post-augmentation drift (typically 10-30 rows on the small C++ scope)
 * never trips it. Original 20 was too low — FSS regularly trips it at
 * 22-30 candidates as the LLM name-shifts row identity.
 */
const MAX_CANDIDATES = 100;

// ---------------------------------------------------------------------------
// Output record schemas
// ---------------------------------------------------------------------------

const RecheckVerdictSchema = z.object({
  component_id: z.string(),
  verdict: z.enum(["present", "removed"]),
  new_evidence_path: z.string().optional(),
  rationale: z.string(),
});
export type SbomRecheckVerdict = z.infer<typeof RecheckVerdictSchema>;

const MergeVerdictSchema = z.object({
  type: z.literal("merge"),
  keep_id: z.string(),
  drop_ids: z.array(z.string()).min(1),
  rationale: z.string(),
});
export type SbomMergeVerdict = z.infer<typeof MergeVerdictSchema>;

/**
 * Discriminated union: parse any line the LLM emits.
 * Lines without `"type":"merge"` are tried as presence/absence verdicts;
 * lines with `"type":"merge"` are tried as merge verdicts.
 */
const AnyVerdictSchema = z.union([MergeVerdictSchema, RecheckVerdictSchema]);

// ---------------------------------------------------------------------------
// Internal helpers (mirrored from llmSastService / llmSbomService)
// ---------------------------------------------------------------------------

interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
  estimatedUsdCost: number | null;
  requestCount: number;
}

interface ParseError {
  raw: string;
  reason: string;
}

async function resolveLlmConfig(orgId: string | null): Promise<{
  baseUrl: string;
  modelName: string;
  apiKey: string;
}> {
  const settings = await getOrCreateSettings(orgId);
  if (!settings.llmBaseUrl || !settings.llmModel || !settings.llmCredentialId) {
    throw new Error(
      "LLM SBOM recheck requires AppSettings.llmBaseUrl, llmModel, and llmCredentialId to be configured.",
    );
  }
  const credential = await decodeCredential(settings.llmCredentialId);
  if (credential.kind !== "llm_api_key") {
    throw new Error(
      `LLM SBOM recheck expects an llm_api_key credential; got ${credential.kind}.`,
    );
  }
  return {
    baseUrl: settings.llmBaseUrl,
    modelName: settings.llmModel,
    apiKey: credential.value,
  };
}

async function ensureTmpDir(scanRunId: string): Promise<{ tmpDir: string; claudeHome: string }> {
  const tmpDir = `/tmp/sastbot-sbomrecheck-${scanRunId}`;
  const claudeHome = path.join(tmpDir, "home");
  await fs.mkdir(tmpDir, { recursive: true, mode: 0o755 });
  await fs.mkdir(claudeHome, { recursive: true, mode: 0o755 });
  await fs.chown(claudeHome, CLAUDE_UID, CLAUDE_GID).catch(() => { /* non-fatal */ });
  return { tmpDir, claudeHome };
}

async function spawnClaudeAndCollectVerdicts(input: {
  scanRunId: string;
  scopeDir: string;
  systemPrompt: string;
  userPrompt: string;
  modelName: string;
  apiKey: string;
  baseUrl: string;
  claudeHome: string;
  effortLevel: string;
  onProgress?: (usage: TokenUsage) => void;
}): Promise<{ verdicts: SbomRecheckVerdict[]; mergeVerdicts: SbomMergeVerdict[]; parseErrors: ParseError[]; exitCode: number | null; usage: TokenUsage }> {
  const usage: TokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
    estimatedUsdCost: null,
    requestCount: 0,
  };

  const verdicts: SbomRecheckVerdict[] = [];
  const mergeVerdicts: SbomMergeVerdict[] = [];
  const parseErrors: ParseError[] = [];

  const args = [
    "-p", input.userPrompt,
    "--model", input.modelName,
    "--effort", input.effortLevel,
    "--allowed-tools", "Bash Read Glob Grep",
    "--permission-mode", "bypassPermissions",
    "--output-format", "stream-json",
    "--verbose",
    "--append-system-prompt", input.systemPrompt,
  ];

  const childEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ANTHROPIC_API_KEY: input.apiKey,
    ANTHROPIC_BASE_URL: input.baseUrl,
    HOME: input.claudeHome,
    USER: "claudeuser",
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
      // Robust JSON-object extraction — same logic as llmSastService.
      const { objects, rest } = extractJsonObjects(assistantTextBuf);
      assistantTextBuf = final ? "" : rest;
      for (const trimmed of objects) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(trimmed);
        } catch (err) {
          parseErrors.push({ raw: trimmed, reason: `JSON parse: ${(err as Error).message}` });
          continue;
        }
        const result = AnyVerdictSchema.safeParse(parsed);
        if (result.success) {
          if ("type" in result.data && result.data.type === "merge") {
            mergeVerdicts.push(result.data);
          } else if ("verdict" in result.data) {
            verdicts.push(result.data);
          }
        } else {
          parseErrors.push({
            raw: trimmed,
            reason: `schema: ${result.error.errors.map((e) => `${e.path.join(".")}: ${e.message}`).join("; ")}`,
          });
        }
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
            assistantTextBuf = appendBlockText(assistantTextBuf, block.text);
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
        } catch {
          // non-JSON stream line from the claude CLI wrapper — ignore
        }
      }
    });

    proc.stderr.setEncoding("utf8");
    proc.stderr.on("data", (chunk: string) => { stderrBuf += chunk; });

    proc.on("error", (err) => {
      logger.error({ err: err.message }, "[llmSbomRecheckService] claude spawn error");
      reject(err);
    });

    proc.on("close", (code) => {
      flushAssistantLines(true);
      if (stderrBuf.trim().length > 0) {
        logger.info({ stderr: stderrBuf.slice(0, 2000) }, "[llmSbomRecheckService] claude stderr");
      }
      resolve(code);
    });
  });

  return { verdicts, mergeVerdicts, parseErrors, exitCode, usage };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface RunSbomRecheckInput {
  scanRunId: string;
  scopeId: string;
  scopeDir: string;
  effortLevel: string;
  tokenBudget: number;
  orgId: string | null;
  onProgress?: (usage: TokenUsage) => void;
}

export interface MergeResult {
  keepId: string;
  dropIds: string[];
  rationale: string;
}

export interface RunSbomRecheckResult {
  /** IDs of scope_component rows recovered (present verdict). */
  recovered: string[];
  /** IDs of scope_component rows marked removed. */
  removed: string[];
  /** Merge verdicts applied — groups that were collapsed into a single row. */
  merged: MergeResult[];
  /** Total scope_component rows deleted due to merge verdicts. */
  mergedRowsRemoved: number;
  /** Number of candidates skipped by the hard cap. */
  capped: number;
  parseErrors: ParseError[];
  exitCode: number | null;
  durationMs: number;
  usage: TokenUsage;
}

/**
 * Runs the two-tier SBOM component recheck for a single scan run.
 *
 * Must be called AFTER `persistScanComponentsToScopeState` so the current
 * run's components are already reflected in `scan_run_components`.
 */
export async function runSbomRecheck(input: RunSbomRecheckInput): Promise<RunSbomRecheckResult> {
  const startedAt = Date.now();
  const emptyUsage: TokenUsage = {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
    estimatedUsdCost: null,
    requestCount: 0,
  };

  // ── 1. Build candidate set: active scope_components NOT seen this run ──────
  //
  // Exclude 'manual_override' rows from the candidate set — those are operator
  // decisions and must not be touched by the automated recheck.
  const candidates = await prisma.$queryRawUnsafe<Array<{
    id: string;
    name: string;
    version: string | null;
    purl: string;
    cpe: string | null;
    evidence_path: string | null;
    llm_evidence: unknown;
    last_seen_at: Date | null;
  }>>(
    `SELECT sc.id, sc.name, sc.version, sc.purl, sc.cpe, sc.evidence_path, sc.llm_evidence, sc.last_seen_at
     FROM scope_components sc
     WHERE sc.scope_id = $1::uuid
       AND sc.dismissed_status = 'active'
       AND sc.id NOT IN (
         SELECT src.scope_component_id
         FROM scan_run_components src
         WHERE src.scan_run_id = $2::uuid
       )
     ORDER BY sc.last_seen_at DESC NULLS LAST`,
    input.scopeId,
    input.scanRunId,
  );

  // ── 1b. Fetch ALL active scope_components for the dedup task ──────────────
  //
  // The LLM needs the full inventory picture to identify duplicates. We fetch
  // all active rows (excluding manual_override) regardless of whether they
  // appeared in this run's scan_run_components. This is a superset of the
  // candidates set above.
  const allActiveComponents = await prisma.$queryRawUnsafe<Array<{
    id: string;
    name: string;
    version: string | null;
    purl: string;
    cpe: string | null;
    evidence_path: string | null;
    llm_evidence: unknown;
  }>>(
    `SELECT sc.id, sc.name, sc.version, sc.purl, sc.cpe, sc.evidence_path, sc.llm_evidence
     FROM scope_components sc
     WHERE sc.scope_id = $1::uuid
       AND sc.dismissed_status != 'manual_override'
       AND sc.dismissed_status = 'active'
     ORDER BY sc.name ASC, sc.id ASC`,
    input.scopeId,
  );

  if (candidates.length === 0 && allActiveComponents.length <= 1) {
    logger.info(
      { scanRunId: input.scanRunId, scopeId: input.scopeId },
      "[llmSbomRecheckService] no candidates and ≤1 active component — phase is a no-op",
    );
    return {
      recovered: [],
      removed: [],
      merged: [],
      mergedRowsRemoved: 0,
      capped: 0,
      parseErrors: [],
      exitCode: 0,
      durationMs: Date.now() - startedAt,
      usage: emptyUsage,
    };
  }

  // Apply hard cap of 20 (most-recently-seen first, already ordered above).
  const cappedCount = Math.max(0, candidates.length - MAX_CANDIDATES);
  const workSet = candidates.slice(0, MAX_CANDIDATES);

  logger.info(
    { scanRunId: input.scanRunId, total: candidates.length, processing: workSet.length, capped: cappedCount },
    "[llmSbomRecheckService] candidate set built",
  );

  // ── 2. Tier-1: filesystem evidence check ──────────────────────────────────
  const tier1Removed: string[] = [];
  const tier2Candidates: typeof workSet = [];

  for (const c of workSet) {
    if (c.evidence_path) {
      const absPath = path.join(input.scopeDir, c.evidence_path);
      if (!existsSync(absPath)) {
        // File is gone — component is removed without needing LLM.
        tier1Removed.push(c.id);
        logger.info(
          { id: c.id, name: c.name, evidencePath: c.evidence_path },
          "[llmSbomRecheckService] Tier-1 removal: evidence file missing",
        );
        await prisma.$executeRawUnsafe(
          `UPDATE scope_components
           SET dismissed_status = 'removed',
               dismissed_reason = 'no_evidence',
               dismissed_at     = now(),
               updated_at       = now()
           WHERE id = $1::uuid`,
          c.id,
        );
        continue;
      }
    }
    // Either no evidence_path, or file is still present → Tier 2.
    tier2Candidates.push(c);
  }

  logger.info(
    { tier1Removed: tier1Removed.length, tier2: tier2Candidates.length },
    "[llmSbomRecheckService] Tier-1 done",
  );

  // Skip Tier 2 + dedup LLM call entirely if there are no candidates AND
  // only 0 or 1 active components (nothing to dedup).
  if (tier2Candidates.length === 0 && allActiveComponents.length <= 1) {
    return {
      recovered: [],
      removed: tier1Removed,
      merged: [],
      mergedRowsRemoved: 0,
      capped: cappedCount,
      parseErrors: [],
      exitCode: 0,
      durationMs: Date.now() - startedAt,
      usage: emptyUsage,
    };
  }

  // ── 3. Tier-2: LLM recheck + dedup ───────────────────────────────────────
  let { baseUrl, modelName, apiKey } = { baseUrl: "", modelName: "", apiKey: "" };
  try {
    ({ baseUrl, modelName, apiKey } = await resolveLlmConfig(input.orgId));
  } catch (err) {
    throw err; // Let worker's try/catch emit the error warning.
  }

  const { tmpDir, claudeHome } = await ensureTmpDir(input.scanRunId);

  try {
    // Write the candidate list as JSON-Lines (Task 1 input for the LLM).
    const candidatesPath = path.join(tmpDir, "sbom_recheck_candidates.jsonl");
    const candidateLines = tier2Candidates.map((c) => {
      let priorReason: string | null = null;
      if (c.llm_evidence && typeof c.llm_evidence === "object") {
        const ev = c.llm_evidence as Record<string, unknown>;
        if (typeof ev.llmReason === "string") priorReason = ev.llmReason;
      }
      return JSON.stringify({
        component_id: c.id,
        name: c.name,
        version: c.version ?? null,
        evidence_path: c.evidence_path ?? null,
        prior_reason: priorReason,
      });
    }).join("\n") + "\n";
    await fs.writeFile(candidatesPath, candidateLines, { encoding: "utf8", mode: 0o644 });

    // Write ALL active components as JSON-Lines (Task 2 input for the LLM).
    const allComponentsPath = path.join(tmpDir, "sbom_recheck_all_components.jsonl");
    const allComponentLines = allActiveComponents.map((c) => {
      let llmReason: string | null = null;
      if (c.llm_evidence && typeof c.llm_evidence === "object") {
        const ev = c.llm_evidence as Record<string, unknown>;
        if (typeof ev.llmReason === "string") llmReason = ev.llmReason;
      }
      return JSON.stringify({
        id: c.id,
        name: c.name,
        version: c.version ?? null,
        purl: c.purl,
        cpe: c.cpe ?? null,
        evidence_path: c.evidence_path ?? null,
        llm_reason: llmReason,
      });
    }).join("\n") + "\n";
    await fs.writeFile(allComponentsPath, allComponentLines, { encoding: "utf8", mode: 0o644 });

    const systemPrompt = loadPrompt("sbom_recheck_system", {});
    const userPrompt = loadPrompt("sbom_recheck", {
      SCOPE_PATH: input.scopeDir,
      TOKEN_BUDGET: String(input.tokenBudget),
      CANDIDATES_PATH: candidatesPath,
      ALL_COMPONENTS_PATH: allComponentsPath,
    });

    logger.info(
      {
        scanRunId: input.scanRunId,
        candidateCount: tier2Candidates.length,
        allComponentsCount: allActiveComponents.length,
        effortLevel: input.effortLevel,
        model: modelName,
      },
      "[llmSbomRecheckService] starting LLM recheck + dedup",
    );

    const { verdicts, mergeVerdicts, parseErrors, exitCode, usage } = await spawnClaudeAndCollectVerdicts({
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
    });

    logger.info(
      { verdicts: verdicts.length, mergeVerdicts: mergeVerdicts.length, parseErrors: parseErrors.length, exitCode, usage },
      "[llmSbomRecheckService] LLM recheck + dedup finished",
    );

    // ── 4. Apply presence/absence verdicts ────────────────────────────────
    const tier2Recovered: string[] = [];
    const tier2Removed: string[] = [];

    const candidateMap = new Map(tier2Candidates.map((c) => [c.id, c]));

    for (const v of verdicts) {
      if (!candidateMap.has(v.component_id)) {
        logger.warn(
          { componentId: v.component_id },
          "[llmSbomRecheckService] verdict for unknown component_id — ignoring",
        );
        continue;
      }

      if (v.verdict === "present") {
        // Advance lastSeenScanRunId / lastSeenAt; update evidencePath if provided.
        if (v.new_evidence_path) {
          await prisma.$executeRawUnsafe(
            `UPDATE scope_components
             SET last_seen_scan_run_id = $2::uuid,
                 last_seen_at          = now(),
                 evidence_path         = $3,
                 updated_at            = now()
             WHERE id = $1::uuid`,
            v.component_id,
            input.scanRunId,
            v.new_evidence_path,
          );
        } else {
          await prisma.$executeRawUnsafe(
            `UPDATE scope_components
             SET last_seen_scan_run_id = $2::uuid,
                 last_seen_at          = now(),
                 updated_at            = now()
             WHERE id = $1::uuid`,
            v.component_id,
            input.scanRunId,
          );
        }

        // Insert the join row with discoveryMethod = 'recheck_recovery'.
        await prisma.$executeRawUnsafe(
          `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
           VALUES ($1::uuid, $2::uuid, 'recheck_recovery')
           ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING`,
          input.scanRunId,
          v.component_id,
        );

        tier2Recovered.push(v.component_id);
      } else {
        // verdict === "removed"
        await prisma.$executeRawUnsafe(
          `UPDATE scope_components
           SET dismissed_status = 'removed',
               dismissed_reason = 'llm_confirmed_removed',
               dismissed_at     = now(),
               updated_at       = now()
           WHERE id = $1::uuid`,
          v.component_id,
        );

        tier2Removed.push(v.component_id);
      }
    }

    logger.info(
      { recovered: tier2Recovered.length, removed: tier2Removed.length, tier1Removed: tier1Removed.length },
      "[llmSbomRecheckService] presence/absence verdicts applied",
    );

    // ── 5. Apply merge verdicts ────────────────────────────────────────────
    const appliedMerges: MergeResult[] = [];
    let mergedRowsRemoved = 0;

    // Build a set of all active scope_component IDs for this scope (for validation).
    const activeComponentIdSet = new Set(allActiveComponents.map((c) => c.id));

    for (const mv of mergeVerdicts) {
      // Validate: keep_id must exist in active components.
      if (!activeComponentIdSet.has(mv.keep_id)) {
        logger.warn(
          { keepId: mv.keep_id, rationale: mv.rationale },
          "[llmSbomRecheckService] merge verdict keep_id not found in active components — skipping",
        );
        continue;
      }

      // Validate: all drop_ids must exist in active components.
      const invalidDropIds = mv.drop_ids.filter((id) => !activeComponentIdSet.has(id));
      if (invalidDropIds.length > 0) {
        logger.warn(
          { keepId: mv.keep_id, invalidDropIds, rationale: mv.rationale },
          "[llmSbomRecheckService] merge verdict has drop_ids not in active components — skipping entire group",
        );
        continue;
      }

      // Validate: keep_id must not be one of the drop_ids.
      if (mv.drop_ids.includes(mv.keep_id)) {
        logger.warn(
          { keepId: mv.keep_id, rationale: mv.rationale },
          "[llmSbomRecheckService] merge verdict keep_id appears in drop_ids — skipping",
        );
        continue;
      }

      // Re-confirm none of the IDs are manual_override rows in the DB
      // (the LLM was not sent those rows, but double-check for safety).
      const overrideCheck = await prisma.$queryRawUnsafe<Array<{ id: string }>>(
        `SELECT id FROM scope_components
         WHERE id = ANY($1::uuid[])
           AND dismissed_status = 'manual_override'`,
        `{${[mv.keep_id, ...mv.drop_ids].map((id) => id).join(",")}}`,
      );
      if (overrideCheck.length > 0) {
        logger.warn(
          { keepId: mv.keep_id, overrideIds: overrideCheck.map((r) => r.id), rationale: mv.rationale },
          "[llmSbomRecheckService] merge verdict touches manual_override rows — skipping",
        );
        continue;
      }

      // Apply the merge:
      // Step 1: Re-point scan_run_components from drop_ids to keep_id.
      //   Use INSERT ... ON CONFLICT DO NOTHING per the dedup migration pattern
      //   (avoids PK conflicts when multiple drop_ids map to the same scan_run).
      for (const dropId of mv.drop_ids) {
        await prisma.$executeRawUnsafe(
          `INSERT INTO scan_run_components (scan_run_id, scope_component_id, discovery_method)
           SELECT DISTINCT ON (src.scan_run_id, $2::uuid)
             src.scan_run_id,
             $2::uuid,
             src.discovery_method
           FROM scan_run_components src
           WHERE src.scope_component_id = $1::uuid
           ORDER BY src.scan_run_id, $2::uuid, src.discovery_method
           ON CONFLICT (scan_run_id, scope_component_id) DO NOTHING`,
          dropId,
          mv.keep_id,
        );
      }

      // Step 2: Delete leftover join rows pointing at drop_ids.
      await prisma.$executeRawUnsafe(
        `DELETE FROM scan_run_components
         WHERE scope_component_id = ANY($1::uuid[])`,
        `{${mv.drop_ids.join(",")}}`,
      );

      // Step 3: Delete the dropped scope_components rows.
      const deleted = await prisma.$executeRawUnsafe(
        `DELETE FROM scope_components
         WHERE id = ANY($1::uuid[])`,
        `{${mv.drop_ids.join(",")}}`,
      );

      mergedRowsRemoved += deleted;

      // Remove merged IDs from the active set so subsequent merge verdicts
      // from the same LLM call don't try to re-use them.
      for (const dropId of mv.drop_ids) {
        activeComponentIdSet.delete(dropId);
      }

      appliedMerges.push({ keepId: mv.keep_id, dropIds: mv.drop_ids, rationale: mv.rationale });

      logger.info(
        { keepId: mv.keep_id, dropIds: mv.drop_ids, rowsDeleted: deleted, rationale: mv.rationale },
        "[llmSbomRecheckService] merge verdict applied",
      );
    }

    logger.info(
      { mergeGroups: appliedMerges.length, mergedRowsRemoved },
      "[llmSbomRecheckService] merge verdicts applied",
    );

    return {
      recovered: tier2Recovered,
      removed: [...tier1Removed, ...tier2Removed],
      merged: appliedMerges,
      mergedRowsRemoved,
      capped: cappedCount,
      parseErrors,
      exitCode,
      durationMs: Date.now() - startedAt,
      usage,
    };
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
  }
}
