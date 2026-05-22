import { rm, stat } from "node:fs/promises";
import { join } from "node:path";

import { Worker } from "bullmq";
import { pino } from "pino";

import { loadConfig } from "./config.js";
import { prisma } from "./db.js";
import { closeRedis, getRedis } from "./queue/connection.js";
import { SCAN_QUEUE_NAME, type ScanJobData } from "./queue/scanQueue.js";
import { APP_VERSION } from "./routes/version.js";
import { cloneOrRefresh, RemoteUnreachableError } from "./services/repoCache.js";
import { GitCloneError } from "./services/gitClone.js";
import {
  extractCleanedComponents,
  runCdxgen,
} from "./services/sbomService.js";
import { queryAndPersistFindings, backfillCvssScores, backfillManifestOrigin } from "./services/osvService.js";
import { queryAndPersistNvdFindings } from "./services/nvdService.js";
import { checkAndPersistEolFindings } from "./services/eolService.js";
import { backfillReachability } from "./services/reachabilityService.js";
import { generateIssueSummary } from "./services/llmClient.js";
import { toRepoRelative } from "./services/scopePath.js";
import { buildSarifFromIssues } from "./services/sarifService.js";
import { buildAugmentationSbom, stableStringify } from "./services/sbomCurated.js";
import { ingestSbomFromArtifact } from "./services/sbomIngest.js";
import { sarifPathFor, sbomPathFor, writeArtifact } from "./services/artifactStore.js";
import {
  applyRecheckVerdicts,
  cleanupTmp as cleanupLlmTmp,
  persistDetection,
  type RecheckIssueInput,
  runDetection,
  runRecheck,
  type ScaHintInput,
} from "./services/llmSastService.js";
import { mergeDuplicateSastIssues } from "./services/sastDedup.js";
import {
  applySbomAugmentation,
  cleanupSbomTmp,
  runSbomAugmentation,
} from "./services/llmSbomService.js";
import { persistScanComponentsToScopeState, materializeRecoveredComponents } from "./services/scopeComponentService.js";
import { runSbomRecheck } from "./services/llmSbomRecheckService.js";
import type { ScanWarning } from "./schemas.js";
import { Prisma } from "@prisma/client";

const config = loadConfig();
const logger = pino({ level: config.logLevel, name: "sastbot-worker" });

// ---------------------------------------------------------------------------
// Parse-error truncation helper
// ---------------------------------------------------------------------------

/** Maximum byte length for a single `raw` string stored in warning details. */
export const PARSE_ERROR_RAW_MAX_BYTES = 2048;

/** Truncation suffix appended when a raw string exceeds the byte cap. */
const TRUNCATION_SUFFIX = "…[truncated]";

/**
 * Slice `parseErrors` to at most `limit` entries and cap each `raw` value to
 * `PARSE_ERROR_RAW_MAX_BYTES` bytes (UTF-8).  Returns a plain array of
 * `{raw, reason}` objects suitable for storage in a warning's `details` field.
 *
 * Exported so unit tests can exercise it without touching the DB.
 */
export function truncateParseErrors(
  parseErrors: ReadonlyArray<{ raw: string; reason: string }>,
  limit = 5,
): Array<{ raw: string; reason: string }> {
  return parseErrors.slice(0, limit).map((e) => {
    const enc = new TextEncoder().encode(e.raw);
    if (enc.byteLength <= PARSE_ERROR_RAW_MAX_BYTES) {
      return { raw: e.raw, reason: e.reason };
    }
    // Decode only the first PARSE_ERROR_RAW_MAX_BYTES bytes, then trim any
    // incomplete multi-byte sequence that TextDecoder might replace with U+FFFD.
    const truncBytes = enc.slice(0, PARSE_ERROR_RAW_MAX_BYTES);
    const truncText = new TextDecoder("utf-8", { fatal: false }).decode(truncBytes).replace(/�$/, "");
    return { raw: truncText + TRUNCATION_SUFFIX, reason: e.reason };
  });
}

// ---------------------------------------------------------------------------
// Warning helper
// ---------------------------------------------------------------------------

async function appendWarning(scanRunId: string, warning: ScanWarning): Promise<void> {
  // Read-modify-write: Prisma's JSONB doesn't support || concat natively, so we
  // fetch the current array and push the new entry.
  const run = await prisma.scanRun.findUnique({
    where: { id: scanRunId },
    select: { warnings: true },
  });
  const current = Array.isArray(run?.warnings) ? (run!.warnings as ScanWarning[]) : [];
  await prisma.scanRun.update({
    where: { id: scanRunId },
    data: { warnings: [...current, warning] as unknown as Prisma.InputJsonValue },
  });
}

/** Returns true iff any error-severity warning has been recorded on this
 *  scan. Gates remediation actions (SCA auto-fix sweep, etc.) so a scan
 *  with a degraded data path doesn't silently destroy real findings. */
async function hasErrorWarnings(scanRunId: string): Promise<boolean> {
  const run = await prisma.scanRun.findUnique({
    where: { id: scanRunId },
    select: { warnings: true },
  });
  const list = Array.isArray(run?.warnings) ? (run!.warnings as ScanWarning[]) : [];
  return list.some((w) => w.severity === "error");
}

// ---------------------------------------------------------------------------
// Phase tracking — surfaces live progress to the scope/scan detail pages.
// `phase` is one of the canonical labels; `progress` is the optional
// {done, total, label?} payload for within-phase counts. Both columns are
// null on terminal scans; the frontend only reads them while status is
// "running". Best-effort write — failure to update progress should never
// abort the scan.
// ---------------------------------------------------------------------------

type ScanPhase =
  | "cloning"
  | "cdxgen"
  | "llm_sbom"
  | "llm_sbom_recheck"
  | "sbom_emit"      // B1: write canonical CycloneDX artifact to disk
  | "sbom_ingest"    // B2: ingest SBOM from disk (no-op for cdxgen flow)
  | "osv"
  | "nvd"
  | "eol"
  | "llm_detection"
  | "llm_recheck"
  | "sarif_emit"     // B4: dual-write SARIF to disk + column
  | "sca_summaries"
  | "finalizing";

interface PhaseProgress {
  done: number;
  total: number;
  label?: string;
}

async function setPhase(
  scanRunId: string,
  phase: ScanPhase,
  progress: PhaseProgress | null = null,
): Promise<void> {
  await prisma.scanRun
    .update({
      where: { id: scanRunId },
      data: {
        currentPhase: phase,
        phaseProgress: progress
          ? (progress as unknown as Prisma.InputJsonValue)
          : Prisma.JsonNull,
      },
    })
    .catch(() => undefined);
}

// ---------------------------------------------------------------------------
// LLM token-budget defaults. Per-repo overrides are stored as nullable Int?
// columns; NULL means "use this default".
// ---------------------------------------------------------------------------

const DEFAULT_LLM_SBOM_TOKEN_BUDGET = 200_000;
const DEFAULT_LLM_SBOM_RECHECK_TOKEN_BUDGET = 50_000;
const DEFAULT_LLM_SAST_TOKEN_BUDGET = 300_000;
const DEFAULT_LLM_RECHECK_TOKEN_BUDGET = 50_000;

// ---------------------------------------------------------------------------
// LLM-mode SAST pipeline (M6 — runs when repo.sastEngine === "llm")
// ---------------------------------------------------------------------------

interface LlmSastPipelineInput {
  scanRunId: string;
  repo: {
    name: string;
    defaultBranch: string;
    ignorePaths: unknown;
    llmSastTokenBudget: number | null;
    llmRecheckTokenBudget: number | null;
    llmSastEffort: string;
    llmRecheckEffort: string;
    reachabilityEnabled: boolean;
    reachabilityIncludeDevDeps: boolean;
  };
  run: { scopeId: string; orgId: string | null };
  scanDir: string;
  /** Repo-rooted scope path ("/" or "/GoWeb" etc.). Threaded through to
   *  llmSastService so it can translate between LLM-emitted scope-relative
   *  paths and the repo-rooted form we persist. */
  scopePath: string;
  log: pino.Logger;
}

const LLM_SCA_HINT_CAP = 200;
const TERMINAL_TRIAGE_STATUSES = ["fixed", "suppressed", "false_positive"];
/** Hard cap on SBOM recheck candidates — keep in sync with llmSbomRecheckService MAX_CANDIDATES. */
const MAX_SBOM_RECHECK_CANDIDATES = 100;

async function runLlmSastPipeline(input: LlmSastPipelineInput): Promise<void> {
  const { scanRunId, repo, run, scanDir, scopePath, log } = input;

  try {
    // 1. Build the SCA hint list (top-N by severity then CVSS) from rows the
    //    cdxgen + OSV pipeline already wrote in steps 4–5. When reachability
    //    is disabled on the repo we skip this entirely — the model gets an
    //    empty hint file, Goal 2 of the prompt iterates zero times, and we
    //    save the output tokens that would have gone into 100+ verdicts.
    let scaHints: ScaHintInput[] = [];
    if (repo.reachabilityEnabled) {
      // Optionally exclude npm dev-only deps (cdxgen 12.2+ emits the
      // `cdx:npm:package:development=true` property when the lockfile entry
      // has `dev: true`; we mirror it onto SbomComponent.isDevOnly /
      // ScaIssue.latestIsDevOnly). Default true = include everything.
      // npm-only signal: non-npm components have isDevOnly=false and are
      // unaffected. Caveat: cdxgen issue #3927 — `devOptional: true` entries
      // miss the marker, so a small fraction of dev-only deps still slip in.
      const where: Prisma.ScaIssueWhereInput = {
        scopeId: run.scopeId,
        lastSeenScanRunId: scanRunId,
        latestFindingType: "cve",
        latestSeverity: { in: ["critical", "high"] },
      };
      if (!repo.reachabilityIncludeDevDeps) {
        where.latestIsDevOnly = false;
      }
      const scaIssues = await prisma.scaIssue.findMany({
        where,
        orderBy: [
          { latestSeverity: "asc" },
          { latestCvssScore: "desc" },
        ],
        take: LLM_SCA_HINT_CAP,
      });
      scaHints = scaIssues.map((i) => ({
        id: i.id,
        package: i.packageName,
        version: i.latestPackageVersion,
        cve_id: i.latestCveId,
        osv_id: i.osvId,
        cvss_score: i.latestCvssScore,
        summary: i.latestSummary,
      }));
      log.info(
        { count: scaHints.length, includeDevDeps: repo.reachabilityIncludeDevDeps },
        "[worker] built SCA hint set",
      );
    } else {
      log.info("[worker] reachability disabled on this repo — skipping SCA hint injection");
    }

    // 2. Detection pass.
    const sastTokenBudget = repo.llmSastTokenBudget ?? DEFAULT_LLM_SAST_TOKEN_BUDGET;
    log.info({ scaHintCount: scaHints.length, budget: sastTokenBudget, effort: repo.llmSastEffort }, "[worker] LLM detection start");
    await setPhase(scanRunId, "llm_detection", { done: 0, total: sastTokenBudget });
    // Throttle live progress writes to once every 2s — matches the
    // useScanDetail / useScopes refetch cadence so the UI sees an update on
    // every poll without burying the DB in updates during a long claude-p run.
    let lastProgressAt = 0;
    const detection = await runDetection({
      scanRunId,
      scopeId: run.scopeId,
      scopeDir: scanDir,
      repoName: repo.name,
      repoBranch: repo.defaultBranch,
      ignorePaths: Array.isArray(repo.ignorePaths) ? (repo.ignorePaths as string[]) : [],
      scaHints,
      tokenBudget: sastTokenBudget,
      effortLevel: repo.llmSastEffort,
      orgId: run.orgId,
      wallClockTimeoutMs: config.claudeDetectionTimeoutMs,
      stdoutStalenessMs: config.claudeStdoutStalenessMs,
      onProgress: (usage) => {
        const now = Date.now();
        if (now - lastProgressAt < 2000) return;
        lastProgressAt = now;
        void setPhase(scanRunId, "llm_detection", {
          done: usage.inputTokens + usage.outputTokens,
          total: sastTokenBudget,
        });
      },
    });
    log.info(
      {
        records: detection.records.length,
        parseErrors: detection.parseErrors.length,
        parseErrorSamples: detection.parseErrors.slice(0, 3).map((e) => ({
          reason: e.reason,
          raw: e.raw.slice(0, 300),
        })),
        durationMs: detection.durationMs,
        usage: detection.usage,
        exitCode: detection.exitCode,
        killedReason: detection.killedReason,
        wasRetry: detection.wasRetry,
      },
      "[worker] LLM detection finished",
    );

    // Emit a warning when a retry was performed so the operator can audit the
    // doubled token spend.  This is info-only (the scan is not untrustworthy
    // just because the first attempt crashed); the exit-code guard below will
    // escalate to error-severity if the retry also failed.
    if (detection.wasRetry) {
      await appendWarning(scanRunId, {
        code: "llm_sast_detection_retry",
        severity: "info",
        message: "LLM SAST detection attempt 1 exited non-zero with no records. A retry was performed automatically using the same prompts and full token budget. Note: both attempts consumed tokens — the operator may have been billed for both runs.",
      });
    }

    // Watchdog kills (timeout / staleness) are a stronger untrust signal than
    // a plain non-zero exit — the endpoint may still be hung.  Emit a
    // specific warning so the operator knows what happened.
    if (detection.killedReason !== null) {
      const reason = detection.killedReason === "timeout"
        ? `wall-clock cap (${config.claudeDetectionTimeoutMs / 1000}s)`
        : `stdout staleness threshold (${config.claudeStdoutStalenessMs / 1000}s without output)`;
      await appendWarning(scanRunId, {
        code: "llm_sast_detection_failed",
        severity: "error",
        message: `LLM SAST detection subprocess was killed by SASTBot after exceeding the ${reason}. Existing SAST/SCA findings were preserved — check the LLM endpoint health and re-run.`,
      });
    } else if (detection.parseErrors.length > 0) {
      await appendWarning(scanRunId, {
        code: "llm_sast_parse_errors",
        severity: "info",
        message: `LLM SAST detection emitted ${detection.parseErrors.length} unparseable record(s); some findings may be missing.`,
        details: truncateParseErrors(detection.parseErrors),
      });
    }

    // Untrust signal: detection subprocess didn't exit cleanly. exitCode === 0
    // with zero records is a legitimate "no findings" outcome (clean
    // codebase). exitCode !== 0 means claude-p crashed mid-run (or the retry
    // also failed), so any SAST/SCA remediation logic that gates on this scan
    // should be skipped.
    if (detection.exitCode !== 0 && detection.killedReason === null) {
      await appendWarning(scanRunId, {
        code: "llm_sast_detection_failed",
        severity: "error",
        message: `LLM SAST detection exited with code ${detection.exitCode} after ${(detection.durationMs / 1000).toFixed(0)}s${detection.wasRetry ? " (including retry)" : ""}. Existing SAST/SCA findings were preserved — re-run the scan once the LLM endpoint is healthy.`,
      });
    }

    // 3. Persist detection records.
    const persistResult = await persistDetection(prisma, {
      scanRunId,
      scopeId: run.scopeId,
      scopeDir: scanDir,
      scopePath,
      orgId: run.orgId,
      records: detection.records,
      modelName: "claude-code-cli",
    });
    log.info(persistResult, "[worker] LLM detection persisted");

    // 4. Stamp llm summary on every SastIssue from the detection records so
    //    the scope page shows the LLM's one-liner instead of just rule_id.
    //    SastIssue.latestFilePath is repo-rooted; translate the LLM's
    //    scope-relative path before matching.
    for (const r of detection.records) {
      if (r.kind === "sast" || r.kind === "sast_absence") {
        const scopeRelFile = r.kind === "sast" ? r.file_path : r.evidence_file;
        await prisma.sastIssue.updateMany({
          where: {
            scopeId: run.scopeId,
            lastSeenScanRunId: scanRunId,
            latestFilePath: toRepoRelative(scopePath, scopeRelFile),
            latestStartLine: r.kind === "sast" ? r.start_line : r.evidence_line,
          },
          data: { latestLlmSummary: r.summary, triageConfidence: r.confidence },
        });
      }
    }

    // 5. Recheck pass for any non-terminal SastIssue this detection didn't
    //    re-emit. Includes "error" rows so they self-heal once the file is
    //    actually gone (per locked decision #7).
    const candidates = await prisma.sastIssue.findMany({
      where: {
        scopeId: run.scopeId,
        lastSeenScanRunId: { not: scanRunId },
        triageStatus: { notIn: TERMINAL_TRIAGE_STATUSES },
      },
    });

    if (candidates.length > 0) {
      const recheckIssues: RecheckIssueInput[] = candidates.map((i) => ({
        id: i.id,
        file_path: i.latestFilePath,
        start_line: i.latestStartLine,
        summary: i.latestRuleMessage ?? i.latestRuleId,
        snippet: i.latestSnippet ?? "",
        cwe: i.latestCweIds[0] ?? "CWE-UNKNOWN",
      }));

      // Duplicate-target reference for the LLM: active issues in this scope
      // the candidate could be a relocated variant of. Includes issues the
      // current detection just re-emitted (lastSeenScanRunId === scanRunId)
      // and the recheck candidates themselves — the LLM can fold a
      // candidate into another candidate when both describe the same bug
      // at different files/lines. Terminal/operator-curated rows are
      // excluded — we don't want the LLM merging things into them.
      const targetRows = await prisma.sastIssue.findMany({
        where: {
          scopeId: run.scopeId,
          triageStatus: { in: ["pending", "error"] },
        },
        select: {
          id: true,
          latestFilePath: true,
          latestStartLine: true,
          latestCweIds: true,
          latestRuleMessage: true,
          latestLlmSummary: true,
        },
      });
      const duplicateTargets = targetRows.map((t) => ({
        id: t.id,
        file: t.latestFilePath,
        line: t.latestStartLine,
        cwe: t.latestCweIds[0] ?? "CWE-UNKNOWN",
        summary: t.latestLlmSummary ?? t.latestRuleMessage ?? "",
      }));
      const recheckBudget = repo.llmRecheckTokenBudget ?? DEFAULT_LLM_RECHECK_TOKEN_BUDGET;
      log.info({ count: recheckIssues.length, budget: recheckBudget, effort: repo.llmRecheckEffort }, "[worker] LLM recheck start");
      // Use tokens-against-budget for live progress: verdicts arrive batched
      // at the end of the claude-p run, so done=verdictCount only flips from
      // 0 to N right before the phase ends and the user sees no movement.
      // Token usage advances per LLM round-trip (~20 over a recheck run).
      await setPhase(scanRunId, "llm_recheck", { done: 0, total: recheckBudget });
      let lastRecheckProgressAt = 0;
      const recheck = await runRecheck({
        scanRunId,
        scopeDir: scanDir,
        scopePath,
        issues: recheckIssues,
        duplicateTargets,
        tokenBudget: recheckBudget,
        effortLevel: repo.llmRecheckEffort,
        orgId: run.orgId,
        wallClockTimeoutMs: config.claudeRecheckTimeoutMs,
        stdoutStalenessMs: config.claudeStdoutStalenessMs,
        onProgress: (usage) => {
          const now = Date.now();
          if (now - lastRecheckProgressAt < 2000) return;
          lastRecheckProgressAt = now;
          void setPhase(scanRunId, "llm_recheck", {
            done: usage.inputTokens + usage.outputTokens,
            total: recheckBudget,
          });
        },
      });
      log.info(
        {
          verdicts: recheck.verdicts.length,
          parseErrors: recheck.parseErrors.length,
          parseErrorSamples: recheck.parseErrors.slice(0, 3).map((e) => ({
            reason: e.reason,
            raw: e.raw.slice(0, 300),
          })),
          durationMs: recheck.durationMs,
          usage: recheck.usage,
          killedReason: recheck.killedReason,
          wasRetry: recheck.wasRetry,
        },
        "[worker] LLM recheck finished",
      );
      const apply = await applyRecheckVerdicts(prisma, {
        scanRunId,
        scopeId: run.scopeId,
        scopeDir: scanDir,
        scopePath,
        inputIssues: recheckIssues,
        verdicts: recheck.verdicts,
      });
      log.info(apply, "[worker] LLM recheck applied");

      if (recheck.wasRetry) {
        await appendWarning(scanRunId, {
          code: "llm_recheck_retry",
          severity: "info",
          message: "LLM SAST recheck attempt 1 exited non-zero with no verdicts. A retry was performed automatically using the same prompts and full token budget. Note: both attempts consumed tokens — the operator may have been billed for both runs.",
        });
      }

      if (recheck.killedReason !== null) {
        const reason = recheck.killedReason === "timeout"
          ? `wall-clock cap (${config.claudeRecheckTimeoutMs / 1000}s)`
          : `stdout staleness threshold (${config.claudeStdoutStalenessMs / 1000}s without output)`;
        await appendWarning(scanRunId, {
          code: "llm_recheck_failed",
          severity: "error",
          message: `LLM SAST recheck subprocess was killed by SASTBot after exceeding the ${reason}. Existing recheck results are incomplete — re-run the scan once the LLM endpoint is healthy.`,
        });
      } else if (recheck.parseErrors.length > 0) {
        await appendWarning(scanRunId, {
          code: "llm_recheck_parse_errors",
          severity: "info",
          message: `LLM recheck emitted ${recheck.parseErrors.length} unparseable record(s).`,
          details: truncateParseErrors(recheck.parseErrors),
        });
      }

      // Add recheck token usage on top of detection's.
      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: {
          llmInputTokens: { increment: recheck.usage.inputTokens },
          llmOutputTokens: { increment: recheck.usage.outputTokens },
          llmRequestCount: { increment: recheck.usage.requestCount },
        },
      });
    }

    // 6. Stamp detection token usage onto the scan run.
    await prisma.scanRun.update({
      where: { id: scanRunId },
      data: {
        llmInputTokens: { increment: detection.usage.inputTokens },
        llmOutputTokens: { increment: detection.usage.outputTokens },
        llmRequestCount: { increment: detection.usage.requestCount },
      },
    });

    // 6b. Collapse same-scope SAST duplicates produced by LLM drift across
    //     scans (different start_line / CWE for one weakness). Gated on
    //     scan trustworthiness — same rule as the SCA auto-fix sweep —
    //     so a degraded scan can't delete real findings.
    if (!(await hasErrorWarnings(scanRunId))) {
      const dedup = await mergeDuplicateSastIssues(prisma, run.scopeId, scanRunId);
      if (dedup.mergedCount > 0) {
        log.info(dedup, "[worker] SAST duplicate merge");
        await appendWarning(scanRunId, {
          code: "sast_duplicates_merged",
          severity: "info",
          message: `Merged ${dedup.mergedCount} duplicate SAST issue(s) into ${dedup.survivorCount} survivor(s).`,
        });
      }
    }

    // 7. Update sastFindingCount denorm.
    const sastCount = await prisma.sastIssue.count({
      where: { scopeId: run.scopeId, lastSeenScanRunId: scanRunId },
    });
    await prisma.scanRun.update({
      where: { id: scanRunId },
      data: { sastFindingCount: sastCount },
    });

    // 8. Generate the SARIF export from the issues observed in this run so
    //    operators can hand the standard JSON to dashboards / CI gates /
    //    compliance evidence collection. Cheap; idempotent.
    // B4: set sarif_emit phase so the UI sees a live progress tick.
    await setPhase(scanRunId, "sarif_emit");
    await regenerateSastSarifForScan(scanRunId, run.scopeId, scopePath);
  } finally {
    await cleanupLlmTmp(scanRunId);
  }
}

async function regenerateSastSarifForScan(
  scanRunId: string,
  scopeId: string,
  scopePath: string,
): Promise<void> {
  const issues = await prisma.sastIssue.findMany({
    where: { scopeId, lastSeenScanRunId: scanRunId },
  });
  const run = await prisma.scanRun.findUnique({
    where: { id: scanRunId },
    select: { startedAt: true, finishedAt: true },
  });
  const sarif = buildSarifFromIssues(issues, {
    toolVersion: APP_VERSION,
    modelName: "claude-code-cli",
    scopePath,
    startedAt: run?.startedAt ?? null,
    endedAt: run?.finishedAt ?? null,
  });

  // Write to the artifact file — the only storage path for SARIF since Deploy 3.
  const sarifBody = JSON.stringify(sarif, null, 2);
  try {
    await writeArtifact(sarifPathFor(scanRunId), sarifBody);
  } catch (err) {
    logger.error({ err: (err as Error).message, scanRunId }, "[worker] sarif_emit: disk write failed");
    await appendWarning(scanRunId, {
      code: "sarif_emit_failed",
      severity: "error",
      message: `Failed to write SARIF artifact: ${(err as Error).message}.`,
    });
  }
}

// ---------------------------------------------------------------------------
// Sibling-scope exclusions
//
// When a repo has overlapping scan paths (e.g. "/" and "/GoWeb"), the
// broader scope should not double-scan the deeper sibling. This helper
// returns the list of subdirs to exclude from `currentPath`'s scan,
// expressed relative to that scope's working dir.
//
// Examples:
//   currentPath="/", all=["/", "/GoWeb"]            → ["GoWeb"]
//   currentPath="/", all=["/", "/a", "/a/b"]        → ["a", "a/b"]
//   currentPath="/a", all=["/", "/a", "/a/b"]       → ["b"]
//   currentPath="/a/b", all=["/", "/a", "/a/b"]     → []
// ---------------------------------------------------------------------------

function computeScopeExclusions(currentPath: string, allPaths: string[]): string[] {
  const norm = (p: string) => p.replace(/^\/+/, "").replace(/\/+$/, "");
  const cur = norm(currentPath);
  const curPrefix = cur === "" ? "" : cur + "/";
  return allPaths
    .map(norm)
    .filter((s) => s !== cur && (curPrefix === "" ? s !== "" : s.startsWith(curPrefix)))
    .map((s) => (curPrefix === "" ? s : s.slice(curPrefix.length)));
}

// ---------------------------------------------------------------------------
// Backfill LLM summaries for existing issues that lack them
// ---------------------------------------------------------------------------

async function backfillLlmSummaries(): Promise<void> {
  const [sastCount, scaCount] = await Promise.all([
    prisma.sastIssue.count({ where: { latestLlmSummary: null } }),
    prisma.scaIssue.count({ where: { latestLlmSummary: null } }),
  ]);

  if (sastCount === 0 && scaCount === 0) return;

  logger.info({ sastCount, scaCount }, "[worker] backfilling LLM summaries");

  const BATCH = 50;

  // SAST backfill — use `notIn: attempted` so rows that fail aren't retried
  // in an infinite loop, and successes drop out naturally via the null filter.
  const attemptedSast = new Set<string>();
  while (true) {
    const issues = await prisma.sastIssue.findMany({
      where: { latestLlmSummary: null, id: { notIn: [...attemptedSast] } },
      select: { id: true, latestRuleId: true, latestRuleName: true, latestRuleMessage: true, latestFilePath: true, latestSnippet: true, orgId: true },
      take: BATCH,
    });
    if (issues.length === 0) break;
    for (const issue of issues) {
      attemptedSast.add(issue.id);
      const summary = await generateIssueSummary("sast", {
        ruleId: issue.latestRuleId,
        ruleName: issue.latestRuleName,
        ruleMessage: issue.latestRuleMessage,
        filePath: issue.latestFilePath,
        snippet: issue.latestSnippet,
        orgId: issue.orgId,
      });
      if (summary) {
        await prisma.sastIssue.update({ where: { id: issue.id }, data: { latestLlmSummary: summary } });
      } else {
        logger.warn({ issueId: issue.id, ruleId: issue.latestRuleId }, "[worker] SAST summary returned null");
      }
    }
  }

  // SCA backfill — same pattern
  const attemptedSca = new Set<string>();
  while (true) {
    const issues = await prisma.scaIssue.findMany({
      where: { latestLlmSummary: null, id: { notIn: [...attemptedSca] } },
      select: { id: true, packageName: true, latestPackageVersion: true, osvId: true, latestCveId: true, latestCvssScore: true, latestSummary: true, orgId: true },
      take: BATCH,
    });
    if (issues.length === 0) break;
    for (const issue of issues) {
      attemptedSca.add(issue.id);
      const summary = await generateIssueSummary("sca", {
        packageName: issue.packageName,
        version: issue.latestPackageVersion,
        osvId: issue.osvId,
        cveId: issue.latestCveId,
        cvssScore: issue.latestCvssScore,
        osvSummary: issue.latestSummary,
        orgId: issue.orgId,
      });
      if (summary) {
        await prisma.scaIssue.update({ where: { id: issue.id }, data: { latestLlmSummary: summary } });
      } else {
        logger.warn({ issueId: issue.id, osvId: issue.osvId }, "[worker] SCA summary returned null");
      }
    }
  }

  logger.info(
    { sastAttempted: attemptedSast.size, scaAttempted: attemptedSca.size },
    "[worker] LLM summary backfill complete",
  );
}

// ---------------------------------------------------------------------------
// One-shot: prepend scope.path to file paths persisted scope-relative under
// the previous (buggy) behavior. Idempotent — only prepends when the stored
// path doesn't already start with the scope's slug.
// ---------------------------------------------------------------------------
async function backfillRepoRelativePaths(): Promise<void> {
  const scopes = await prisma.scanScope.findMany({
    select: { id: true, path: true },
    where: { path: { not: "/" } },
  });
  if (scopes.length === 0) return;

  let sastUpdated = 0, scaManifestUpdated = 0, scaCallSitesUpdated = 0, sbomUpdated = 0;

  for (const scope of scopes) {
    const slug = scope.path.replace(/^\/+/, "").replace(/\/+$/, "");
    if (!slug) continue;
    const prefix = `${slug}/`;

    // SastIssue.latestFilePath
    const sast = await prisma.sastIssue.findMany({
      where: { scopeId: scope.id, NOT: { latestFilePath: { startsWith: prefix } } },
      select: { id: true, latestFilePath: true },
    });
    for (const i of sast) {
      // Skip rows whose path is already absolute or the synthetic absence marker.
      if (!i.latestFilePath || i.latestFilePath.startsWith("__absence__") || i.latestFilePath.startsWith("/")) continue;
      await prisma.sastIssue.update({
        where: { id: i.id },
        data: { latestFilePath: `${prefix}${i.latestFilePath}` },
      });
      sastUpdated++;
    }

    // ScaIssue.latestManifestFile
    const sca = await prisma.scaIssue.findMany({
      where: {
        scopeId: scope.id,
        latestManifestFile: { not: null },
        NOT: { latestManifestFile: { startsWith: prefix } },
      },
      select: { id: true, latestManifestFile: true, reachableCallSites: true },
    });
    for (const i of sca) {
      const data: Prisma.ScaIssueUpdateInput = {};
      if (i.latestManifestFile && !i.latestManifestFile.startsWith("/")) {
        data.latestManifestFile = `${prefix}${i.latestManifestFile}`;
        scaManifestUpdated++;
      }
      // reachable_call_sites[].file — JSONB array, translate elements that need it
      if (Array.isArray(i.reachableCallSites)) {
        const sites = i.reachableCallSites as unknown as Array<{ file?: string; line?: number; snippet?: string }>;
        let touched = false;
        const next = sites.map((s) => {
          if (s.file && !s.file.startsWith(prefix) && !s.file.startsWith("/")) {
            touched = true;
            return { ...s, file: `${prefix}${s.file}` };
          }
          return s;
        });
        if (touched) {
          data.reachableCallSites = next as unknown as Prisma.InputJsonValue;
          scaCallSitesUpdated++;
        }
      }
      if (Object.keys(data).length > 0) {
        await prisma.scaIssue.update({ where: { id: i.id }, data });
      }
    }

    // SbomComponent.manifestFile (joined via scan_runs.scope_id)
    const sbom = await prisma.sbomComponent.findMany({
      where: {
        manifestFile: { not: null },
        NOT: { manifestFile: { startsWith: prefix } },
        scanRun: { scopeId: scope.id },
      },
      select: { id: true, manifestFile: true },
    });
    for (const c of sbom) {
      if (!c.manifestFile || c.manifestFile.startsWith("/")) continue;
      await prisma.sbomComponent.update({
        where: { id: c.id },
        data: { manifestFile: `${prefix}${c.manifestFile}` },
      });
      sbomUpdated++;
    }
  }

  if (sastUpdated || scaManifestUpdated || scaCallSitesUpdated || sbomUpdated) {
    logger.info(
      { sastUpdated, scaManifestUpdated, scaCallSitesUpdated, sbomUpdated },
      "[worker] backfilled repo-rooted file paths for non-root scopes",
    );
  }
}

// Recomputes scan_runs.{critical,high,medium,low}_count from the actual
// SCA findings + SAST issues observed in each run. Until this commit the
// counts only reflected SCA, so historical rows show partial totals on the
// scans list. Idempotent — same input → same output.
//
// Each table is aggregated separately first; joining `scan_findings` to
// `sast_issues` directly produces a Cartesian product per scan_run and
// inflates the totals by the multiplied row count.
async function backfillScanRunSeverities(): Promise<void> {
  const updated = await prisma.$executeRawUnsafe(`
    WITH sca_counts AS (
      SELECT scan_run_id,
        COUNT(*) FILTER (WHERE severity = 'critical') AS critical,
        COUNT(*) FILTER (WHERE severity = 'high') AS high,
        COUNT(*) FILTER (WHERE severity = 'medium') AS medium,
        COUNT(*) FILTER (WHERE severity = 'low') AS low
      FROM scan_findings
      GROUP BY scan_run_id
    ),
    sast_counts AS (
      SELECT last_seen_scan_run_id AS scan_run_id,
        COUNT(*) FILTER (WHERE latest_severity = 'critical') AS critical,
        COUNT(*) FILTER (WHERE latest_severity = 'high') AS high,
        COUNT(*) FILTER (WHERE latest_severity = 'medium') AS medium,
        COUNT(*) FILTER (WHERE latest_severity = 'low') AS low
      FROM sast_issues
      GROUP BY last_seen_scan_run_id
    ),
    totals AS (
      SELECT sr.id AS scan_run_id,
        COALESCE(sca.critical, 0) + COALESCE(sast.critical, 0) AS critical,
        COALESCE(sca.high, 0) + COALESCE(sast.high, 0) AS high,
        COALESCE(sca.medium, 0) + COALESCE(sast.medium, 0) AS medium,
        COALESCE(sca.low, 0) + COALESCE(sast.low, 0) AS low
      FROM scan_runs sr
      LEFT JOIN sca_counts sca ON sca.scan_run_id = sr.id
      LEFT JOIN sast_counts sast ON sast.scan_run_id = sr.id
      WHERE sr.status = 'success'
    )
    UPDATE scan_runs sr
    SET critical_count = t.critical,
        high_count = t.high,
        medium_count = t.medium,
        low_count = t.low
    FROM totals t
    WHERE sr.id = t.scan_run_id
      AND (sr.critical_count, sr.high_count, sr.medium_count, sr.low_count)
        IS DISTINCT FROM (t.critical, t.high, t.medium, t.low)
  `);
  if (updated > 0) {
    logger.info({ rowsUpdated: updated }, "[worker] backfilled scan_runs severity counts (SCA + SAST combined)");
  }
}

backfillLlmSummaries().catch((err) => {
  logger.warn({ err }, "[worker] backfill failed — will retry on next scan");
});

backfillScanRunSeverities().catch((err) => {
  logger.warn({ err }, "[worker] scan-run severity backfill failed");
});

// Strip leaked `clones/<UUID>/` (and `../clones/<UUID>/`) prefixes from
// historical manifest paths. cdxgen 12.x emits paths in several shapes that
// the original prefix-strip didn't handle, leaving the repo's clone GUID
// embedded in the stored path. The "Declared in" link then renders a broken
// URL with the GUID in it. Idempotent — paths already correct don't match.
async function backfillManifestPathPrefixes(): Promise<void> {
  const pattern =
    "^.*?clones/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/";
  const sbomUpdated = await prisma.$executeRawUnsafe(
    `UPDATE sbom_components
     SET manifest_file = regexp_replace(manifest_file, $1, '')
     WHERE manifest_file ~ $1`,
    pattern,
  );
  const scaUpdated = await prisma.$executeRawUnsafe(
    `UPDATE sca_issues
     SET latest_manifest_file = regexp_replace(latest_manifest_file, $1, '')
     WHERE latest_manifest_file ~ $1`,
    pattern,
  );
  if (sbomUpdated > 0 || scaUpdated > 0) {
    logger.info(
      { sbomUpdated, scaUpdated },
      "[worker] backfilled manifest paths (stripped leaked clone-root prefix)",
    );
  }
}

backfillManifestPathPrefixes().catch((err) => {
  logger.warn({ err }, "[worker] manifest-path-prefix backfill failed");
});

// M6k: re-extract SAST snippets from disk so they all conform to the
// canonical 3-lines-before / problem / 3-lines-after layout. Old snippets
// were the raw LLM output and varied wildly in length, forcing the
// frontend to use a keyword-search heuristic to find the match. Refreshes
// every issue whose scope's repo is retained on disk; absence-style rows
// (snippet starts with `__absence__:`) are skipped — they have no real
// code site.
async function backfillSastSnippets(): Promise<void> {
  const { repoCachePath } = await import("./services/repoCache.js");
  const { stat } = await import("node:fs/promises");
  const { readSourceSnippet } = await import("./services/sourceSnippet.js");

  const scopes = await prisma.scanScope.findMany({
    where: { repo: { retainClone: true } },
    select: { id: true, repoId: true, path: true },
  });
  let refreshed = 0;
  for (const scope of scopes) {
    const cacheDir = repoCachePath(scope.repoId);
    try { await stat(cacheDir); } catch { continue; }
    const scopeDir = scope.path === "/" || scope.path === "" ? cacheDir : join(cacheDir, scope.path);
    const issues = await prisma.sastIssue.findMany({
      where: { scopeId: scope.id },
      select: { id: true, latestFilePath: true, latestStartLine: true, latestEndLine: true, latestSnippet: true },
    });
    for (const i of issues) {
      if (i.latestSnippet?.startsWith("__absence__:")) continue;
      // latestFilePath is repo-rooted; readSourceSnippet expects scope-relative.
      const scopeRel = scope.path === "/" || scope.path === ""
        ? i.latestFilePath
        : i.latestFilePath.replace(new RegExp(`^${scope.path.replace(/^\//, "").replace(/\/$/, "")}/`), "");
      const fresh = await readSourceSnippet(
        scopeDir,
        scopeRel,
        i.latestStartLine,
        i.latestEndLine ?? undefined,
      );
      if (!fresh) continue;
      if (fresh.text === i.latestSnippet) continue;
      await prisma.sastIssue.update({
        where: { id: i.id },
        data: { latestSnippet: fresh.text },
      });
      refreshed++;
    }
  }
  if (refreshed > 0) {
    logger.info({ refreshed }, "[worker] backfilled SAST snippets from disk");
  }
}

backfillSastSnippets().catch((err) => {
  logger.warn({ err }, "[worker] sast-snippet backfill failed");
});

backfillRepoRelativePaths().catch((err) => {
  logger.warn({ err }, "[worker] repo-rooted path backfill failed");
});

backfillCvssScores(prisma).catch((err) => {
  logger.warn({ err }, "[worker] CVSS score backfill failed");
});

backfillReachability(prisma).catch((err) => {
  logger.warn({ err }, "[worker] reachability backfill failed");
});

// M6n: suppress dev-only SCA issues for repos that have opted out of dev deps.
// Idempotent — filters on dismissedStatus not already terminal. Safe to re-run.
async function backfillDevOnlyScaIssues(): Promise<void> {
  const repos = await prisma.repo.findMany({
    where: { reachabilityIncludeDevDeps: false },
    select: { id: true, scopes: { select: { id: true } } },
  });
  if (repos.length === 0) return;

  const scopeIds = repos.flatMap((r) => r.scopes.map((s) => s.id));
  if (scopeIds.length === 0) return;

  const TERMINAL = ["fixed", "suppressed", "false_positive"];
  const { count } = await prisma.scaIssue.updateMany({
    where: {
      scopeId: { in: scopeIds },
      latestIsDevOnly: true,
      dismissedStatus: { notIn: TERMINAL },
    },
    data: {
      dismissedStatus: "suppressed",
      dismissedReason: "dev_tree_policy",
    },
  });
  logger.info(
    { reposChecked: repos.length, scopesChecked: scopeIds.length, rowsUpdated: count },
    "[worker] backfillDevOnlyScaIssues complete",
  );
}

backfillDevOnlyScaIssues().catch((err) => {
  logger.warn({ err }, "[worker] dev-only SCA backfill failed");
});

// Repair SCA-issue manifest origins (file + line + snippet) from sbom_components.
backfillManifestOrigin(prisma).catch((err) => {
  logger.warn({ err }, "[worker] manifest-origin backfill failed");
});

// Split evidence/usage refactor: fill in line + snippet on scope_components
// rows whose evidence was written as path-only by the split-evidence-usage
// migration. Reads the lockfile from the retained repo cache and uses
// readManifestSnippet to find the line where the package is declared.
// Skips manual_override rows (operators own those) and rows whose evidence
// already carries a line. Idempotent.
async function backfillScopeComponentEvidenceSnippets(): Promise<void> {
  const { repoCachePath } = await import("./services/repoCache.js");
  const { stat } = await import("node:fs/promises");
  const { readManifestSnippet } = await import("./services/manifestSnippet.js");

  const scopes = await prisma.scanScope.findMany({
    where: { repo: { retainClone: true } },
    select: { id: true, repoId: true, path: true },
  });
  let refreshed = 0;
  for (const scope of scopes) {
    const cacheDir = repoCachePath(scope.repoId);
    try { await stat(cacheDir); } catch { continue; }
    const scopeDir = scope.path === "/" || scope.path === "" ? cacheDir : join(cacheDir, scope.path);

    // Pull rows whose evidence is a non-empty array with no line yet, and
    // whose manifest_file is set (i.e. manifest-tracked packages where we
    // can resolve a lockfile line). `manual_override` rows are operator-
    // curated — skip them so we don't trample an explicit edit.
    const rows = await prisma.$queryRawUnsafe<Array<{
      id: string;
      name: string;
      manifest_file: string | null;
      evidence: unknown;
    }>>(
      `SELECT id, name, manifest_file, evidence
       FROM scope_components
       WHERE scope_id = $1::uuid
         AND source <> 'manual_override'
         AND manifest_file IS NOT NULL
         AND jsonb_typeof(evidence) = 'array'
         AND jsonb_array_length(evidence) > 0
         AND NOT EXISTS (
           SELECT 1 FROM jsonb_array_elements(evidence) AS e
           WHERE (e->>'line') IS NOT NULL
              OR ((e->>'snippet') IS NOT NULL AND length(e->>'snippet') > 0)
         )`,
      scope.id,
    );

    for (const row of rows) {
      if (!row.manifest_file) continue;
      // manifest_file is repo-rooted; readManifestSnippet wants scope-relative.
      const prefix = scope.path === "/" || scope.path === "" ? "" : scope.path.replace(/^\//, "").replace(/\/$/, "") + "/";
      const scopeRel = prefix && row.manifest_file.startsWith(prefix)
        ? row.manifest_file.slice(prefix.length)
        : row.manifest_file;
      const ms = await readManifestSnippet(scopeDir, scopeRel, row.name);
      if (ms.line == null && ms.snippet == null) continue;
      const enriched = [{
        path: row.manifest_file,
        ...(ms.line != null ? { line: ms.line } : {}),
        ...(ms.snippet != null ? { snippet: ms.snippet } : {}),
      }];
      await prisma.$executeRawUnsafe(
        `UPDATE scope_components SET evidence = $1::jsonb, updated_at = now() WHERE id = $2::uuid`,
        JSON.stringify(enriched),
        row.id,
      );
      refreshed++;
    }
  }
  if (refreshed > 0) {
    logger.info({ refreshed }, "[worker] backfilled scope_components evidence (line + snippet)");
  }
}

backfillScopeComponentEvidenceSnippets().catch((err) => {
  logger.warn({ err }, "[worker] scope-component evidence snippet backfill failed");
});

const worker = new Worker<ScanJobData>(
  SCAN_QUEUE_NAME,
  async (job) => {
    const { scanRunId, scopePath = "/" } = job.data;
    const log = logger.child({ scanRunId });

    const run = await prisma.scanRun.findUnique({
      where: { id: scanRunId },
      include: { repo: true },
    });
    if (!run || !run.repo) {
      log.warn("[worker] scan run or repo missing — nothing to do");
      return;
    }
    // Honor cancel requests that landed while the job was queued.
    if (run.status === "cancelled") {
      log.info("[worker] scan run was cancelled before start — skipping");
      return;
    }
    const { repo } = run;

    await prisma.scanRun.update({
      where: { id: scanRunId },
      data: {
        status: "running",
        startedAt: new Date(),
        // On BullMQ retry, the prior attempt may have left error / warnings /
        // finishedAt populated. Clear them so the new attempt starts clean —
        // otherwise the UI shows stale failure messages on a now-running
        // scan, the elapsed-time calculation produces 0/negative seconds
        // (when finishedAt < startedAt), and stale error-severity warnings
        // would falsely mark the eventually-completed scan untrustworthy.
        finishedAt: null,
        error: null,
        warnings: [],
      },
    });

    // Retry-idempotency: BullMQ retries the same scan_run_id on worker
    // crash / restart (stalled-job recovery). Per-scan rows from the killed
    // attempt would otherwise pollute this attempt — sbom_components from
    // the prior augmentation get loaded into the retry's in-memory list
    // alongside its own augmentation output, producing duplicate OSV / NVD
    // queries and inflated finding counts. Scan_run_components and
    // scan_findings have the same exposure. Clean them now; first-attempt
    // counts are zero, so this is a safe no-op on fresh scans.
    const [staleComponents, staleJoins, staleFindings] = await prisma.$transaction([
      prisma.sbomComponent.deleteMany({ where: { scanRunId } }),
      prisma.scanRunComponent.deleteMany({ where: { scanRunId } }),
      prisma.scanFinding.deleteMany({ where: { scanRunId } }),
    ]);
    if (staleComponents.count > 0 || staleJoins.count > 0 || staleFindings.count > 0) {
      log.warn(
        {
          sbomComponents: staleComponents.count,
          scanRunComponents: staleJoins.count,
          scanFindings: staleFindings.count,
        },
        "[worker] cleared stale per-scan rows from prior attempt (BullMQ retry)",
      );
    }

    let clone: Awaited<ReturnType<typeof cloneOrRefresh>> | null = null;
    try {
      // ── Step 1: clone / refresh ─────────────────────────────────────────
      log.info({ url: repo.url, retainClone: repo.retainClone }, "[worker] cloning repo");
      await setPhase(scanRunId, "cloning");
      clone = await cloneOrRefresh({
        repoId: repo.id,
        url: repo.url,
        defaultBranch: repo.defaultBranch,
        credentialId: repo.credentialId,
        retainClone: repo.retainClone,
      });
      log.info(
        { workingDir: clone.workingDir, fromCache: clone.fromCache },
        "[worker] clone ready",
      );

      // ── Step 2: cdxgen → CycloneDX 1.7 SBOM ────────────────────────────
      // scanDir is the scope sub-path within the clone (e.g. "services/api").
      // For the root scope ("/") we scan the full clone.
      const scanDir =
        scopePath === "/" || scopePath === ""
          ? clone.workingDir
          : join(clone.workingDir, scopePath);

      // Pre-flight: scope path must exist in the clone. Otherwise the
      // failure surfaces deep inside cdxgen as a confusing "spawn ENOENT"
      // (Node's spawn returns ENOENT on a missing `cwd` and reports it as
      // if the executable were missing). Emit a clear typed warning and
      // abort the scan so the operator knows what to fix.
      try {
        const s = await stat(scanDir);
        if (!s.isDirectory()) {
          throw new Error(`scope path "${scopePath}" exists but is not a directory`);
        }
      } catch (statErr) {
        const reason = statErr instanceof Error
          ? (statErr as { code?: string }).code === "ENOENT"
            ? `Scope path "${scopePath}" does not exist in the cloned repository. Edit the repo in Admin → Repos and set Scan paths to a directory that actually exists at the repo root (e.g. "/").`
            : statErr.message
          : "scope path stat failed";
        await appendWarning(scanRunId, {
          code: "scope_path_missing",
          severity: "error",
          message: reason,
        });
        throw new Error(reason);
      }

      // When the same repo defines nested scopes (e.g. "/" and "/GoWeb"),
      // the broader scope excludes the deeper sibling so files aren't
      // double-counted. We also strip excluded subtrees from opengrep.
      // Per-repo ignore_paths are concatenated with sibling scopes — both
      // are "things to skip from this scope's tree", so the same logic
      // handles them. An ignore path that isn't under this scope is
      // filtered out by computeScopeExclusions.
      const allScanPaths = (Array.isArray(repo.scanPaths) ? repo.scanPaths : ["/"]) as string[];
      const ignorePaths = (Array.isArray(repo.ignorePaths) ? repo.ignorePaths : []) as string[];
      const excludes = computeScopeExclusions(scopePath, [...allScanPaths, ...ignorePaths]);

      log.info({ scanDir, scopePath, excludes }, "[worker] running cdxgen");
      await setPhase(scanRunId, "cdxgen");
      const cdxgenResult = await runCdxgen(scanDir, excludes);
      const sbomDoc = cdxgenResult.doc;
      const componentCount = sbomDoc.components?.length ?? 0;
      log.info({ componentCount, ok: cdxgenResult.ok }, "[worker] cdxgen done");

      // Untrust signal: cdxgen failed to produce a parseable SBOM. Worker
      // continues so the scan record still completes (audit trail), but
      // skips remediation logic that would otherwise mark stale findings
      // as fixed.
      if (!cdxgenResult.ok) {
        await appendWarning(scanRunId, {
          code: "cdxgen_failed",
          severity: "error",
          message: `cdxgen failed to produce a usable SBOM (${cdxgenResult.failureReason ?? "unknown"}). SCA auto-fix sweep was skipped to avoid marking real findings as resolved.`,
        });
      }

      // Soft notice: 0 components from a scope that previously had >0.
      // Could be legitimate (operator removed package.json) or a misconfig
      // (manifest path moved). We do NOT block auto-fix on this — the
      // operator's deliberate cleanup should propagate. Just surface it.
      if (cdxgenResult.ok && componentCount === 0) {
        const previousNonZero = await prisma.scanRun.findFirst({
          where: { scopeId: run.scopeId, status: "success", componentCount: { gt: 0 } },
          orderBy: { createdAt: "desc" },
          select: { componentCount: true, finishedAt: true },
        });
        if (previousNonZero) {
          await appendWarning(scanRunId, {
            code: "cdxgen_zero_components",
            severity: "info",
            message: `cdxgen returned 0 components — previous scan had ${previousNonZero.componentCount}. If the manifest was removed intentionally, no action needed; otherwise verify the repo has package.json / pyproject.toml / etc. at the expected path.`,
          });
        }
      }

      // ── Step 3: Stage-1 post-processing ─────────────────────────────────
      // Extract cleaned components without persisting yet — Stage 2 (LLM
      // augmentation) may add or remove entries before the DB write.
      const cleanedComponents = extractCleanedComponents(sbomDoc);
      log.info({ cleaned: cleanedComponents.length }, "[worker] Stage-1 post-processing done");

      // ── Step 3.5: LLM SBOM augmentation (Stage 2) ───────────────────────
      // Runs between cdxgen+Stage-1 and OSV. On failure, emits an error
      // warning and falls back to the Stage-1-only component list so the scan
      // can still complete. A failed augmentation never aborts the scan.
      let finalComponents = cleanedComponents;
      let sbomEvidenceMap = new Map<string, { path: string; excerpt: string | null; llmReason: string }>();
      let sbomCpeMap = new Map<string, string>();
      let sbomIdentityMap = new Map<string, { componentRoot: string | null; evidence: Array<{ path: string; line: number | null }> }>();
      let augmentationFailed = false;
      const sbomTokenBudget = repo.llmSbomTokenBudget ?? DEFAULT_LLM_SBOM_TOKEN_BUDGET;

      try {
        await setPhase(scanRunId, "llm_sbom", {
          done: 0,
          total: sbomTokenBudget,
        });
        const augResult = await runSbomAugmentation({
          scanRunId,
          scopeDir: scanDir,
          scopePath,
          components: cleanedComponents,
          firstPartyNamespaces: repo.firstPartyNamespaces ?? [],
          vendoredDirs:
            repo.vendoredDirs?.length > 0
              ? repo.vendoredDirs
              : ["extern/", "third-party/", "vendor/"],
          tokenBudget: sbomTokenBudget,
          effortLevel: repo.llmSbomEffort ?? "medium",
          orgId: run.orgId,
          onProgress: (usage) => {
            void setPhase(scanRunId, "llm_sbom", {
              done: usage.inputTokens + usage.outputTokens,
              total: sbomTokenBudget,
            });
          },
        });

        if (augResult.parseErrors.length > 0) {
          log.warn(
            { count: augResult.parseErrors.length, samples: augResult.parseErrors.slice(0, 3) },
            "[worker] LLM SBOM augmentation parse errors",
          );
          await appendWarning(scanRunId, {
            code: "llm_sbom_parse_errors",
            severity: "info",
            message: `LLM SBOM augmentation emitted ${augResult.parseErrors.length} unparseable records. Partial results applied.`,
            details: truncateParseErrors(augResult.parseErrors),
          });
        }

        if (augResult.exitCode !== 0 && augResult.records.length === 0) {
          throw new Error(`claude -p exited ${augResult.exitCode} with no records`);
        }

        const applied = applySbomAugmentation(cleanedComponents, augResult);
        finalComponents = applied.components;
        sbomEvidenceMap = applied.evidenceMap;
        sbomCpeMap = applied.cpeMap;
        sbomIdentityMap = applied.identityMap;

        log.info(
          {
            before: cleanedComponents.length,
            after: finalComponents.length,
            keeps: augResult.records.filter((r) => r.type === "keep").length,
            drops: augResult.records.filter((r) => r.type === "drop").length,
            adds: augResult.records.filter((r) => r.type === "add").length,
            evidenceEntries: sbomEvidenceMap.size,
          },
          "[worker] LLM SBOM augmentation applied",
        );
      } catch (err) {
        log.error({ err: (err as Error).message }, "[worker] LLM SBOM augmentation failed — using Stage-1 output");
        await appendWarning(scanRunId, {
          code: "llm_sbom_augmentation_failed",
          severity: "error",
          message: `LLM SBOM augmentation failed: ${(err as Error).message}. Using Stage-1-only output.`,
        });
        // Fall back to Stage-1 output; evidence map stays empty.
        finalComponents = cleanedComponents;
        sbomEvidenceMap = new Map();
        augmentationFailed = true;
      } finally {
        await cleanupSbomTmp(scanRunId);
      }

      // ── Step 3.9: emit canonical SBOM artifact (file-first, E1) ─────────────
      // Build the CycloneDX 1.7 document in memory from the post-augmentation
      // component list, then write it to disk. This is the canonical source of
      // truth for what this scan directly observed (manifest + llm_augmentation).
      // No recheck-recovery rows appear at this point — those are scope-level only.
      await setPhase(scanRunId, "sbom_emit");
      try {
        const sbomEmitDoc = await buildAugmentationSbom({
          scanRunId,
          scopeId: run.scopeId,
          scopePath,
          scanDir,
          components: finalComponents,
          sbomEvidenceMap,
          sbomCpeMap,
          sbomIdentityMap,
          startedAt: run.startedAt ?? null,
          finishedAt: null, // not finished yet
          repoName: repo.name,
          repoDefaultBranch: repo.defaultBranch,
        });
        await writeArtifact(sbomPathFor(scanRunId), stableStringify(sbomEmitDoc, 2));
        log.info({ components: sbomEmitDoc.components.length }, "[worker] SBOM artifact written");
      } catch (err) {
        log.error({ err: (err as Error).message }, "[worker] sbom_emit failed");
        await appendWarning(scanRunId, {
          code: "sbom_emit_failed",
          severity: "error",
          message: `Failed to write SBOM artifact: ${(err as Error).message}`,
        });
      }

      // ── Step 3.92: ingest SBOM from artifact file ─────────────────────────
      // Reads the just-written file and populates sbom_components + componentCount.
      // After this, sbom_components is the immutable direct-observation record
      // for this scan. All subsequent phases read from it; none write to it.
      await setPhase(scanRunId, "sbom_ingest");
      try {
        await ingestSbomFromArtifact(scanRunId);
        log.info("[worker] sbom_components populated from artifact file");
      } catch (err) {
        log.error({ err: (err as Error).message }, "[worker] sbom_ingest failed");
        await appendWarning(scanRunId, {
          code: "sbom_ingest_failed",
          severity: "error",
          message: `Failed to ingest SBOM artifact: ${(err as Error).message}`,
        });
      }

      // ── Step 3.95: persist components into scope-level state ─────────────
      // Reads the now-populated sbom_components rows for this scan and upserts
      // scope_components + scan_run_components join rows. Must happen before the
      // recheck phase so the candidate set (active rows NOT in this run's join
      // table) is correctly populated.
      //
      // Gated on augmentation success: when augmentation fails, finalComponents
      // is the Stage-1 cdxgen-cleaned output, which for most repos is dominated
      // by CMake probe noise. Persisting that noise into scope_components would
      // pollute the durable truth set.
      let components = await prisma.sbomComponent.findMany({ where: { scanRunId } });

      if (!augmentationFailed) {
        try {
          const scopeState = await persistScanComponentsToScopeState(
            scanRunId,
            run.scopeId,
            run.orgId,
            components,
          );
          log.info(scopeState, "[worker] scope_components state updated");
        } catch (err) {
          // Non-fatal: the scan should not die from a scope-state failure.
          // The recheck phase will simply find zero candidates for this run
          // (they won't have join rows) and become a no-op.
          log.error({ err: (err as Error).message }, "[worker] scope_components persistence failed — continuing");
        }
      } else {
        log.warn(
          "[worker] skipping scope_components persistence — augmentation failed, Stage-1 output is dominated by noise (CMake probes, etc.); not promoting to scope-level truth set",
        );
      }

      // ── Step 3.97: LLM SBOM component recheck (scope-only) ───────────────
      // Compares scope-level truth set (active components not seen this run)
      // against the filesystem and LLM. Confirmed-present components are
      // recovered into scope_components (lastSeenScanRunId bumped). The
      // per-scan sbom_components table is NOT modified — it stays immutable
      // post-ingest and contains direct observations only.
      try {
        const sbomRecheckTokenBudget = repo.llmSbomRecheckTokenBudget ?? DEFAULT_LLM_SBOM_RECHECK_TOKEN_BUDGET;
        const recheckEffort = repo.llmSbomRecheckEffort ?? "medium";
        await setPhase(scanRunId, "llm_sbom_recheck", { done: 0, total: sbomRecheckTokenBudget });

        const recheckResult = await runSbomRecheck({
          scanRunId,
          scopeId: run.scopeId,
          scopeDir: scanDir,
          effortLevel: recheckEffort,
          tokenBudget: sbomRecheckTokenBudget,
          orgId: run.orgId,
          onProgress: (usage) => {
            void setPhase(scanRunId, "llm_sbom_recheck", {
              done: usage.inputTokens + usage.outputTokens,
              total: sbomRecheckTokenBudget,
            });
          },
        });

        log.info(
          {
            recovered: recheckResult.recovered.length,
            removed: recheckResult.removed.length,
            mergeGroups: recheckResult.merged.length,
            mergedRowsRemoved: recheckResult.mergedRowsRemoved,
            capped: recheckResult.capped,
            parseErrors: recheckResult.parseErrors.length,
            exitCode: recheckResult.exitCode,
            durationMs: recheckResult.durationMs,
            usage: recheckResult.usage,
          },
          "[worker] SBOM component recheck finished",
        );

        // E1: scope-only recovery — bump scope_components.lastSeenScanRunId
        // only. No sbom_components writes; no in-memory list extension.
        // OSV / NVD phases run against direct-observation components only
        // (what this scan actually found via cdxgen + LLM augmentation).
        if (recheckResult.recovered.length > 0) {
          try {
            const { updated } = await materializeRecoveredComponents(
              recheckResult.recovered,
              scanRunId,
            );
            log.info(
              { updated },
              "[worker] recovered components: scope_components.lastSeenScanRunId bumped (scope-only)",
            );
          } catch (err) {
            log.error(
              { err: (err as Error).message },
              "[worker] failed to bump lastSeenScanRunId on recovered components",
            );
          }
        }

        if (recheckResult.capped > 0) {
          await appendWarning(scanRunId, {
            code: "recheck_capped",
            severity: "info",
            message: `SBOM recheck: ${recheckResult.capped} candidate(s) skipped (hard cap of ${MAX_SBOM_RECHECK_CANDIDATES} reached). Components not processed remain active from prior runs.`,
            context: { totalCandidates: recheckResult.capped + Math.min(recheckResult.recovered.length + recheckResult.removed.length + recheckResult.parseErrors.length, MAX_SBOM_RECHECK_CANDIDATES), processed: MAX_SBOM_RECHECK_CANDIDATES },
          });
        }

        if (recheckResult.parseErrors.length > 0) {
          await appendWarning(scanRunId, {
            code: "llm_sbom_recheck_partial",
            severity: "info",
            message: `SBOM recheck emitted ${recheckResult.parseErrors.length} unparseable verdict(s). Ambiguous components remain active.`,
            details: truncateParseErrors(recheckResult.parseErrors),
          });
        }

        // Token usage accounting.
        if (recheckResult.usage.inputTokens > 0 || recheckResult.usage.outputTokens > 0) {
          await prisma.scanRun.update({
            where: { id: scanRunId },
            data: {
              llmInputTokens: { increment: recheckResult.usage.inputTokens },
              llmOutputTokens: { increment: recheckResult.usage.outputTokens },
              llmRequestCount: { increment: recheckResult.usage.requestCount },
            },
          });
        }

        // Failure signal: non-zero exit with zero records from Tier-2.
        if (recheckResult.exitCode !== null && recheckResult.exitCode !== 0 && recheckResult.recovered.length === 0 && recheckResult.removed.length === 0) {
          await appendWarning(scanRunId, {
            code: "llm_sbom_recheck_failed",
            severity: "error",
            message: `SBOM component recheck exited with code ${recheckResult.exitCode}. Potentially-missing components remain active (safe default). Scan marked untrustworthy.`,
          });
        }
      } catch (err) {
        log.error({ err: (err as Error).message }, "[worker] SBOM component recheck phase failed");
        await appendWarning(scanRunId, {
          code: "llm_sbom_recheck_failed",
          severity: "error",
          message: `SBOM component recheck failed: ${(err as Error).message}. Components from prior runs remain active.`,
        });
      }

      // ── Step 4: OSV.dev vulnerability lookup ────────────────────────────
      log.info("[worker] querying OSV.dev");
      await setPhase(scanRunId, "osv", { done: 0, total: components.length, label: "Querying OSV.dev" });
      const cveFindings = await queryAndPersistFindings(scanRunId, run.scopeId, run.orgId, components, prisma, scanDir, scopePath, repo.reachabilityIncludeDevDeps);
      log.info({ findings: cveFindings.length }, "[worker] CVE findings persisted");

      // ── Step 4.5: NVD fallback for generic/C/C++ components ─────────────
      // Always-on for `generic` ecosystem components — OSV has near-zero
      // coverage there. Uses CPE for precise matching when available (set by
      // the LLM SBOM augmentation pass). Failure is non-fatal: an info-level
      // warning is recorded and the scan continues without NVD data.
      const genericComponents = components.filter((c) => c.ecosystem === "generic" || c.ecosystem === null);
      let nvdFindings: typeof cveFindings = [];
      if (genericComponents.length > 0) {
        log.info({ genericCount: genericComponents.length }, "[worker] querying NVD for generic components");
        await setPhase(scanRunId, "nvd", { done: 0, total: genericComponents.length, label: "Querying NVD" });
        try {
          nvdFindings = await queryAndPersistNvdFindings(
            scanRunId,
            run.scopeId,
            run.orgId,
            components,
            prisma,
            (done, total) => {
              void setPhase(scanRunId, "nvd", { done, total, label: "Querying NVD" });
            },
          );
          log.info({ findings: nvdFindings.length }, "[worker] NVD findings persisted");
        } catch (err) {
          log.warn({ err: (err as Error).message }, "[worker] NVD phase failed — continuing without NVD data");
          await appendWarning(scanRunId, {
            code: "nvd_query_failed",
            severity: "info",
            message: `NVD query phase failed: ${(err as Error).message}. NVD-sourced findings are unavailable for this scan.`,
          });
        }
      }

      // ── Step 5: EOL / deprecation check ─────────────────────────────────
      log.info("[worker] checking EOL / deprecation");
      await setPhase(scanRunId, "eol", { done: 0, total: components.length, label: "Checking EOL / deprecation" });
      const eolFindings = await checkAndPersistEolFindings(scanRunId, run.scopeId, run.orgId, components, prisma);
      log.info({ eolFindings: eolFindings.length }, "[worker] EOL findings persisted");

      const findings = [...cveFindings, ...nvdFindings, ...eolFindings];

      // ── Step 6: SAST (LLM-mode only — Opengrep removed in M6g) ───────────
      // The LLM pass also emits reachability verdicts and vendored-library
      // records; standalone reachability + opengrep-era SAST summary backfill
      // are no longer needed.
      const analysisTypes = Array.isArray(repo.analysisTypes)
        ? (repo.analysisTypes as string[])
        : [];

      if (analysisTypes.includes("sast")) {
        await runLlmSastPipeline({
          scanRunId,
          repo,
          run,
          scanDir,
          scopePath,
          log,
        });
      }

      // ── Step 6d: LLM summaries for SCA issues ───────────────────────────
      const scaNeedingSummary = await prisma.scaIssue.findMany({
        where: { scopeId: run.scopeId, lastSeenScanRunId: scanRunId, latestLlmSummary: null },
        select: { id: true, packageName: true, latestPackageVersion: true, osvId: true, latestCveId: true, latestCvssScore: true, latestSummary: true },
      });
      if (scaNeedingSummary.length > 0) {
        log.info({ count: scaNeedingSummary.length }, "[worker] generating SCA summaries");
        await setPhase(scanRunId, "sca_summaries", {
          done: 0,
          total: scaNeedingSummary.length,
          label: "Generating SCA summaries",
        });
        let done = 0;
        for (const issue of scaNeedingSummary) {
          const summary = await generateIssueSummary("sca", {
            packageName: issue.packageName,
            version: issue.latestPackageVersion,
            osvId: issue.osvId,
            cveId: issue.latestCveId,
            cvssScore: issue.latestCvssScore,
            osvSummary: issue.latestSummary,
            scanRunId,
            orgId: run.orgId,
          });
          if (summary) {
            await prisma.scaIssue.update({ where: { id: issue.id }, data: { latestLlmSummary: summary } });
          }
          done++;
          // Update progress every 5 summaries to keep the DB write rate sane.
          if (done % 5 === 0 || done === scaNeedingSummary.length) {
            await setPhase(scanRunId, "sca_summaries", {
              done,
              total: scaNeedingSummary.length,
              label: "Generating SCA summaries",
            });
          }
        }
      }

      // ── Step 7: SCA auto-fix ─────────────────────────────────────────────
      // Reachability + SAST recheck are handled inside runLlmSastPipeline.
      // SCA findings still need the simple "wasn't detected this run → mark
      // resolved" sweep since cdxgen + OSV don't have an analogous recheck
      // mechanism (a manifest entry that disappears IS the resolution).
      //
      // GATE: skip the sweep entirely when any error-severity warning was
      // recorded during this scan — a degraded scan ("cdxgen produced 0
      // components because the network died mid-fetch", "claude-p
      // crashed after 6h") would otherwise silently mark every existing
      // finding as fixed. The operator can manually trigger remediation
      // after diagnosing the failure.
      await setPhase(scanRunId, "finalizing");
      const untrustworthy = await hasErrorWarnings(scanRunId);
      if (untrustworthy) {
        log.warn("[worker] skipping SCA auto-fix sweep — scan has error-severity warnings");
      } else {
        const TERMINAL_STATUSES = ["fixed", "suppressed", "false_positive"];
        await prisma.scaIssue.updateMany({
          where: {
            scopeId: run.scopeId,
            lastSeenScanRunId: { not: scanRunId },
            dismissedStatus: { notIn: TERMINAL_STATUSES },
          },
          data: { dismissedStatus: "fixed" },
        });
        log.info("[worker] auto-fixed resolved SCA issues");
      }

      // ── Step 8: update severity summary counters (SCA + SAST) ────────────
      // Combined totals so the scans list and scan detail page show the full
      // picture for a run, not just the SCA half. SAST `info` severity is
      // intentionally not surfaced here — it has no critical/high/medium/low
      // bucket and operators don't track it as risk.
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of findings) {
        if (f.severity === "critical") counts.critical++;
        else if (f.severity === "high") counts.high++;
        else if (f.severity === "medium") counts.medium++;
        else if (f.severity === "low") counts.low++;
      }
      const sastIssuesForScan = await prisma.sastIssue.findMany({
        where: { lastSeenScanRunId: scanRunId },
        select: { latestSeverity: true },
      });
      for (const i of sastIssuesForScan) {
        if (i.latestSeverity === "critical") counts.critical++;
        else if (i.latestSeverity === "high") counts.high++;
        else if (i.latestSeverity === "medium") counts.medium++;
        else if (i.latestSeverity === "low") counts.low++;
      }

      const finishedAt = new Date();
      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: {
          status: "success",
          finishedAt,
          criticalCount: counts.critical,
          highCount: counts.high,
          mediumCount: counts.medium,
          lowCount: counts.low,
          currentPhase: null,
          phaseProgress: Prisma.JsonNull,
        },
      });

      // Update scope denorm. `lastScanCompletedAt` always advances (operators
      // want to see "Last scan: just now" even when the scan was degraded —
      // it's the operational truth). `lastScanRunId` is the pivot point for
      // "which run defines current findings" used by the SCA/SAST default
      // filters, so it ONLY advances when the scan is trustworthy. A degraded
      // run doesn't earn the pointer; previous good run keeps it.
      await prisma.scanScope.update({
        where: { id: run.scopeId },
        data: untrustworthy
          ? { lastScanCompletedAt: finishedAt }
          : { lastScanRunId: scanRunId, lastScanCompletedAt: finishedAt },
      });

      log.info({ ...counts, untrustworthy }, "[worker] scan complete");
    } catch (err) {
      // Map known error classes to operator-friendly messages + typed
      // warnings so the GUI surfaces something useful instead of a
      // silent "failed" with an empty warnings array.
      let message: string;
      let warningCode: string | null = null;
      if (err instanceof RemoteUnreachableError) {
        message = `Git remote unreachable — cache preserved. Reconnect VPN/network and retry. (${err.message})`;
        warningCode = "remote_unreachable";
      } else if (err instanceof GitCloneError) {
        // Branch-not-found is the common "user pasted a repo and the
        // default branch is master, not main" case. Detect it from
        // stderr and frame the fix concretely.
        const stderr = err.stderr ?? "";
        if (/Remote branch .* not found in upstream origin/i.test(stderr)) {
          const branchMatch = stderr.match(/Remote branch (\S+) not found/i);
          const wrongBranch = branchMatch?.[1] ?? repo.defaultBranch;
          message = `Default branch "${wrongBranch}" does not exist on the remote. Edit the repo in Admin → Repos and set Default branch to the branch the repo actually uses (commonly "master" for older LMI repos, "main" for newer ones).`;
          warningCode = "branch_not_found";
        } else if (/could not read Username|Authentication failed|fatal: Authentication/i.test(stderr)) {
          message = `Git authentication failed. Verify the repo's stored credentials in Admin → Credentials. (${err.message})`;
          warningCode = "auth_failed";
        } else {
          message = `Git clone failed: ${err.message}`;
          warningCode = "clone_failed";
        }
      } else {
        message = err instanceof Error ? err.message : String(err);
      }

      if (warningCode) {
        await appendWarning(scanRunId, {
          code: warningCode,
          severity: "error",
          message,
        }).catch(() => undefined);
      }
      log.error({ err }, "[worker] scan failed");
      await prisma.scanRun
        .update({
          where: { id: scanRunId },
          data: {
            status: "failed",
            finishedAt: new Date(),
            error: message,
            currentPhase: null,
            phaseProgress: Prisma.JsonNull,
          },
        })
        .catch(() => undefined);
      throw err;
    } finally {
      if (clone?.ephemeral) {
        await rm(clone.workingDir, { recursive: true, force: true }).catch(
          () => undefined,
        );
      }
    }
  },
  { connection: getRedis(), concurrency: config.scanWorkerConcurrency },
);

worker.on("failed", (job, err) => {
  logger.error({ jobId: job?.id, err }, "[worker] job failed");
});

worker.on("ready", () => logger.info("[worker] ready"));

async function shutdown(signal: string): Promise<void> {
  logger.info({ signal }, "[worker] shutting down");
  try {
    await worker.close();
  } catch (err) {
    logger.warn({ err }, "[worker] error closing worker");
  }
  await prisma.$disconnect().catch(() => undefined);
  await closeRedis();
  process.exit(0);
}

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

// Diagnostic catch-alls. Without these, an async error inside a stream-event
// handler (claude-p stdout parsing, BullMQ callback) crashes the worker
// silently — pnpm just prints `ELIFECYCLE Command failed` and we have no
// signal what broke. Log with the full stack, then exit so BullMQ retries
// the job rather than us limping along with corrupted state.
process.on("uncaughtException", (err) => {
  logger.fatal({ err }, "[worker] uncaughtException");
  process.exit(1);
});
process.on("unhandledRejection", (reason) => {
  logger.fatal({ reason }, "[worker] unhandledRejection");
  process.exit(1);
});
