import { rm } from "node:fs/promises";
import { join } from "node:path";

import { Worker } from "bullmq";
import { pino } from "pino";

import { loadConfig } from "./config.js";
import { prisma } from "./db.js";
import { closeRedis, getRedis } from "./queue/connection.js";
import { SCAN_QUEUE_NAME, type ScanJobData } from "./queue/scanQueue.js";
import { cloneOrRefresh, RemoteUnreachableError } from "./services/repoCache.js";
import { persistComponents, runCdxgen } from "./services/sbomService.js";
import { queryAndPersistFindings, backfillCvssScores, backfillManifestOrigin } from "./services/osvService.js";
import { checkAndPersistEolFindings } from "./services/eolService.js";
import { backfillReachability } from "./services/reachabilityService.js";
import { generateIssueSummary } from "./services/llmClient.js";
import {
  applyRecheckVerdicts,
  cleanupTmp as cleanupLlmTmp,
  persistDetection,
  type RecheckIssueInput,
  runDetection,
  runRecheck,
  type ScaHintInput,
} from "./services/llmSastService.js";
import type { ScanWarning } from "./schemas.js";
import type { Prisma } from "@prisma/client";

const config = loadConfig();
const logger = pino({ level: config.logLevel, name: "sastbot-worker" });

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

// ---------------------------------------------------------------------------
// LLM-mode SAST pipeline (M6 — runs when repo.sastEngine === "llm")
// ---------------------------------------------------------------------------

interface LlmSastPipelineInput {
  scanRunId: string;
  repo: {
    name: string;
    defaultBranch: string;
    ignorePaths: unknown;
    llmSastTokenBudget: number;
    llmRecheckTokenBudget: number;
    reachabilityEnabled: boolean;
    reachabilityIncludeDevDeps: boolean;
  };
  run: { scopeId: string; orgId: string | null };
  scanDir: string;
  log: pino.Logger;
}

const LLM_SCA_HINT_CAP = 200;
const TERMINAL_TRIAGE_STATUSES = ["fixed", "suppressed", "false_positive"];

async function runLlmSastPipeline(input: LlmSastPipelineInput): Promise<void> {
  const { scanRunId, repo, run, scanDir, log } = input;

  try {
    // 1. Build the SCA hint list (top-N by severity then CVSS) from rows the
    //    cdxgen + OSV pipeline already wrote in steps 4–5. When reachability
    //    is disabled on the repo we skip this entirely — the model gets an
    //    empty hint file, Goal 2 of the prompt iterates zero times, and we
    //    save the output tokens that would have gone into 100+ verdicts.
    let scaHints: ScaHintInput[] = [];
    if (repo.reachabilityEnabled) {
      // Filter cdxgen `optional`-scoped components (devDependencies / build
      // tooling) unless the repo opts in. cdxgen reuses the CycloneDX
      // `scope` field — `required` for runtime, `optional` for dev/build.
      // The /GoWeb experiment showed dev-tooling CVEs dominated the hint
      // list with no actionable verdicts; this filter cuts that noise.
      const where: Prisma.ScaIssueWhereInput = {
        scopeId: run.scopeId,
        lastSeenScanRunId: scanRunId,
        latestFindingType: "cve",
        latestSeverity: { in: ["critical", "high"] },
      };
      if (!repo.reachabilityIncludeDevDeps) {
        where.latestComponentScope = { not: "optional" };
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
    log.info({ scaHintCount: scaHints.length, budget: repo.llmSastTokenBudget }, "[worker] LLM detection start");
    const detection = await runDetection({
      scanRunId,
      scopeId: run.scopeId,
      scopeDir: scanDir,
      repoName: repo.name,
      repoBranch: repo.defaultBranch,
      ignorePaths: Array.isArray(repo.ignorePaths) ? (repo.ignorePaths as string[]) : [],
      scaHints,
      tokenBudget: repo.llmSastTokenBudget,
      orgId: run.orgId,
    });
    log.info(
      { records: detection.records.length, parseErrors: detection.parseErrors.length, durationMs: detection.durationMs, usage: detection.usage },
      "[worker] LLM detection finished",
    );

    if (detection.parseErrors.length > 0) {
      await appendWarning(scanRunId, {
        code: "llm_sast_parse_errors",
        message: `LLM SAST detection emitted ${detection.parseErrors.length} unparseable record(s); some findings may be missing.`,
      });
    }

    // 3. Persist detection records.
    const persistResult = await persistDetection(prisma, {
      scanRunId,
      scopeId: run.scopeId,
      scopeDir: scanDir,
      orgId: run.orgId,
      records: detection.records,
      modelName: "claude-code-cli",
    });
    log.info(persistResult, "[worker] LLM detection persisted");

    // 4. Stamp llm summary on every SastIssue from the detection records so
    //    the scope page shows the LLM's one-liner instead of just rule_id.
    for (const r of detection.records) {
      if (r.kind === "sast" || r.kind === "sast_absence") {
        await prisma.sastIssue.updateMany({
          where: {
            scopeId: run.scopeId,
            lastSeenScanRunId: scanRunId,
            latestFilePath: r.kind === "sast" ? r.file_path : r.evidence_file,
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
        file: i.latestFilePath,
        line: i.latestStartLine,
        summary: i.latestRuleMessage ?? i.latestRuleId,
        snippet: i.latestSnippet ?? "",
        cwe: i.latestCweIds[0] ?? "CWE-UNKNOWN",
      }));
      log.info({ count: recheckIssues.length, budget: repo.llmRecheckTokenBudget }, "[worker] LLM recheck start");
      const recheck = await runRecheck({
        scanRunId,
        scopeDir: scanDir,
        issues: recheckIssues,
        tokenBudget: repo.llmRecheckTokenBudget,
        orgId: run.orgId,
      });
      log.info(
        { verdicts: recheck.verdicts.length, parseErrors: recheck.parseErrors.length, durationMs: recheck.durationMs, usage: recheck.usage },
        "[worker] LLM recheck finished",
      );
      const apply = await applyRecheckVerdicts(prisma, {
        scanRunId,
        scopeId: run.scopeId,
        inputIssues: recheckIssues,
        verdicts: recheck.verdicts,
      });
      log.info(apply, "[worker] LLM recheck applied");

      if (recheck.parseErrors.length > 0) {
        await appendWarning(scanRunId, {
          code: "llm_recheck_parse_errors",
          message: `LLM recheck emitted ${recheck.parseErrors.length} unparseable record(s).`,
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

    // 7. Update sastFindingCount denorm.
    const sastCount = await prisma.sastIssue.count({
      where: { scopeId: run.scopeId, lastSeenScanRunId: scanRunId },
    });
    await prisma.scanRun.update({
      where: { id: scanRunId },
      data: { sastFindingCount: sastCount },
    });
  } finally {
    await cleanupLlmTmp(scanRunId);
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

backfillLlmSummaries().catch((err) => {
  logger.warn({ err }, "[worker] backfill failed — will retry on next scan");
});

backfillCvssScores(prisma).catch((err) => {
  logger.warn({ err }, "[worker] CVSS score backfill failed");
});

backfillReachability(prisma).catch((err) => {
  logger.warn({ err }, "[worker] reachability backfill failed");
});

backfillManifestOrigin(prisma).catch((err) => {
  logger.warn({ err }, "[worker] manifest-origin backfill failed");
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
      data: { status: "running", startedAt: new Date() },
    });

    let clone: Awaited<ReturnType<typeof cloneOrRefresh>> | null = null;
    try {
      // ── Step 1: clone / refresh ─────────────────────────────────────────
      log.info({ url: repo.url, retainClone: repo.retainClone }, "[worker] cloning repo");
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
      const sbomDoc = await runCdxgen(scanDir, excludes);
      const componentCount = sbomDoc.components?.length ?? 0;
      log.info({ componentCount }, "[worker] cdxgen done");

      // ── Step 3: persist components + raw SBOM ───────────────────────────
      const components = await prisma.$transaction(async (tx) => {
        // Store the raw SBOM and the component count on the run row now so
        // partial failures still leave the SBOM downloadable.
        await tx.scanRun.update({
          where: { id: scanRunId },
          data: {
            sbomJson: sbomDoc as object,
            componentCount,
          },
        });
        return persistComponents(scanRunId, sbomDoc, tx, scanDir);
      });
      log.info({ inserted: components.length }, "[worker] components persisted");

      // ── Step 4: OSV.dev vulnerability lookup ────────────────────────────
      log.info("[worker] querying OSV.dev");
      const cveFindings = await queryAndPersistFindings(scanRunId, run.scopeId, run.orgId, components, prisma, scanDir);
      log.info({ findings: cveFindings.length }, "[worker] CVE findings persisted");

      // ── Step 5: EOL / deprecation check ─────────────────────────────────
      log.info("[worker] checking EOL / deprecation");
      const eolFindings = await checkAndPersistEolFindings(scanRunId, run.scopeId, run.orgId, components, prisma);
      log.info({ eolFindings: eolFindings.length }, "[worker] EOL findings persisted");

      const findings = [...cveFindings, ...eolFindings];

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
        }
      }

      // ── Step 7: SCA auto-fix ─────────────────────────────────────────────
      // Reachability + SAST recheck are handled inside runLlmSastPipeline.
      // SCA findings still need the simple "wasn't detected this run → mark
      // resolved" sweep since cdxgen + OSV don't have an analogous recheck
      // mechanism (a manifest entry that disappears IS the resolution).
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

      // ── Step 8: update SCA severity summary counters ─────────────────────
      const counts = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const f of findings) {
        if (f.severity === "critical") counts.critical++;
        else if (f.severity === "high") counts.high++;
        else if (f.severity === "medium") counts.medium++;
        else if (f.severity === "low") counts.low++;
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
        },
      });

      // Update scope denorm so the scope list page can show last-scan timestamps
      await prisma.scanScope.update({
        where: { id: run.scopeId },
        data: { lastScanRunId: scanRunId, lastScanCompletedAt: finishedAt },
      });

      log.info(counts, "[worker] scan complete");
    } catch (err) {
      // Network failures get a plain-English error; everything else carries
      // the underlying error message through.
      const message = err instanceof RemoteUnreachableError
        ? `Git remote unreachable — cache preserved. Reconnect VPN/network and retry. (${err.message})`
        : err instanceof Error ? err.message : String(err);
      log.error({ err }, "[worker] scan failed");
      await prisma.scanRun
        .update({
          where: { id: scanRunId },
          data: {
            status: "failed",
            finishedAt: new Date(),
            error: message,
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
  { connection: getRedis() },
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
