import { rm } from "node:fs/promises";
import { join } from "node:path";

import { Worker } from "bullmq";
import { pino } from "pino";

import { loadConfig } from "./config.js";
import { prisma } from "./db.js";
import { closeRedis, getRedis } from "./queue/connection.js";
import { SCAN_QUEUE_NAME, type ScanJobData } from "./queue/scanQueue.js";
import { cloneOrRefresh } from "./services/repoCache.js";
import { persistComponents, runCdxgen } from "./services/sbomService.js";
import { queryAndPersistFindings, backfillCvssScores, backfillManifestOrigin } from "./services/osvService.js";
import { checkAndPersistEolFindings } from "./services/eolService.js";
import { runOpengrep, parseSarif, persistSastFindings, backfillSastContextSnippets } from "./services/sastService.js";
import { triageFindings } from "./services/llmTriageService.js";
import { assessReachability, backfillReachability } from "./services/reachabilityService.js";
import { generateIssueSummary } from "./services/llmClient.js";
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

backfillSastContextSnippets(prisma).catch((err) => {
  logger.warn({ err }, "[worker] SAST context backfill failed");
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

      // ── Step 6: SAST via Opengrep ─────────────────────────────────────────
      const analysisTypes = Array.isArray(repo.analysisTypes)
        ? (repo.analysisTypes as string[])
        : [];
      if (analysisTypes.includes("sast")) {
        log.info({ scanDir, excludes }, "[worker] running opengrep SAST");
        const sarif = await runOpengrep(scanDir, excludes);
        if (sarif === null) {
          log.warn("[worker] opengrep binary missing — SAST skipped");
          await appendWarning(scanRunId, {
            code: "opengrep_missing",
            message:
              "Opengrep binary not found; SAST analysis skipped. Install opengrep in the backend image.",
          });
        } else {
          const inputs = parseSarif(sarif, scanDir);
          log.info({ inputCount: inputs.length }, "[worker] SARIF parsed");
          const sastFindings = await persistSastFindings(
            scanRunId,
            run.scopeId,
            run.orgId,
            inputs,
            prisma,
            scanDir, // pass the working directory so snippets get ±3 lines of context
          );
          log.info({ count: sastFindings.length }, "[worker] SAST findings persisted");
          await prisma.scanRun.update({
            where: { id: scanRunId },
            data: { sastFindingCount: sastFindings.length },
          });

          // ── Step 6b: LLM triage ───────────────────────────────────────────
          if (sastFindings.length > 0) {
            log.info("[worker] starting LLM triage");
            await triageFindings(scanRunId, run.scopeId, run.orgId, prisma);
            log.info("[worker] LLM triage complete");
          }

          // ── Step 6c: LLM summaries for SAST issues ───────────────────────
          const sastNeedingSummary = await prisma.sastIssue.findMany({
            where: { scopeId: run.scopeId, lastSeenScanRunId: scanRunId, latestLlmSummary: null },
            select: { id: true, latestRuleId: true, latestRuleName: true, latestRuleMessage: true, latestFilePath: true, latestSnippet: true },
          });
          if (sastNeedingSummary.length > 0) {
            log.info({ count: sastNeedingSummary.length }, "[worker] generating SAST summaries");
            for (const issue of sastNeedingSummary) {
              const summary = await generateIssueSummary("sast", {
                ruleId: issue.latestRuleId,
                ruleName: issue.latestRuleName,
                ruleMessage: issue.latestRuleMessage,
                filePath: issue.latestFilePath,
                snippet: issue.latestSnippet,
                scanRunId,
                orgId: run.orgId,
              });
              if (summary) {
                await prisma.sastIssue.update({ where: { id: issue.id }, data: { latestLlmSummary: summary } });
              }
            }
          }
        }
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

      // ── Step 7: SCA reachability analysis ────────────────────────────────
      log.info("[worker] assessing SCA reachability");
      await assessReachability(scanRunId, run.scopeId, scanDir, run.orgId, prisma);
      log.info("[worker] reachability assessment complete");

      // ── Step 8: auto-fix SAST and SCA issues no longer detected in this scan ─
      // Any non-terminal issue that wasn't seen in this scan is now "fixed".
      const TERMINAL_STATUSES = ["fixed", "suppressed", "false_positive"];
      await prisma.sastIssue.updateMany({
        where: {
          scopeId: run.scopeId,
          lastSeenScanRunId: { not: scanRunId },
          triageStatus: { notIn: TERMINAL_STATUSES },
        },
        data: { triageStatus: "fixed" },
      });
      await prisma.scaIssue.updateMany({
        where: {
          scopeId: run.scopeId,
          lastSeenScanRunId: { not: scanRunId },
          dismissedStatus: { notIn: TERMINAL_STATUSES },
        },
        data: { dismissedStatus: "fixed" },
      });
      log.info("[worker] auto-fixed resolved issues");

      // ── Step 9: update SCA severity summary counters ─────────────────────
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
      const message = err instanceof Error ? err.message : String(err);
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
