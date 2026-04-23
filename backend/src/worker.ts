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
import { queryAndPersistFindings } from "./services/osvService.js";
import { checkAndPersistEolFindings } from "./services/eolService.js";
import { runOpengrep, parseSarif, persistSastFindings } from "./services/sastService.js";
import { triageFindings } from "./services/llmTriageService.js";
import { assessReachability } from "./services/reachabilityService.js";
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
      log.info({ scanDir, scopePath }, "[worker] running cdxgen");
      const sbomDoc = await runCdxgen(scanDir);
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
        return persistComponents(scanRunId, sbomDoc, tx);
      });
      log.info({ inserted: components.length }, "[worker] components persisted");

      // ── Step 4: OSV.dev vulnerability lookup ────────────────────────────
      log.info("[worker] querying OSV.dev");
      const cveFindings = await queryAndPersistFindings(scanRunId, run.scopeId, run.orgId, components, prisma);
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
        log.info({ scanDir }, "[worker] running opengrep SAST");
        const sarif = await runOpengrep(scanDir);
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
        }
      }

      // ── Step 7: SCA reachability analysis ────────────────────────────────
      log.info("[worker] assessing SCA reachability");
      await assessReachability(scanRunId, run.scopeId, scanDir, run.orgId, prisma);
      log.info("[worker] reachability assessment complete");

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
