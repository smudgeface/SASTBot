import { rm } from "node:fs/promises";

import { Worker } from "bullmq";
import { pino } from "pino";

import { loadConfig } from "./config.js";
import { prisma } from "./db.js";
import { closeRedis, getRedis } from "./queue/connection.js";
import { SCAN_QUEUE_NAME, type ScanJobData } from "./queue/scanQueue.js";
import { cloneOrRefresh } from "./services/repoCache.js";

const config = loadConfig();
const logger = pino({ level: config.logLevel, name: "sastbot-worker" });

/**
 * Scan job handler.
 *
 * M1/M2 scope: clone the repo (honouring retain_clone), then mark the run
 * as success. No analysis yet — M3 is where cdxgen + OSV integration lands
 * and M4 adds Opengrep + LLM triage.
 *
 * Even without real analysis, exercising the clone path makes the scan
 * pipeline properly end-to-end: credentials get decrypted and exercised,
 * retained clones get cached, and any git/auth failure surfaces as a
 * real `failed` scan_run with an error message.
 */
const worker = new Worker<ScanJobData>(
  SCAN_QUEUE_NAME,
  async (job) => {
    const { scanRunId } = job.data;
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
      log.info(
        { url: repo.url, retainClone: repo.retainClone },
        "[worker] cloning repo",
      );
      clone = await cloneOrRefresh({
        repoId: repo.id,
        url: repo.url,
        defaultBranch: repo.defaultBranch,
        credentialId: repo.credentialId,
        retainClone: repo.retainClone,
      });
      log.info(
        { workingDir: clone.workingDir, fromCache: clone.fromCache },
        "[worker] clone ready (analysis deferred to M3)",
      );

      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: { status: "success", finishedAt: new Date() },
      });
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
