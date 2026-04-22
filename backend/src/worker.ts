import { Worker } from "bullmq";
import { pino } from "pino";

import { loadConfig } from "./config.js";
import { prisma } from "./db.js";
import { closeRedis, getRedis } from "./queue/connection.js";
import { SCAN_QUEUE_NAME, type ScanJobData } from "./queue/scanQueue.js";

const config = loadConfig();
const logger = pino({ level: config.logLevel, name: "sastbot-worker" });

const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * M1 stub worker: consumes jobs from the `scans` queue, marks the scan run as
 * running, sleeps, then marks it success. No actual scanning yet.
 */
const worker = new Worker<ScanJobData>(
  SCAN_QUEUE_NAME,
  async (job) => {
    const { scanRunId } = job.data;
    logger.info({ scanRunId }, "[worker] would scan");

    try {
      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: { status: "running", startedAt: new Date() },
      });
    } catch (err) {
      logger.warn({ err, scanRunId }, "[worker] could not mark scan running");
    }

    await sleep(2000);

    try {
      await prisma.scanRun.update({
        where: { id: scanRunId },
        data: { status: "success", finishedAt: new Date() },
      });
    } catch (err) {
      logger.warn({ err, scanRunId }, "[worker] could not mark scan success");
    }
  },
  { connection: getRedis() },
);

worker.on("failed", (job, err) => {
  logger.error({ jobId: job?.id, err }, "[worker] job failed");
  if (job?.data?.scanRunId) {
    prisma.scanRun
      .update({
        where: { id: job.data.scanRunId },
        data: {
          status: "failed",
          finishedAt: new Date(),
          error: err.message ?? String(err),
        },
      })
      .catch(() => undefined);
  }
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
