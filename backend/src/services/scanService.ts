/**
 * Scan lifecycle — creating scan_runs rows and enqueueing BullMQ jobs.
 *
 * The worker (src/worker.ts) picks up the jobs and transitions the row
 * through pending → running → success/failed. M1/M2 uses a stub handler;
 * M3 fills in the real SCA work.
 */
import { prisma } from "../db.js";
import { RepoNotFoundError } from "./repoService.js";
import { getScanQueue } from "../queue/scanQueue.js";

export interface TriggerScanInput {
  repoId: string;
  orgId: string | null;
  triggeredByUserId: string | null;
  /** "user" | "api" | "schedule" — matches the ScanRunOut contract. */
  triggeredBy: "user" | "api" | "schedule";
}

/** Verify the repo exists + belongs to this org, then create a pending
 *  scan_runs row and enqueue it on the BullMQ `scans` queue. */
export async function triggerScan(input: TriggerScanInput) {
  const repo = await prisma.repo.findFirst({
    where: { id: input.repoId, orgId: input.orgId ?? null },
    select: { id: true, orgId: true },
  });
  if (!repo) {
    throw new RepoNotFoundError();
  }

  const run = await prisma.scanRun.create({
    data: {
      orgId: repo.orgId,
      repoId: repo.id,
      status: "pending",
      triggeredBy: input.triggeredBy,
      triggeredByUserId: input.triggeredByUserId,
    },
  });

  await getScanQueue().add(
    "scan",
    { scanRunId: run.id },
    {
      // Keep the queue tidy — BullMQ's default retains jobs forever.
      removeOnComplete: { count: 100 },
      removeOnFail: { count: 200 },
    },
  );

  return run;
}
