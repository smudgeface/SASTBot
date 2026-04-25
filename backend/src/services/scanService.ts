import type { ScanRun } from "@prisma/client";

import { prisma } from "../db.js";
import { RepoNotFoundError } from "./repoService.js";
import { getScanQueue } from "../queue/scanQueue.js";

export interface TriggerScanInput {
  repoId: string;
  orgId: string | null;
  triggeredByUserId: string | null;
  triggeredBy: "user" | "api" | "schedule";
}

/**
 * Trigger one ScanRun per active ScanScope on the repo.
 * Returns the array of created runs (usually just one for single-path repos).
 */
export async function triggerScan(input: TriggerScanInput): Promise<ScanRun[]> {
  const repo = await prisma.repo.findFirst({
    where: { id: input.repoId, orgId: input.orgId ?? null },
    select: { id: true, orgId: true },
  });
  if (!repo) throw new RepoNotFoundError();

  const scopes = await prisma.scanScope.findMany({
    where: { repoId: repo.id, isActive: true },
    orderBy: { path: "asc" },
  });

  if (scopes.length === 0) {
    // Safety net: repo has no scopes (shouldn't happen after migration, but
    // guard against it so a scan trigger doesn't silently do nothing).
    throw new Error("Repo has no active scan scopes — re-save the repo to fix this.");
  }

  const runs: ScanRun[] = [];
  const queue = getScanQueue();

  for (const scope of scopes) {
    // Defense in depth: don't queue another run for a scope that already has
    // a pending/running one. Frontend disables the button while scanning, but
    // a fast double-click or stale state shouldn't pile scans up either.
    const existing = await prisma.scanRun.findFirst({
      where: { scopeId: scope.id, status: { in: ["pending", "running"] } },
    });
    if (existing) {
      runs.push(existing);
      continue;
    }

    const run = await prisma.scanRun.create({
      data: {
        orgId: repo.orgId,
        repoId: repo.id,
        scopeId: scope.id,
        status: "pending",
        triggeredBy: input.triggeredBy,
        triggeredByUserId: input.triggeredByUserId,
      },
    });

    await queue.add(
      "scan",
      { scanRunId: run.id, scopeId: scope.id, scopePath: scope.path },
      { removeOnComplete: { count: 100 }, removeOnFail: { count: 200 } },
    );

    runs.push(run);
  }

  return runs;
}
