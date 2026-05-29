import type { ScanRun } from "@prisma/client";

import { prisma } from "../db.js";
import { RepoNotFoundError } from "./repoService.js";
import { getScanQueue } from "../queue/scanQueue.js";
import { deleteScanArtifacts } from "./artifactStore.js";

export class ScanRunNotFoundError extends Error {
  constructor() { super("Scan run not found"); }
}

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
      {
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 200 },
        // Explicit: a thrown processor error marks the scan failed and must NOT
        // re-run. A SAST scan is expensive (LLM tokens) and the worker already
        // finalizes the scan_runs row to `failed` in its catch block — retrying
        // would double-spend and create duplicate state. Stalled-job recovery
        // (worker crash) is a separate BullMQ mechanism, unaffected by this.
        attempts: 1,
      },
    );

    runs.push(run);
  }

  return runs;
}

/**
 * Cancel a pending or running scan run. For waiting/delayed BullMQ jobs we
 * remove the job from the queue. For an already-running job we set the
 * scan_run row to "cancelled" so the worker bails on the next phase boundary
 * (the worker checks status before each major step). Returns the updated
 * ScanRun. Raises ScanRunNotFoundError if the id doesn't exist.
 *
 * Idempotent: cancelling a run that's already in a terminal state is a no-op
 * and returns the row unchanged.
 */
export async function cancelScanRun(scanRunId: string, orgId: string | null): Promise<ScanRun> {
  const run = await prisma.scanRun.findFirst({
    where: { id: scanRunId, orgId: orgId ?? null },
  });
  if (!run) throw new ScanRunNotFoundError();

  if (run.status === "success" || run.status === "failed" || run.status === "cancelled") {
    return run;
  }

  // Best-effort: remove the BullMQ job for this run. The job's data carries
  // scanRunId so we look it up rather than trusting BullMQ's incrementing id.
  const queue = getScanQueue();
  const jobs = await queue.getJobs(["waiting", "delayed", "paused", "wait"]);
  for (const job of jobs) {
    const data = job.data as { scanRunId?: string };
    if (data?.scanRunId === scanRunId) {
      try { await job.remove(); } catch {
        // ignore: job may have moved to active between lookup and remove
      }
    }
  }

  return prisma.scanRun.update({
    where: { id: scanRunId },
    data: {
      status: "cancelled",
      finishedAt: new Date(),
      error: run.status === "running"
        ? "Cancelled by user while running — partial results may have been written"
        : "Cancelled by user before scan started",
    },
  });
}

/**
 * Raised when an operator tries to delete the scan_run that's currently
 * anchoring its scope's truth set (scope.lastScanRunId). Trigger a new
 * scan first, then re-attempt the delete.
 */
export class ScanIsCurrentLatestError extends Error {
  constructor(public readonly scopeId: string, public readonly scanRunId: string) {
    super("Scan is the scope's lastScanRunId");
  }
}

/**
 * Raised when a delete is attempted on a scan that's still pending/running.
 * Cancel it first.
 */
export class ScanStillRunningError extends Error {
  constructor(public readonly status: string) {
    super(`Scan is still ${status}; cancel it first`);
  }
}

/**
 * Delete a scan_run and its artifact files. Refuses to delete when the run
 * is the scope's current `lastScanRunId` (the run anchoring the scope's
 * truth set — see CLAUDE.md "Scan trustworthiness gates remediation logic").
 * Refuses to delete a pending/running scan; cancel it first.
 *
 * On success: scan_run row is removed (cascades sbom_components,
 * scan_findings, scan_run_components, etc.). The artifact files (SBOM + SARIF
 * on disk) are deleted best-effort — a filesystem-side failure logs a warning
 * but doesn't undo the DB delete (DB is authoritative).
 *
 * Note: rows on sast_issues / sca_issues whose `lastSeenScanRunId` happens
 * to match the deleted run will point at a dangling UUID afterwards. The
 * scope.lastScanRunId guard above ensures the *latest* scan is never the
 * deleted one, so most such rows will already point to a newer scan. Any
 * that don't will be re-anchored by the next scan. No active re-anchor here.
 */
export async function deleteScanRun(scanRunId: string, orgId: string | null): Promise<void> {
  const run = await prisma.scanRun.findFirst({
    where: { id: scanRunId, orgId: orgId ?? null },
    select: { id: true, scopeId: true, status: true },
  });
  if (!run) throw new ScanRunNotFoundError();

  if (run.status === "pending" || run.status === "running") {
    throw new ScanStillRunningError(run.status);
  }

  const scope = await prisma.scanScope.findUnique({
    where: { id: run.scopeId },
    select: { id: true, lastScanRunId: true },
  });
  if (scope?.lastScanRunId === run.id) {
    throw new ScanIsCurrentLatestError(scope.id, run.id);
  }

  await prisma.scanRun.delete({ where: { id: run.id } });

  await deleteScanArtifacts(run.id).catch((err: unknown) => {
    console.warn("[scanService] artifact cleanup failed for scan", run.id, err);
  });
}
