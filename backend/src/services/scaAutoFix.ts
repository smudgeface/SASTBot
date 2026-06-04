import { type Prisma, type PrismaClient } from "@prisma/client";

type Tx = PrismaClient | Prisma.TransactionClient;

/** Statuses the auto-fix sweep must never overwrite — they're operator/terminal
 *  decisions. `fixed` is included so a re-run doesn't churn already-resolved rows. */
const TERMINAL_SCA_STATUSES = ["fixed", "suppressed", "false_positive"];

export interface ScaSweepDecision {
  /** True when the sweep ran and marked the targeted findings "fixed". */
  swept: boolean;
  /** Findings re-detected this run (lastSeenScanRunId === scanRunId). */
  detectedThisRun: number;
  /** Active, non-terminal findings from prior runs the sweep would target. */
  activeToSweep: number;
  /** True when the run was degenerate and the sweep was deliberately withheld. */
  degenerate: boolean;
}

/**
 * Backstop guard for the SCA auto-fix sweep. The sweep marks every active
 * finding not re-detected this run as "fixed", on the theory that "a manifest
 * entry that disappears IS the resolution". That theory only holds when the
 * scan actually detected a representative set. A scan that analyzed a populated
 * component set yet detected ZERO findings, while prior scans left active
 * findings on the scope, is degenerate: either a silent degradation (OSV
 * returned empty 200s / was rate-limited, augmentation dropped everything) or a
 * genuine full-remediation. Both deserve a human's eyes rather than a silent
 * mass-fix — telling an operator a CVE is fixed when it isn't is this tool's
 * worst failure mode, and the cost of withholding (stale-but-visible findings)
 * is far smaller than the cost of a false "fixed".
 *
 * Returns true when the sweep should be withheld and the scan marked
 * untrustworthy.
 */
export function isDegenerateScaSweep(
  detectedThisRun: number,
  activeToSweep: number,
  analyzedComponentCount: number,
): boolean {
  return detectedThisRun === 0 && activeToSweep > 0 && analyzedComponentCount > 0;
}

/**
 * Mark every active SCA finding not re-detected this run as "fixed" — UNLESS
 * the run is degenerate (analyzed components but detected nothing), in which
 * case the sweep is withheld and the returned decision signals the caller to
 * mark the scan untrustworthy. The caller is responsible for the
 * `hasErrorWarnings` gate (skip calling this entirely when the scan already has
 * error warnings) and for emitting the operator-facing warning on a degenerate
 * decision.
 */
export async function runScaAutoFixSweep(
  client: Tx,
  args: { scopeId: string; scanRunId: string; analyzedComponentCount: number },
): Promise<ScaSweepDecision> {
  const { scopeId, scanRunId, analyzedComponentCount } = args;
  const sweepWhere = {
    scopeId,
    lastSeenScanRunId: { not: scanRunId },
    dismissedStatus: { notIn: TERMINAL_SCA_STATUSES },
  };

  const detectedThisRun = await (client as PrismaClient).scaIssue.count({
    where: { scopeId, lastSeenScanRunId: scanRunId },
  });
  const activeToSweep = await (client as PrismaClient).scaIssue.count({ where: sweepWhere });

  if (isDegenerateScaSweep(detectedThisRun, activeToSweep, analyzedComponentCount)) {
    return { swept: false, detectedThisRun, activeToSweep, degenerate: true };
  }

  await (client as PrismaClient).scaIssue.updateMany({
    where: sweepWhere,
    data: { dismissedStatus: "fixed" },
  });
  return { swept: true, detectedThisRun, activeToSweep, degenerate: false };
}
