import { prisma } from "../db.js";
import { type ScanWarning } from "../schemas.js";

/** Returns true iff any error-severity warning has been recorded on this scan.
 *  An error warning means the scan should be marked `status=failed` at
 *  finalize; failed scans don't touch the scope (no pointer advance, no
 *  SCA sweep, no SAST recheck cleanup). M12 reframe: trustworthiness is
 *  collapsed into the lifecycle status — there is no per-subsystem
 *  partial-trust UX. */
export async function hasErrorWarnings(scanRunId: string): Promise<boolean> {
  const run = await prisma.scanRun.findUnique({
    where: { id: scanRunId },
    select: { warnings: true },
  });
  const list = Array.isArray(run?.warnings) ? (run!.warnings as ScanWarning[]) : [];
  return list.some((w) => w.severity === "error");
}
