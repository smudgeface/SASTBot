// Pill badge for a scan run's status (pending / running / success / failed
// / cancelled). Used on the scans-list table and on the scan-detail header.
//
// Distinct from the issue-level triage StatusBadge in ScopeDetailPage
// (pending / confirmed / planned / fixed / suppressed / false_positive) —
// different status enum, different lifecycle. Keep both, name them so they
// don't get confused.

import type { ScanStatus } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const STATUS_STYLE: Record<ScanStatus, string> = {
  pending:   "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
  running:   "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200",
  success:   "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200",
  failed:    "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
  cancelled: "bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
};

const STATUS_LABEL: Record<ScanStatus, string> = {
  pending:   "pending",
  running:   "running",
  success:   "complete",
  failed:    "failed",
  cancelled: "cancelled",
};

export function ScanStatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  return (
    <Badge variant="secondary" className={cn("uppercase", STATUS_STYLE[status], className)}>
      {STATUS_LABEL[status]}
    </Badge>
  );
}
