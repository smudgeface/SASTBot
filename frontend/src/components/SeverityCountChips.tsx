// Aggregate severity-count chips: `C:42 H:118 M:6 L:2`. Used to summarize
// findings on list pages. One chip per non-zero severity, color from the
// shared severity palette.
//
// Distinct from <SeverityBadge> (which is the rounded-full pill rendering a
// single severity word for a row): these are squared chips with both the
// initial and the count, used to show aggregates.

import { cn } from "@/lib/utils";
import { severityClass } from "@/components/SeverityBadge";

export function SeverityCountChips({
  critical,
  high,
  medium,
  low,
}: {
  critical: number;
  high: number;
  medium: number;
  low: number;
}) {
  const total = critical + high + medium + low;
  if (total === 0) return <span className="text-muted-foreground text-xs">—</span>;

  const chips: { label: string; count: number; sev: string }[] = [];
  if (critical > 0) chips.push({ label: "C", count: critical, sev: "critical" });
  if (high > 0) chips.push({ label: "H", count: high, sev: "high" });
  if (medium > 0) chips.push({ label: "M", count: medium, sev: "medium" });
  if (low > 0) chips.push({ label: "L", count: low, sev: "low" });

  return (
    <span className="inline-flex gap-1">
      {chips.map(({ label, count, sev }) => (
        <span
          key={label}
          className={cn(
            "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold",
            severityClass(sev),
          )}
        >
          {label}:{count}
        </span>
      ))}
    </span>
  );
}
