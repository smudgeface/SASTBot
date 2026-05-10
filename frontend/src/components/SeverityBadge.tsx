// Canonical severity rendering — one palette, one badge shape used across
// the app. The palette is the vivid `bg-X-500/20 text-X-600 border-X-400`
// scheme (matches the stacked-bar colors in the scope summary card). All
// other severity-tinted UI (filter buttons, finding chips, summary card
// numbers, severity chips on findings columns) reads from the same map via
// `severityClass()` so the palette stays in one place.

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-600 border-red-400",
  high:     "bg-orange-500/20 text-orange-600 border-orange-400",
  medium:   "bg-yellow-500/20 text-yellow-600 border-yellow-400",
  low:      "bg-blue-500/20 text-blue-600 border-blue-400",
  info:     "bg-slate-500/20 text-slate-600 border-slate-400",
  unknown:  "bg-slate-500/20 text-slate-500 border-slate-300",
};

/** Full `bg-X text-Y border-Z` triple for the given severity. Used by code
 *  that styles non-Badge elements (filter buttons, finding-count chips,
 *  components-tab finding chips). */
export function severityClass(severity: string | null | undefined): string {
  const key = (severity ?? "unknown").toLowerCase();
  return SEVERITY_COLORS[key] ?? SEVERITY_COLORS.unknown;
}

/** Just the text-color class — for places that apply color to text without
 *  also applying a chip background (the SummaryCard number on the scan
 *  detail page). */
export function severityTextClass(severity: string | null | undefined): string {
  const cls = severityClass(severity);
  return cls.split(" ").find((c) => c.startsWith("text-")) ?? "";
}

/** The canonical severity pill — rounded-full outline Badge with the vivid
 *  palette and `text-[10px] uppercase`. Use this for any "severity word"
 *  label on a row. For severity-tinted aggregate chips like `C:5 H:12`,
 *  use `severityClass()` directly. */
export function SeverityBadge({
  severity,
  className,
}: {
  severity: string;
  className?: string;
}) {
  return (
    <Badge
      variant="outline"
      className={cn("uppercase text-[10px] px-1.5", severityClass(severity), className)}
    >
      {severity}
    </Badge>
  );
}
