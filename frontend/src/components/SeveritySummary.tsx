// Stacked-bar severity summary card — used as the headline panel on both
// /scopes/:id and /scans/:id. Shows total open issues, a proportional bar,
// per-severity legend, and a footer of secondary counts (SCA / SAST /
// optional Components / optional Pending triage).
//
// Footer items are independently optional: pass undefined to omit. SAST
// and SCA are required since both call sites have them; Components is
// shown alongside on /scans/:id where the scan exposes a per-run total;
// Pending is only meaningful for the scope view (it counts triage state
// across runs).

import { CheckCircle2, Clock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";

const SEVERITY_BAR_COLOR: Record<"critical" | "high" | "medium" | "low", string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
};

export function SeveritySummary({
  critical,
  high,
  medium,
  low,
  sca,
  sast,
  components,
  pending,
}: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  sca: number;
  sast: number;
  /** Optional — shown alongside SCA / SAST on the scan view. */
  components?: number;
  /** Optional — pending triage count, shown only on the scope view. */
  pending?: number;
}) {
  const total = critical + high + medium + low;
  const segments: { key: "critical" | "high" | "medium" | "low"; label: string; count: number }[] = [
    { key: "critical", label: "Critical", count: critical },
    { key: "high",     label: "High",     count: high },
    { key: "medium",   label: "Medium",   count: medium },
    { key: "low",      label: "Low",      count: low },
  ];

  return (
    <Card>
      <CardContent className="px-5 py-4 space-y-3">
        {total === 0 ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            No open issues.
          </div>
        ) : (
          <>
            <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
              {segments.filter(s => s.count > 0).map((s) => (
                <div
                  key={s.key}
                  className={SEVERITY_BAR_COLOR[s.key]}
                  style={{ width: `${(s.count / total) * 100}%` }}
                  title={`${s.count} ${s.label}`}
                />
              ))}
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold leading-none">{total}</span>
              <span className="text-sm text-muted-foreground">Open Issues</span>
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
              {segments.map((s) => (
                <span key={s.key} className="inline-flex items-center gap-1.5">
                  <span className={`inline-block h-2.5 w-2.5 rounded-sm ${SEVERITY_BAR_COLOR[s.key]} ${s.count === 0 ? "opacity-30" : ""}`} />
                  <span className={s.count === 0 ? "text-muted-foreground/60" : ""}>
                    {s.count} {s.label}
                  </span>
                </span>
              ))}
            </div>
          </>
        )}
        <div className="flex flex-wrap gap-x-4 gap-y-1 pt-2 text-xs text-muted-foreground border-t">
          <span><span className="font-medium text-foreground">{sca}</span> SCA</span>
          <span><span className="font-medium text-foreground">{sast}</span> SAST</span>
          {components != null && (
            <span><span className="font-medium text-foreground">{components}</span> Components</span>
          )}
          {pending != null && pending > 0 && (
            <span className="inline-flex items-center gap-1">
              <Clock className="h-3 w-3 text-amber-500" />
              <span className="font-medium text-foreground">{pending}</span> Pending triage
            </span>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
