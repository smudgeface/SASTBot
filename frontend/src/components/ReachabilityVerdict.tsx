import { Button } from "@/components/ui/button";

// Reachability verdict — read-only by default. Pass `admin` props to enable
// the inline "Mark Invalid / Won't fix" CTA shown when the LLM returned a
// high-confidence "Not reachable" verdict on a still-open issue. The scope
// detail page wires up `admin`; the scan detail page does not (audit view).

export type ReachabilityCallSite = { file: string; line: number; snippet: string };

export interface ReachabilityFields {
  confirmed_reachable: boolean;
  reachable_confidence: number | null;
  reachable_reasoning: string | null;
  reachable_call_sites: ReachabilityCallSite[] | null;
  reachable_model: string | null;
}

const HIGH_CONFIDENCE_DISMISS_THRESHOLD = 0.85;

export function ReachabilityVerdict({
  fields,
  sourceUrlTemplate,
  FileLink,
  admin,
}: {
  fields: ReachabilityFields;
  sourceUrlTemplate: string | null | undefined;
  /** Caller injects its own FileLink renderer (the implementation lives in
   *  each page module and pulls from a slightly different template helper). */
  FileLink: React.ComponentType<{
    template: string | null | undefined;
    file: string;
    line?: number | null;
    className?: string;
    children: React.ReactNode;
  }>;
  /** When omitted, the high-confidence dismiss CTA is hidden — the verdict
   *  is purely informational (e.g. on the scan detail page audit view). */
  admin?: {
    isOpen: boolean;
    isPending: boolean;
    onDismiss: (status: "false_positive" | "suppressed") => void;
  };
}) {
  const reachable = fields.confirmed_reachable;
  const conf = fields.reachable_confidence;
  const sites = fields.reachable_call_sites ?? [];

  const hasStructuredVerdict = conf !== null;
  const highConfidenceNotReachable =
    hasStructuredVerdict && !reachable && conf! >= HIGH_CONFIDENCE_DISMISS_THRESHOLD;

  const tone = reachable
    ? "border-amber-400 bg-amber-50 dark:bg-amber-950/30"
    : "border-emerald-400 bg-emerald-50 dark:bg-emerald-950/30";

  const headlineColor = reachable
    ? "text-amber-700 dark:text-amber-400"
    : "text-emerald-700 dark:text-emerald-400";

  return (
    <div className={`rounded-md border ${tone} px-3 py-2 space-y-2`}>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className={`text-sm font-semibold ${headlineColor}`}>
          {reachable ? "Reachable" : "Not reachable"}
        </span>
        {hasStructuredVerdict && (
          <span className="text-xs text-muted-foreground">
            · {Math.round(conf! * 100)}% confident
          </span>
        )}
        <span className="text-[10px] text-muted-foreground/70 ml-auto">
          {fields.reachable_model && `via ${fields.reachable_model}`}
        </span>
      </div>
      {fields.reachable_reasoning && (
        <p className="text-xs">{fields.reachable_reasoning}</p>
      )}
      {sites.length > 0 && (
        <div className="space-y-1">
          {sites.slice(0, 5).map((s, i) => (
            <div key={i} className="rounded border bg-background text-xs font-mono overflow-x-auto">
              <div className="flex items-center justify-between px-2 py-1 border-b text-[10px] text-muted-foreground">
                <FileLink template={sourceUrlTemplate} file={s.file} line={s.line} className="truncate">
                  {s.file}
                </FileLink>
                <FileLink template={sourceUrlTemplate} file={s.file} line={s.line} className="ml-2 shrink-0">
                  line {s.line}
                </FileLink>
              </div>
              <pre className="px-2 py-1 whitespace-pre">{s.snippet}</pre>
            </div>
          ))}
        </div>
      )}
      {admin && admin.isOpen && highConfidenceNotReachable && (
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-emerald-200 dark:border-emerald-900/40">
          <span className="text-xs text-muted-foreground">
            High-confidence verdict — apply directly:
          </span>
          <Button size="sm" variant="outline" disabled={admin.isPending} onClick={() => admin.onDismiss("false_positive")}>
            Mark Invalid
          </Button>
          <Button size="sm" variant="outline" disabled={admin.isPending} onClick={() => admin.onDismiss("suppressed")}>
            Mark Won't fix
          </Button>
        </div>
      )}
    </div>
  );
}
