// Slot at the top of an issue's expanded panel for "this is more serious
// than the severity badge alone suggests" callouts. Today the only signal
// wired up is `actively_exploited` (CISA KEV) on SCA issues. Reserved for
// future SAST signals (e.g. KEV-mapped CWEs, high-confidence critical LLM
// findings).

import { ShieldAlert } from "lucide-react";

export function HighSeverityCallout({
  title,
  detail,
}: {
  title: string;
  detail: string;
}) {
  return (
    <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0" />
      <span>
        <span className="font-semibold">{title}</span>
        {" — "}
        {detail}
      </span>
    </div>
  );
}
