import { Layers, ShieldCheck, Zap } from "lucide-react";

import { useScans } from "@/api/queries/scans";
import { useScopes } from "@/api/queries/scopes";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export default function DashboardPage() {
  useDocumentTitle("Dashboard — SASTBot");
  const scans = useScans();
  const scopes = useScopes();

  const scopeCount = scopes.data?.length ?? 0;

  const scansThisWeek = (() => {
    if (!scans.data) return null;
    const cutoff = Date.now() - ONE_WEEK_MS;
    return scans.data.items.filter((s) => new Date(s.created_at).getTime() >= cutoff).length;
  })();

  // Open findings across all scopes — summed from the scope list, which already
  // carries per-scope active issue + severity counts (no extra request).
  const findings = (() => {
    if (!scopes.data) return null;
    let open = 0;
    let critical = 0;
    let high = 0;
    for (const s of scopes.data) {
      open += s.active_sast_issue_count + s.active_sca_issue_count;
      critical += s.critical_count;
      high += s.high_count;
    }
    return { open, critical, high };
  })();

  const findingsHint = (() => {
    if (scopes.isError) return "Unable to load";
    if (!findings) return "Active issues across scopes";
    if (findings.open === 0) return "No open findings";
    if (findings.critical === 0 && findings.high === 0) return "Across all scopes";
    return `${findings.critical} critical · ${findings.high} high`;
  })();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Dashboard</h1>
        <p className="text-sm text-muted-foreground">
          A quick snapshot of your scanning posture.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <SummaryCard
          icon={Layers}
          title="Scopes"
          value={scopes.isLoading ? "—" : String(scopeCount)}
          hint={scopes.isError ? "Unable to load" : "Repo + path combinations"}
        />
        <SummaryCard
          icon={Zap}
          title="Scans this week"
          value={scans.isLoading || scansThisWeek === null ? "—" : String(scansThisWeek)}
          hint={scans.isError ? "Unable to load" : "In the last 7 days"}
        />
        <SummaryCard
          icon={ShieldCheck}
          title="Open findings"
          value={scopes.isLoading || findings === null ? "—" : String(findings.open)}
          hint={findingsHint}
        />
      </div>
    </div>
  );
}

interface SummaryCardProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  value: string;
  hint?: string;
}

function SummaryCard({ icon: Icon, title, value, hint }: SummaryCardProps) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between space-y-0 pb-2">
        <div>
          <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
          {hint ? <CardDescription className="mt-1 text-xs">{hint}</CardDescription> : null}
        </div>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold tabular-nums">{value}</div>
      </CardContent>
    </Card>
  );
}
