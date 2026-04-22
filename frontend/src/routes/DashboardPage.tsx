import { GitBranch, ShieldCheck, Zap } from "lucide-react";

import { useRepos } from "@/api/queries/repos";
import { useScans } from "@/api/queries/scans";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export default function DashboardPage() {
  const repos = useRepos();
  const scans = useScans();

  const repoCount = repos.data?.length ?? 0;

  const scansThisWeek = (() => {
    if (!scans.data) return null;
    const cutoff = Date.now() - ONE_WEEK_MS;
    return scans.data.filter((s) => new Date(s.created_at).getTime() >= cutoff).length;
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
          icon={GitBranch}
          title="Repositories"
          value={repos.isLoading ? "—" : String(repoCount)}
          hint={repos.isError ? "Unable to load" : "Registered for scanning"}
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
          value="—"
          hint="Available in M3"
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
