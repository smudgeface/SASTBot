import { FileSearch } from "lucide-react";
import { useMemo } from "react";

import { useRepos } from "@/api/queries/repos";
import { useScans } from "@/api/queries/scans";
import type { ScanStatus } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

const STATUS_STYLE: Record<ScanStatus, string> = {
  pending: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-200",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200",
  success: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/50 dark:text-emerald-200",
  failed: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
};

function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <Badge variant="secondary" className={cn("uppercase", STATUS_STYLE[status])}>
      {status}
    </Badge>
  );
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString();
}

function formatDuration(startedAt: string | null, finishedAt: string | null): string {
  if (!startedAt) return "—";
  const start = new Date(startedAt).getTime();
  const end = finishedAt ? new Date(finishedAt).getTime() : Date.now();
  const s = Math.max(0, Math.round((end - start) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m ${r}s`;
}

export default function ScansPage() {
  const scans = useScans();
  const repos = useRepos();

  // Repo name lookup so the table reads nicely instead of UUIDs.
  const repoNameById = useMemo(() => {
    const m = new Map<string, string>();
    repos.data?.forEach((r) => m.set(r.id, r.name));
    return m;
  }, [repos.data]);

  const items = scans.data ?? [];
  const empty = !scans.isLoading && items.length === 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Scan Results</h1>
        <p className="text-sm text-muted-foreground">All scans run across your repositories.</p>
      </div>

      {scans.isLoading ? (
        <Card>
          <CardContent className="p-8 text-sm text-muted-foreground">Loading…</CardContent>
        </Card>
      ) : null}

      {empty ? (
        <Card>
          <CardHeader className="flex flex-row items-center gap-3">
            <FileSearch className="h-5 w-5 text-muted-foreground" />
            <div>
              <CardTitle>No scans yet</CardTitle>
              <CardDescription>
                Add a repository and trigger a scan from its row menu.
              </CardDescription>
            </div>
          </CardHeader>
        </Card>
      ) : null}

      {items.length > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Repository</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead>Error</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((scan) => (
                <TableRow key={scan.id}>
                  <TableCell className="font-medium">
                    {repoNameById.get(scan.repo_id) ?? scan.repo_id}
                  </TableCell>
                  <TableCell>
                    <StatusBadge status={scan.status} />
                  </TableCell>
                  <TableCell className="text-muted-foreground uppercase text-xs">
                    {scan.triggered_by}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatTimestamp(scan.started_at ?? scan.created_at)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDuration(scan.started_at, scan.finished_at)}
                  </TableCell>
                  <TableCell className="text-destructive text-xs">
                    {scan.error ?? ""}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      ) : null}
    </div>
  );
}
