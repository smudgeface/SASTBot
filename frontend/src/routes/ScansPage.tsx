import { FileSearch } from "lucide-react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useMe } from "@/api/queries/auth";
import { useRepos } from "@/api/queries/repos";
import { useScans, useCancelScan } from "@/api/queries/scans";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatDate } from "@/lib/format";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { SeverityCountChips } from "@/components/SeverityCountChips";

const PAGE_SIZE = 50;

function Pager({
  page,
  pageSize,
  total,
  onPage,
}: {
  page: number;
  pageSize: number;
  total: number;
  onPage: (p: number) => void;
}) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 px-1">
      <span>
        {(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}
      </span>
      <div className="flex gap-1">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          ‹
        </Button>
        <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>
          ›
        </Button>
      </div>
    </div>
  );
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
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const scans = useScans({ page, page_size: PAGE_SIZE });
  const repos = useRepos();
  const { data: user } = useMe();
  const isAdmin = user?.role === "admin";
  const cancelScan = useCancelScan();

  const repoNameById = useMemo(() => {
    const m = new Map<string, string>();
    repos.data?.items.forEach((r) => m.set(r.id, r.name));
    return m;
  }, [repos.data]);

  const items = scans.data?.items ?? [];
  const total = scans.data?.total ?? 0;
  const empty = !scans.isLoading && total === 0;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Scan Results</h1>
        <p className="text-sm text-muted-foreground">All scans run across your repositories. Click a row to view findings.</p>
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
          <CardHeader className="pb-0">
            <CardTitle className="text-base flex items-center gap-2">
              <FileSearch className="h-4 w-4" />
              {total} scan{total !== 1 ? "s" : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Repository</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Components</TableHead>
                <TableHead>Trigger</TableHead>
                <TableHead>Started</TableHead>
                <TableHead>Duration</TableHead>
                <TableHead className="w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((scan) => {
                const isActive = scan.status === "pending" || scan.status === "running";
                return (
                <TableRow
                  key={scan.id}
                  className="cursor-pointer hover:bg-muted/50"
                  onClick={() => navigate(`/scans/${scan.id}`)}
                >
                  <TableCell className="font-medium">
                    {repoNameById.get(scan.repo_id) ?? scan.repo_id}
                    {scan.scope_path && scan.scope_path !== "/" ? (
                      <span className="ml-1 text-xs text-muted-foreground font-mono">
                        {scan.scope_path}
                      </span>
                    ) : null}
                  </TableCell>
                  <TableCell>
                    <ScanStatusBadge status={scan.status} />
                  </TableCell>
                  <TableCell>
                    <SeverityCountChips
                      critical={scan.critical_count}
                      high={scan.high_count}
                      medium={scan.medium_count}
                      low={scan.low_count}
                    />
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {scan.component_count > 0 ? scan.component_count : "—"}
                  </TableCell>
                  <TableCell className="text-muted-foreground uppercase text-xs">
                    {scan.triggered_by}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDate(scan.started_at ?? scan.created_at)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDuration(scan.started_at, scan.finished_at)}
                  </TableCell>
                  <TableCell>
                    {isAdmin && isActive && (
                      <button
                        type="button"
                        className="text-xs text-destructive hover:underline disabled:opacity-50"
                        disabled={cancelScan.isPending}
                        onClick={(e) => { e.stopPropagation(); cancelScan.mutate(scan.id); }}
                      >
                        Cancel
                      </button>
                    )}
                  </TableCell>
                </TableRow>
                );
              })}
            </TableBody>
          </Table>
          <Pager page={page} pageSize={PAGE_SIZE} total={total} onPage={setPage} />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
