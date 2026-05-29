import { useNavigate } from "react-router-dom";
import { CheckCircle2, Clock, Layers, Loader2 } from "lucide-react";

import { useScopes } from "@/api/queries/scopes";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatDate, formatRelative } from "@/lib/format";
import { SeverityCountChips } from "@/components/SeverityCountChips";
import type { ActiveScan } from "@/api/types";
import { SCAN_PHASE_LABELS, SCAN_PHASE_UNITS, SCAN_PHASE_CAPS } from "@/api/types";

function ActiveScanCell({ scan }: { scan: ActiveScan }) {
  const phaseLabel = scan.current_phase
    ? (scan.phase_progress?.label ?? SCAN_PHASE_LABELS[scan.current_phase])
    : "Starting…";
  const progress = scan.phase_progress;
  const unit = scan.current_phase ? SCAN_PHASE_UNITS[scan.current_phase] : undefined;
  const isCap = scan.current_phase ? SCAN_PHASE_CAPS.has(scan.current_phase) : false;
  return (
    <div className="inline-flex flex-col items-end gap-0.5">
      <span className="inline-flex items-center gap-1 text-amber-600 dark:text-amber-400 font-medium">
        <Loader2 className="h-3 w-3 animate-spin" />
        {phaseLabel}
      </span>
      {progress && progress.total > 0 && (
        <span className="text-[10px] text-muted-foreground">
          {progress.done}/{progress.total}{unit ? ` ${unit}` : ""}
          {isCap ? " (max)" : ` · ${Math.round((progress.done / progress.total) * 100)}%`}
        </span>
      )}
    </div>
  );
}

export default function ScopesPage() {
  useDocumentTitle("Scopes — SASTBot");
  const { data: scopes, isLoading, isError } = useScopes();
  const navigate = useNavigate();

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Scopes</h1>
        <p className="text-sm text-muted-foreground">
          All scan scopes — one row per repo + path combination.
        </p>
      </div>

      {isError && (
        <p className="text-sm text-destructive">Failed to load scopes.</p>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : !scopes || scopes.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center text-sm text-muted-foreground">
            No scopes yet. Add a repository and trigger a scan to get started.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="pb-0">
            <CardTitle className="text-base flex items-center gap-2">
              <Layers className="h-4 w-4" />
              {scopes.length} scope{scopes.length !== 1 ? "s" : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-4">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Repo · Branch · Path</TableHead>
                  <TableHead className="text-right">Last scan</TableHead>
                  <TableHead className="text-right">Findings</TableHead>
                  <TableHead className="text-right">SCA</TableHead>
                  <TableHead className="text-right">SAST</TableHead>
                  <TableHead className="text-right">Pending</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scopes.map((scope) => (
                  <TableRow
                    key={scope.id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => navigate(`/scopes/${scope.id}`)}
                  >
                    <TableCell>
                      <div className="font-medium">{scope.repo_name}</div>
                      <div className="text-xs text-muted-foreground">
                        {scope.repo_branch}
                        {scope.path !== "/" ? ` · ${scope.path}` : ""}
                      </div>
                    </TableCell>
                    <TableCell className="text-right text-xs">
                      {scope.active_scan ? (
                        <ActiveScanCell scan={scope.active_scan} />
                      ) : scope.last_scan_completed_at ? (
                        <span className="text-muted-foreground" title={formatDate(scope.last_scan_completed_at)}>
                          {formatRelative(scope.last_scan_completed_at)}
                        </span>
                      ) : (
                        <span className="italic text-muted-foreground">never</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end">
                        {scope.critical_count + scope.high_count + scope.medium_count + scope.low_count === 0 ? (
                          <CheckCircle2 className="h-4 w-4 text-muted-foreground/40" />
                        ) : (
                          <SeverityCountChips
                            critical={scope.critical_count}
                            high={scope.high_count}
                            medium={scope.medium_count}
                            low={scope.low_count}
                          />
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-right text-sm">
                      {scope.active_sca_issue_count}
                    </TableCell>
                    <TableCell className="text-right text-sm">
                      {scope.active_sast_issue_count}
                    </TableCell>
                    <TableCell className="text-right">
                      {scope.pending_triage_count > 0 ? (
                        <Badge variant="outline" className="gap-1 text-amber-600 border-amber-400">
                          <Clock className="h-3 w-3" />
                          {scope.pending_triage_count}
                        </Badge>
                      ) : (
                        <CheckCircle2 className="ml-auto h-4 w-4 text-muted-foreground/40" />
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
