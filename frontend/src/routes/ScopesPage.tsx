import { useNavigate } from "react-router-dom";
import { AlertTriangle, CheckCircle2, Clock, Layers } from "lucide-react";

import { useScopes } from "@/api/queries/scopes";
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
import { formatRelative } from "@/lib/format";

function SeverityChip({ n, label }: { n: number; label: string }) {
  if (n === 0) return null;
  return (
    <span className="inline-flex items-center gap-0.5 rounded px-1.5 py-0.5 text-xs font-medium bg-destructive/15 text-destructive">
      {n} {label}
    </span>
  );
}

export default function ScopesPage() {
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
                  <TableHead className="text-right">Critical / High</TableHead>
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
                    <TableCell className="text-right text-xs text-muted-foreground">
                      {scope.last_scan_completed_at ? (
                        <span title={scope.last_scan_completed_at}>
                          {formatRelative(scope.last_scan_completed_at)}
                        </span>
                      ) : (
                        <span className="italic">never</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <SeverityChip n={scope.critical_count} label="C" />
                        <SeverityChip n={scope.high_count} label="H" />
                        {scope.critical_count === 0 && scope.high_count === 0 && (
                          <CheckCircle2 className="h-4 w-4 text-muted-foreground/40" />
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
