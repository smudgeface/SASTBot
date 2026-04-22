import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Download,
  Package,
  ShieldAlert,
} from "lucide-react";

import { useScanDetail, useScanFindings } from "@/api/queries/scans";
import { useRepos } from "@/api/queries/repos";
import type { FindingSeverity, ScanFinding } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
import { severityChipClass, formatDate } from "@/lib/format";

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

function sortFindings(findings: ScanFinding[]): ScanFinding[] {
  return [...findings].sort((a, b) => {
    const so = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (so !== 0) return so;
    return (b.cvss_score ?? 0) - (a.cvss_score ?? 0);
  });
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase",
        severityChipClass(severity),
      )}
    >
      {severity}
    </span>
  );
}

function SummaryCard({
  label,
  value,
  severity,
}: {
  label: string;
  value: number;
  severity?: FindingSeverity;
}) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs uppercase text-muted-foreground mb-1">{label}</p>
        <p
          className={cn(
            "text-2xl font-bold",
            severity ? severityChipClass(severity).split(" ").find((c) => c.startsWith("text-")) : "",
          )}
        >
          {value}
        </p>
      </CardContent>
    </Card>
  );
}

function FindingRow({ finding }: { finding: ScanFinding }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <>
      <TableRow
        className="cursor-pointer hover:bg-muted/50"
        onClick={() => setExpanded((x) => !x)}
      >
        <TableCell className="w-4">
          {expanded ? (
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
          )}
        </TableCell>
        <TableCell>
          <SeverityBadge severity={finding.severity} />
        </TableCell>
        <TableCell className="font-medium">
          {finding.component_name}
          {finding.component_version ? (
            <span className="ml-1 text-xs text-muted-foreground">
              @{finding.component_version}
            </span>
          ) : null}
        </TableCell>
        <TableCell className="font-mono text-xs">
          {finding.cve_id ?? finding.osv_id}
        </TableCell>
        <TableCell className="text-muted-foreground text-sm">
          {finding.cvss_score != null ? finding.cvss_score.toFixed(1) : "—"}
        </TableCell>
        <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
          {finding.summary ?? "—"}
        </TableCell>
      </TableRow>
      {expanded ? (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 py-3 px-6">
            <div className="space-y-2 text-sm">
              {finding.summary ? (
                <p>{finding.summary}</p>
              ) : null}
              <div className="flex flex-wrap gap-1">
                {finding.aliases.map((a) => (
                  <Badge key={a} variant="outline" className="font-mono text-xs">
                    {a}
                  </Badge>
                ))}
              </div>
              {finding.cvss_vector ? (
                <p className="font-mono text-xs text-muted-foreground">
                  {finding.cvss_vector}
                </p>
              ) : null}
            </div>
          </TableCell>
        </TableRow>
      ) : null}
    </>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const scan = useScanDetail(id);
  const findings = useScanFindings(id);
  const repos = useRepos();

  const repoName = repos.data?.find((r) => r.id === scan.data?.repo_id)?.name;
  const sorted = sortFindings(findings.data ?? []);

  if (scan.isLoading) {
    return (
      <div className="p-8 text-sm text-muted-foreground">Loading scan…</div>
    );
  }

  if (!scan.data) {
    return (
      <div className="p-8 text-sm text-destructive">Scan not found.</div>
    );
  }

  const s = scan.data;
  const isTerminal = s.status === "success" || s.status === "failed";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <Link
            to="/scans"
            className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> All scans
          </Link>
          <h1 className="text-xl font-semibold tracking-tight">
            {repoName ?? s.repo_id}
          </h1>
          <p className="text-sm text-muted-foreground">
            {formatDate(s.started_at ?? s.created_at)}
            {s.finished_at ? ` · ${formatDuration(s.started_at, s.finished_at)}` : ""}
            {" · "}
            <span
              className={cn(
                "uppercase font-medium",
                s.status === "failed" ? "text-destructive" : "",
                s.status === "success" ? "text-emerald-600 dark:text-emerald-400" : "",
              )}
            >
              {s.status}
            </span>
          </p>
        </div>
        {isTerminal && s.status === "success" ? (
          <Button asChild variant="outline" size="sm" className="gap-1.5">
            <a href={`/scans/${id}/sbom`} download>
              <Download className="h-4 w-4" /> Download SBOM
            </a>
          </Button>
        ) : null}
      </div>

      {/* Error banner */}
      {s.error ? (
        <Card className="border-destructive/50">
          <CardContent className="p-4 flex gap-2 text-sm text-destructive">
            <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
            {s.error}
          </CardContent>
        </Card>
      ) : null}

      {/* Summary cards */}
      {isTerminal && s.status === "success" ? (
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          <SummaryCard label="Components" value={s.component_count} />
          <SummaryCard label="Critical" value={s.critical_count} severity="critical" />
          <SummaryCard label="High" value={s.high_count} severity="high" />
          <SummaryCard label="Medium" value={s.medium_count} severity="medium" />
          <SummaryCard label="Low" value={s.low_count} severity="low" />
        </div>
      ) : null}

      {/* Findings table */}
      {isTerminal && s.status === "success" ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-muted-foreground" />
            <h2 className="font-medium">
              Findings
              {sorted.length > 0 ? (
                <span className="ml-1 text-muted-foreground font-normal text-sm">
                  ({sorted.length})
                </span>
              ) : null}
            </h2>
          </div>

          {findings.isLoading ? (
            <Card>
              <CardContent className="p-6 text-sm text-muted-foreground">
                Loading findings…
              </CardContent>
            </Card>
          ) : sorted.length === 0 ? (
            <Card>
              <CardContent className="p-6 flex items-center gap-3 text-sm text-muted-foreground">
                <Package className="h-4 w-4 shrink-0" />
                No vulnerabilities found in this scan.
              </CardContent>
            </Card>
          ) : (
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-4" />
                    <TableHead className="w-28">Severity</TableHead>
                    <TableHead>Package</TableHead>
                    <TableHead>CVE / ID</TableHead>
                    <TableHead className="w-16">CVSS</TableHead>
                    <TableHead>Summary</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sorted.map((f) => (
                    <FindingRow key={f.id} finding={f} />
                  ))}
                </TableBody>
              </Table>
            </Card>
          )}
        </div>
      ) : null}

      {/* Running / pending state */}
      {!isTerminal ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Scan in progress…
            </CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            This page auto-refreshes. Results will appear once the scan
            completes.
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function formatDuration(
  startedAt: string | null,
  finishedAt: string | null,
): string {
  if (!startedAt) return "";
  const start = new Date(startedAt).getTime();
  const end = finishedAt ? new Date(finishedAt).getTime() : Date.now();
  const s = Math.max(0, Math.round((end - start) / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m ${r}s`;
}
