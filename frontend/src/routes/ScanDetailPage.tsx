import { useState } from "react";
import { useParams, Link } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  Download,
  FileCode2,
  Package,
  ShieldAlert,
} from "lucide-react";

import { useScanDetail, useScanComponents, useScanFindings, useSbomJson } from "@/api/queries/scans";
import { useRepos } from "@/api/queries/repos";
import type { FindingSeverity, SbomComponent, ScanFinding } from "@/api/types";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
// Vulnerability link helpers
// ---------------------------------------------------------------------------

function vulnUrl(id: string): string {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function VulnLink({ id }: { id: string }) {
  if (!id) return null;
  return (
    <a
      href={vulnUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      className="hover:underline text-blue-600 dark:text-blue-400"
    >
      {id}
    </a>
  );
}

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

function FindingTypeBadge({ finding }: { finding: ScanFinding }) {
  if (finding.finding_type === "eol") {
    return (
      <span className={cn(
        "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase",
        severityChipClass(finding.severity),
      )}>
        EOL
      </span>
    );
  }
  if (finding.finding_type === "deprecated") {
    return (
      <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-900">
        DEPRECATED
      </span>
    );
  }
  return <SeverityBadge severity={finding.severity} />;
}

function FindingRow({ finding }: { finding: ScanFinding }) {
  const [expanded, setExpanded] = useState(false);
  const isCve = finding.finding_type === "cve";

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
          <FindingTypeBadge finding={finding} />
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
          {isCve ? (
            <VulnLink id={finding.cve_id ?? finding.osv_id} />
          ) : (
            <span className="text-muted-foreground text-xs">
              {finding.finding_type === "eol" ? "End of Life" : "Deprecated"}
            </span>
          )}
        </TableCell>
        <TableCell className="text-muted-foreground text-sm">
          {isCve && finding.cvss_score != null ? finding.cvss_score.toFixed(1) : "—"}
        </TableCell>
        <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
          {finding.summary ?? "—"}
        </TableCell>
      </TableRow>
      {expanded ? (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 py-3 px-6">
            <div className="space-y-2 text-sm">
              {finding.summary ? <p>{finding.summary}</p> : null}
              {finding.eol_date ? (
                <p className="text-xs text-muted-foreground">
                  EOL date: <span className="font-medium">{finding.eol_date.slice(0, 10)}</span>
                </p>
              ) : null}
              {isCve && finding.aliases.length > 0 ? (
                <div className="flex flex-wrap gap-1">
                  {finding.aliases.map((a) => (
                    <a
                      key={a}
                      href={vulnUrl(a)}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="inline-flex"
                    >
                      <Badge variant="outline" className="font-mono text-xs hover:bg-muted cursor-pointer">
                        {a}
                      </Badge>
                    </a>
                  ))}
                </div>
              ) : null}
              {isCve && finding.cvss_vector ? (
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
// Components tab
// ---------------------------------------------------------------------------

function LicensePill({ license }: { license: string }) {
  return (
    <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-mono bg-muted text-muted-foreground">
      {license}
    </span>
  );
}

function ComponentsTab({
  components,
  findings,
  isLoading,
}: {
  components: SbomComponent[];
  findings: ScanFinding[];
  isLoading: boolean;
}) {
  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent>
      </Card>
    );
  }
  if (components.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 flex items-center gap-3 text-sm text-muted-foreground">
          <Package className="h-4 w-4 shrink-0" />
          No components found in this scan.
        </CardContent>
      </Card>
    );
  }

  // Index findings by component id for O(1) lookup.
  const findingsByComponent = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const list = findingsByComponent.get(f.component_id) ?? [];
    list.push(f);
    findingsByComponent.set(f.component_id, list);
  }

  return (
    <Card>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Package</TableHead>
            <TableHead>Version</TableHead>
            <TableHead>Ecosystem</TableHead>
            <TableHead>Licenses</TableHead>
            <TableHead>Findings</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {components.map((c) => {
            const allFindings = findingsByComponent.get(c.id) ?? [];
            const sorted = [...allFindings].sort(
              (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
            );
            return (
              <TableRow key={c.id}>
                <TableCell className="font-medium font-mono text-sm">{c.name}</TableCell>
                <TableCell className="text-sm text-muted-foreground font-mono">
                  {c.version ?? "—"}
                </TableCell>
                <TableCell className="text-sm text-muted-foreground uppercase text-xs">
                  {c.ecosystem ?? "—"}
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {c.licenses.length > 0
                      ? c.licenses.map((l) => <LicensePill key={l} license={l} />)
                      : <span className="text-xs text-muted-foreground">—</span>}
                  </div>
                </TableCell>
                <TableCell>
                  {sorted.length === 0 ? (
                    <span className="text-xs text-muted-foreground">—</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {sorted.map((f) => {
                        if (f.finding_type === "eol") {
                          return (
                            <span
                              key={f.id}
                              className={cn(
                                "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase",
                                severityChipClass(f.severity),
                              )}
                              title={f.summary ?? undefined}
                            >
                              EOL {f.eol_date ? f.eol_date.slice(0, 10) : ""}
                            </span>
                          );
                        }
                        if (f.finding_type === "deprecated") {
                          return (
                            <span
                              key={f.id}
                              className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-900"
                              title={f.summary ?? undefined}
                            >
                              DEPRECATED
                            </span>
                          );
                        }
                        return (
                          <a
                            key={f.id}
                            href={vulnUrl(f.cve_id ?? f.osv_id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className={cn(
                              "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase hover:opacity-80",
                              severityChipClass(f.severity),
                            )}
                            title={f.summary ?? f.cve_id ?? f.osv_id}
                          >
                            {f.cve_id ?? f.osv_id}
                          </a>
                        );
                      })}
                    </div>
                  )}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function downloadBlob(text: string, filename: string) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const scan = useScanDetail(id);
  const findings = useScanFindings(id);
  const components = useScanComponents(id);
  const repos = useRepos();
  const sbom = useSbomJson(id);

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
            {s.scope_path && s.scope_path !== "/" ? (
              <span className="ml-2 text-base font-normal text-muted-foreground font-mono">
                {s.scope_path}
              </span>
            ) : null}
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
              {s.status === "success" ? "complete" : s.status}
            </span>
          </p>
        </div>
        {isTerminal && s.status === "success" ? (
          <div className="flex gap-2">
            <Button asChild variant="outline" size="sm" className="gap-1.5">
              <Link to={`/scans/${id}/sbom`}>
                <FileCode2 className="h-4 w-4" /> View SBOM
              </Link>
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5"
              disabled={!sbom.data}
              onClick={() => {
                const repoName = repos.data?.find((r) => r.id === s.repo_id)?.name ?? "scan";
                downloadBlob(sbom.data!, `sbom-${repoName}-${(id ?? "").slice(0, 8)}.cdx.json`);
              }}
            >
              <Download className="h-4 w-4" /> Download SBOM
            </Button>
          </div>
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

      {/* Tabbed content: Findings + Components */}
      {isTerminal && s.status === "success" ? (
        <Tabs defaultValue="findings">
          <TabsList>
            <TabsTrigger value="findings" className="gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" />
              Findings
              {sorted.length > 0 ? (
                <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs font-mono">
                  {sorted.length}
                </span>
              ) : null}
            </TabsTrigger>
            <TabsTrigger value="components" className="gap-1.5">
              <Package className="h-3.5 w-3.5" />
              Components
              {s.component_count > 0 ? (
                <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs font-mono">
                  {s.component_count}
                </span>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="findings" className="mt-4">
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
          </TabsContent>

          <TabsContent value="components" className="mt-4">
            <ComponentsTab
              components={components.data ?? []}
              findings={findings.data ?? []}
              isLoading={components.isLoading}
            />
          </TabsContent>
        </Tabs>
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
