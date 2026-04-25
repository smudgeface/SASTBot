/**
 * Scan detail — demoted to an audit/debug view in M5.
 * Shows raw detection rows (SCA findings, SAST detections, components)
 * for a specific scan run. Triage and dismiss actions are on /scopes/:id.
 */
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
  ScanSearch,
  ShieldAlert,
} from "lucide-react";

import {
  useScanDetail,
  useScanComponents,
  useScanFindings,
  useSbomJson,
  useSastFindings,
} from "@/api/queries/scans";
import { useRepos } from "@/api/queries/repos";
import type { FindingSeverity, SastFinding, SbomComponent, ScanFinding } from "@/api/types";
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
import { TooltipProvider } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { severityChipClass, formatDate } from "@/lib/format";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function vulnUrl(id: string): string {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, unknown: 4,
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={cn(
      "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase",
      severityChipClass(severity),
    )}>
      {severity}
    </span>
  );
}

function basename(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] ?? path;
}

function buildSourceUrl(template: string | null | undefined, file: string, line?: number | null): string | null {
  if (!template) return null;
  return template
    .replace(/\$FILE/g, encodeURI(file))
    .replace(/\$LINE/g, line != null ? String(line) : "");
}

function FileLink({
  template,
  file,
  line,
  className,
  children,
}: {
  template: string | null | undefined;
  file: string;
  line?: number | null;
  className?: string;
  children: React.ReactNode;
}) {
  const url = buildSourceUrl(template, file, line);
  if (!url) return <span className={className}>{children}</span>;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className={cn("hover:underline hover:text-foreground", className)}
      onClick={(e) => e.stopPropagation()}
    >
      {children}
    </a>
  );
}

function SummaryCard({ label, value, severity }: { label: string; value: number; severity?: FindingSeverity }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs uppercase text-muted-foreground mb-1">{label}</p>
        <p className={cn("text-2xl font-bold", severity ? severityChipClass(severity).split(" ").find((c) => c.startsWith("text-")) : "")}>
          {value}
        </p>
      </CardContent>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// SCA findings tab (raw detections)
// ---------------------------------------------------------------------------

function FindingRow({
  finding,
  manifestFile,
  sourceUrlTemplate,
}: {
  finding: ScanFinding;
  manifestFile: string | null | undefined;
  sourceUrlTemplate: string | null | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const isCve = finding.finding_type === "cve";
  const summary = finding.summary
    ?? (finding.finding_type === "eol" ? "End of life" : finding.finding_type === "deprecated" ? "Deprecated package" : "—");

  return (
    <>
      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => setExpanded((x) => !x)}>
        <TableCell className="w-6">
          {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        </TableCell>
        <TableCell className="w-24"><SeverityBadge severity={finding.severity} /></TableCell>
        <TableCell className="text-sm">
          <div className="line-clamp-1">{summary}</div>
          <div className="text-xs text-muted-foreground font-mono mt-0.5">
            {finding.component_name}
            {finding.component_version && <span>@{finding.component_version}</span>}
          </div>
        </TableCell>
        <TableCell
          className="w-64 font-mono text-xs text-muted-foreground truncate"
          title={manifestFile ?? undefined}
        >
          {manifestFile ? basename(manifestFile) : "—"}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={4} className="bg-muted/30 py-3 px-6 space-y-2 text-sm">
            {finding.summary && <p>{finding.summary}</p>}
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground">
              <span className="font-mono">
                {finding.component_name}
                {finding.component_version && <span>@{finding.component_version}</span>}
              </span>
              {finding.component_scope === "optional" && (
                <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-[9px] font-semibold text-slate-500 border-slate-300">DEV</span>
              )}
              {isCve && (
                <a
                  href={vulnUrl(finding.cve_id ?? finding.osv_id)}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={(e) => e.stopPropagation()}
                  className="font-mono hover:underline text-blue-600 dark:text-blue-400"
                >
                  {finding.cve_id ?? finding.osv_id}
                </a>
              )}
              {finding.finding_type === "eol" && (
                <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-950 dark:text-orange-300">
                  End of Life
                </span>
              )}
              {finding.finding_type === "deprecated" && (
                <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase bg-amber-100 text-amber-800 border-amber-200">
                  Deprecated
                </span>
              )}
              {finding.has_fix && <span className="text-green-600 font-medium">✓ Fix available</span>}
            </div>
            {manifestFile && (
              <p className="text-xs">
                <span className="text-muted-foreground">Declared in </span>
                <FileLink template={sourceUrlTemplate} file={manifestFile} className="font-mono">
                  {manifestFile}
                </FileLink>
              </p>
            )}
            {finding.eol_date && <p className="text-xs text-muted-foreground">EOL date: {finding.eol_date.slice(0, 10)}</p>}
            {isCve && finding.aliases.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {finding.aliases.map((a) => (
                  <a key={a} href={vulnUrl(a)} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} className="inline-flex">
                    <Badge variant="outline" className="font-mono text-xs hover:bg-muted cursor-pointer">{a}</Badge>
                  </a>
                ))}
              </div>
            )}
            {isCve && finding.cvss_vector && (
              <p className="font-mono text-xs text-muted-foreground">{finding.cvss_vector}</p>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// SAST detections tab (raw detections, no triage actions)
// ---------------------------------------------------------------------------

function SastRow({
  finding,
  sourceUrlTemplate,
}: {
  finding: SastFinding;
  sourceUrlTemplate: string | null | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const summary = finding.rule_message ?? finding.rule_id.split(".").pop()?.replace(/-/g, " ") ?? finding.rule_id;

  return (
    <>
      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => setExpanded((x) => !x)}>
        <TableCell className="w-6">
          {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        </TableCell>
        <TableCell className="w-24"><SeverityBadge severity={finding.severity} /></TableCell>
        <TableCell className="text-sm text-muted-foreground line-clamp-1">{summary}</TableCell>
        <TableCell
          className="w-64 font-mono text-xs text-muted-foreground truncate"
          title={`${finding.file_path}:${finding.start_line}`}
        >
          {basename(finding.file_path)}:{finding.start_line}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={4} className="bg-muted/30 py-3 px-6 space-y-2">
            <p className="text-xs">
              <FileLink
                template={sourceUrlTemplate}
                file={finding.file_path}
                line={finding.start_line}
                className="font-mono"
              >
                {finding.file_path}:{finding.start_line}
              </FileLink>
            </p>
            {finding.snippet && (
              <pre className="rounded bg-background border p-3 text-xs overflow-x-auto font-mono whitespace-pre-wrap">{finding.snippet}</pre>
            )}
            {finding.rule_message && <p className="text-sm text-muted-foreground">{finding.rule_message}</p>}
            <p className="font-mono text-xs text-muted-foreground">{finding.rule_id}</p>
            {finding.cwe_ids.length > 0 && (
              <div className="flex gap-1">{finding.cwe_ids.map((c) => <Badge key={c} variant="outline" className="font-mono text-xs">{c}</Badge>)}</div>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Components tab
// ---------------------------------------------------------------------------

function ComponentsTab({ components, findings, isLoading }: {
  components: SbomComponent[];
  findings: ScanFinding[];
  isLoading: boolean;
}) {
  const [onlyWithFindings, setOnlyWithFindings] = useState(false);
  const findingsByComp = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const list = findingsByComp.get(f.component_id) ?? [];
    list.push(f);
    findingsByComp.set(f.component_id, list);
  }
  const withFindings = components.filter((c) => findingsByComp.has(c.id));
  const visible = onlyWithFindings ? withFindings : components;

  if (isLoading) return <Card><CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent></Card>;
  if (components.length === 0) return <Card><CardContent className="p-6 text-sm text-muted-foreground"><Package className="inline h-4 w-4 mr-1" />No components.</CardContent></Card>;

  return (
    <div className="space-y-3">
      {withFindings.length > 0 && (
        <label className="flex items-center gap-1.5 text-xs cursor-pointer select-none">
          <input type="checkbox" checked={onlyWithFindings} onChange={(e) => setOnlyWithFindings(e.target.checked)} className="rounded" />
          Only show components with findings ({withFindings.length})
        </label>
      )}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Package</TableHead>
              <TableHead>Version</TableHead>
              <TableHead>Ecosystem</TableHead>
              <TableHead>Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.map((c) => {
              const cFindings = [...(findingsByComp.get(c.id) ?? [])].sort(
                (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
              );
              return (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-sm">{c.name}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{c.version ?? "—"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground uppercase">{c.ecosystem ?? "—"}</TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {cFindings.length === 0 ? <span className="text-xs text-muted-foreground">—</span> : cFindings.map((f) => (
                        <span key={f.id} className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase", severityChipClass(f.severity))}>
                          {f.finding_type === "cve" ? (f.cve_id ?? f.osv_id) : f.finding_type.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

function downloadBlob(text: string, filename: string) {
  const blob = new Blob([text], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

export default function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const scan = useScanDetail(id);
  const findings = useScanFindings(id);
  const components = useScanComponents(id);
  const repos = useRepos();
  const sbom = useSbomJson(id);
  const sast = useSastFindings(id);

  const [scaSeverities, setScaSeverities] = useState<Set<string>>(new Set());
  const [scaTypes, setScaTypes]         = useState<Set<string>>(new Set());
  const [sastSeverities, setSastSeverities] = useState<Set<string>>(new Set());

  function toggleSet(current: Set<string>, value: string, setter: (s: Set<string>) => void) {
    const next = new Set(current);
    next.has(value) ? next.delete(value) : next.add(value);
    setter(next);
  }

  const repo = repos.data?.find((r) => r.id === scan.data?.repo_id);
  const repoName = repo?.name;
  const sourceUrlTemplate = repo?.source_url_template ?? null;
  const componentsById = new Map((components.data ?? []).map((c) => [c.id, c]));
  const allFindings = findings.data ?? [];
  const sortedFindings = [...allFindings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || (b.cvss_score ?? 0) - (a.cvss_score ?? 0),
  );
  const filteredFindings = sortedFindings.filter((f) => {
    if (scaSeverities.size > 0 && !scaSeverities.has(f.severity)) return false;
    if (scaTypes.size > 0 && !scaTypes.has(f.finding_type)) return false;
    return true;
  });

  const allSast = sast.data ?? [];
  const sortedSast = [...allSast].sort(
    (a, b) => (SEVERITY_ORDER[a.severity as FindingSeverity] ?? 9) - (SEVERITY_ORDER[b.severity as FindingSeverity] ?? 9),
  );
  const filteredSast = sastSeverities.size > 0
    ? sortedSast.filter((f) => sastSeverities.has(f.severity))
    : sortedSast;

  if (scan.isLoading) return <div className="p-8 text-sm text-muted-foreground">Loading scan…</div>;
  if (!scan.data) return <div className="p-8 text-sm text-destructive">Scan not found.</div>;

  const s = scan.data;
  const isTerminal = s.status === "success" || s.status === "failed";

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div className="space-y-1">
            <Link to="/scans" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
              <ArrowLeft className="h-3.5 w-3.5" /> All scans
            </Link>
            <h1 className="text-xl font-semibold tracking-tight">
              {repoName ?? s.repo_id}
              {s.scope_path && s.scope_path !== "/" && (
                <span className="ml-2 text-base font-normal text-muted-foreground font-mono">{s.scope_path}</span>
              )}
            </h1>
            <p className="text-sm text-muted-foreground">
              {formatDate(s.started_at ?? s.created_at)}
              {s.finished_at ? ` · ${formatDuration(s.started_at, s.finished_at)}` : ""}
              {" · "}
              <span className={cn("uppercase font-medium",
                s.status === "failed" ? "text-destructive" : "",
                s.status === "success" ? "text-emerald-600 dark:text-emerald-400" : "")}>
                {s.status === "success" ? "complete" : s.status}
              </span>
              {" · "}
              <span className="text-muted-foreground italic">Audit view — triage on the </span>
              <Link to={`/scopes/${s.scope_id}`} className="underline text-muted-foreground hover:text-foreground italic">scope page</Link>
            </p>
          </div>
          {isTerminal && s.status === "success" && (
            <div className="flex gap-2">
              <Button asChild variant="outline" size="sm" className="gap-1.5">
                <Link to={`/scans/${id}/sbom`}><FileCode2 className="h-4 w-4" /> View SBOM</Link>
              </Button>
              <Button variant="outline" size="sm" className="gap-1.5" disabled={!sbom.data}
                onClick={() => downloadBlob(sbom.data!, `sbom-${repoName ?? "scan"}-${(id ?? "").slice(0, 8)}.cdx.json`)}>
                <Download className="h-4 w-4" /> Download SBOM
              </Button>
            </div>
          )}
        </div>

        {/* Error / warning banners */}
        {s.error && (
          <Card className="border-destructive/50">
            <CardContent className="p-4 flex gap-2 text-sm text-destructive">
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />{s.error}
            </CardContent>
          </Card>
        )}
        {s.warnings && s.warnings.length > 0 && (
          <Card className="border-amber-200 dark:border-amber-900">
            <CardContent className="p-4 space-y-1">
              {s.warnings.map((w, i) => (
                <div key={i} className="flex gap-2 text-sm text-amber-700 dark:text-amber-300">
                  <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" /><span>{w.message}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        )}

        {/* Summary cards */}
        {isTerminal && s.status === "success" && (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <SummaryCard label="Components" value={s.component_count} />
            <SummaryCard label="Critical" value={s.critical_count} severity="critical" />
            <SummaryCard label="High" value={s.high_count} severity="high" />
            <SummaryCard label="Medium" value={s.medium_count} severity="medium" />
            <SummaryCard label="Low" value={s.low_count} severity="low" />
          </div>
        )}

        {/* Tabs */}
        {isTerminal && s.status === "success" && (
          <Tabs defaultValue="findings">
            <TabsList>
              <TabsTrigger value="findings" className="gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5" />Raw SCA Findings
                {allFindings.length > 0 && <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs">{allFindings.length}</span>}
              </TabsTrigger>
              <TabsTrigger value="sast" className="gap-1.5">
                <ScanSearch className="h-3.5 w-3.5" />Raw SAST Detections
                {s.sast_finding_count > 0 && <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs">{s.sast_finding_count}</span>}
              </TabsTrigger>
              <TabsTrigger value="components" className="gap-1.5">
                <Package className="h-3.5 w-3.5" />Components
                {s.component_count > 0 && <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs">{s.component_count}</span>}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="mt-4">
              {/* Filter bar — same pipe-group pattern as scope detail */}
              <div className="flex flex-wrap items-center gap-y-2 gap-x-0 mb-3">
                {(["critical", "high", "medium", "low"] as const).map((sev, i) => (
                  <div key={sev} className="flex items-center">
                    {i > 0 && <span className="mx-1 text-[10px] text-muted-foreground/50 select-none">|</span>}
                    <button onClick={() => toggleSet(scaSeverities, sev, setScaSeverities)}
                      className={cn("rounded px-2 py-0.5 text-xs font-medium border transition-colors",
                        scaSeverities.has(sev) ? severityChipClass(sev) : "border-transparent text-muted-foreground hover:border-border")}>
                      {sev}
                    </button>
                  </div>
                ))}
                <div className="self-stretch w-px bg-border mx-1" />
                {(["cve", "eol", "deprecated"] as const).map((t, i) => (
                  <div key={t} className="flex items-center">
                    {i > 0 && <span className="mx-1 text-[10px] text-muted-foreground/50 select-none">|</span>}
                    <button onClick={() => toggleSet(scaTypes, t, setScaTypes)}
                      className={cn("rounded px-2 py-0.5 text-xs font-medium border transition-colors",
                        scaTypes.has(t) ? "bg-accent text-accent-foreground border-border" : "border-transparent text-muted-foreground hover:border-border")}>
                      {t === "deprecated" ? "Deprecated" : t.toUpperCase()}
                    </button>
                  </div>
                ))}
                {(scaSeverities.size > 0 || scaTypes.size > 0) && (
                  <>
                    <div className="self-stretch w-px bg-border mx-1" />
                    <button onClick={() => { setScaSeverities(new Set()); setScaTypes(new Set()); }}
                      className="text-xs text-muted-foreground underline underline-offset-2 px-1">Clear</button>
                  </>
                )}
              </div>
              {findings.isLoading ? (
                <Card><CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent></Card>
              ) : filteredFindings.length === 0 ? (
                <Card><CardContent className="p-6 text-sm text-muted-foreground">No findings match.</CardContent></Card>
              ) : (
                <Card>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-6" />
                        <TableHead className="w-24">Severity</TableHead>
                        <TableHead>Summary</TableHead>
                        <TableHead className="w-64">Location</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredFindings.map((f) => (
                        <FindingRow
                          key={f.id}
                          finding={f}
                          manifestFile={componentsById.get(f.component_id)?.manifest_file ?? null}
                          sourceUrlTemplate={sourceUrlTemplate}
                        />
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="sast" className="mt-4">
              {/* Severity filter */}
              <div className="flex flex-wrap items-center gap-y-2 gap-x-0 mb-3">
                {(["critical", "high", "medium", "low", "info"] as const).map((sev, i) => (
                  <div key={sev} className="flex items-center">
                    {i > 0 && <span className="mx-1 text-[10px] text-muted-foreground/50 select-none">|</span>}
                    <button onClick={() => toggleSet(sastSeverities, sev, setSastSeverities)}
                      className={cn("rounded px-2 py-0.5 text-xs font-medium border transition-colors",
                        sastSeverities.has(sev) ? severityChipClass(sev) : "border-transparent text-muted-foreground hover:border-border")}>
                      {sev}
                    </button>
                  </div>
                ))}
                {sastSeverities.size > 0 && (
                  <>
                    <div className="self-stretch w-px bg-border mx-1" />
                    <button onClick={() => setSastSeverities(new Set())}
                      className="text-xs text-muted-foreground underline underline-offset-2 px-1">Clear</button>
                  </>
                )}
              </div>
              {sast.isLoading ? (
                <Card><CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent></Card>
              ) : filteredSast.length === 0 ? (
                <Card><CardContent className="p-6 text-sm text-muted-foreground">No SAST detections match.</CardContent></Card>
              ) : (
                <Card>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-6" />
                        <TableHead className="w-24">Severity</TableHead>
                        <TableHead>Summary</TableHead>
                        <TableHead className="w-64">Location</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredSast.map((f) => (
                        <SastRow key={f.id} finding={f} sourceUrlTemplate={sourceUrlTemplate} />
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="components" className="mt-4">
              <ComponentsTab components={components.data ?? []} findings={findings.data ?? []} isLoading={components.isLoading} />
            </TabsContent>
          </Tabs>
        )}

        {!isTerminal && (
          <Card>
            <CardHeader><CardTitle className="text-base">Scan in progress…</CardTitle></CardHeader>
            <CardContent className="text-sm text-muted-foreground">This page auto-refreshes. Results will appear once the scan completes.</CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  );
}

function formatDuration(startedAt: string | null, finishedAt: string | null): string {
  if (!startedAt) return "";
  const s = Math.max(0, Math.round((new Date(finishedAt ?? Date.now()).getTime() - new Date(startedAt).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}
