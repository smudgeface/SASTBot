/**
 * Scan detail — demoted to an audit/debug view in M5.
 * Shows raw detection rows (SCA findings, SAST detections, components)
 * for a specific scan run. Triage and dismiss actions are on /scopes/:id.
 */
import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
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
  scansKey,
  useScanDetail,
  useScanComponents,
  useScanFindings,
  useSbomJson,
  useSastSarif,
  useSastFindings,
} from "@/api/queries/scans";
import { useRepos } from "@/api/queries/repos";
import type { FindingSeverity, SastIssue, SbomComponent, ScanFinding } from "@/api/types";
import { SCAN_PHASE_LABELS, SCAN_PHASE_UNITS, SCAN_PHASE_CAPS } from "@/api/types";
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
import { formatDate } from "@/lib/format";
import { useNow } from "@/lib/useNow";
import { FilterGroup, Pipe } from "@/components/filters";
import { ContextSnippet } from "@/components/ContextSnippet";
import { ReachabilityVerdict } from "@/components/ReachabilityVerdict";
import { SeverityBadge, severityClass, severityTextClass } from "@/components/SeverityBadge";
import { VulnLink } from "@/components/VulnLink";
import { FileLink, basename } from "@/components/FileLink";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, unknown: 4,
};

function SummaryCard({ label, value, severity }: { label: string; value: number; severity?: FindingSeverity }) {
  return (
    <Card>
      <CardContent className="p-4">
        <p className="text-xs uppercase text-muted-foreground mb-1">{label}</p>
        <p className={cn("text-2xl font-bold", severity ? severityTextClass(severity) : "")}>
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
  sourceUrlTemplate,
}: {
  finding: ScanFinding;
  sourceUrlTemplate: string | null | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const isCve = finding.finding_type === "cve";
  const summary = finding.summary
    ?? (finding.finding_type === "eol" ? "End of life" : finding.finding_type === "deprecated" ? "Deprecated package" : "—");
  const manifestFile = finding.manifest_file;
  // Match scope page's "runtime" relabel for CycloneDX `required`. Anything
  // else (optional, excluded, null) shows the raw value or "unknown".
  const componentScopeLabel =
    finding.component_scope === "required"
      ? "runtime"
      : (finding.component_scope ?? "unknown");
  const otherAliases = isCve
    ? finding.aliases.filter((a) => a !== finding.osv_id && a !== finding.cve_id)
    : [];

  return (
    <>
      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => setExpanded((x) => !x)}>
        <TableCell className="w-6">
          {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        </TableCell>
        <TableCell className="w-24"><SeverityBadge severity={finding.severity} /></TableCell>
        <TableCell className="text-sm">
          <div className="line-clamp-1">{summary}</div>
        </TableCell>
        <TableCell className="w-64 overflow-hidden">
          {manifestFile ? (
            <>
              <div
                className="truncate text-xs text-muted-foreground font-mono"
                title={`${manifestFile}${finding.manifest_line ? `:${finding.manifest_line}` : ""}`}
              >
                {basename(manifestFile)}
                {finding.manifest_line ? `:${finding.manifest_line}` : ""}
              </div>
              <div
                className="truncate text-[10px] text-muted-foreground font-mono mt-0.5"
                title={`${finding.component_name}${finding.component_version ? `@${finding.component_version}` : ""}`}
              >
                {finding.component_name}
                {finding.component_version ? `@${finding.component_version}` : ""}
              </div>
            </>
          ) : (
            <div
              className="truncate text-xs text-muted-foreground font-mono"
              title={`${finding.component_name}${finding.component_version ? `@${finding.component_version}` : ""}`}
            >
              {finding.component_name}
              {finding.component_version ? `@${finding.component_version}` : ""}
            </div>
          )}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={4} className="bg-muted/30 p-4 space-y-3">
            {finding.actively_exploited && (
              <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0" />
                <span>
                  <span className="font-semibold">Actively exploited</span>
                  {" — "}listed in CISA KEV. Prioritize remediation.
                </span>
              </div>
            )}
            {finding.llm_summary && finding.llm_summary !== finding.summary && (
              <p className="text-sm">{finding.llm_summary}</p>
            )}
            {manifestFile && (
              <div className="space-y-1">
                <p className="text-xs font-mono text-muted-foreground break-all">
                  <FileLink
                    template={sourceUrlTemplate}
                    file={manifestFile}
                    line={finding.manifest_line}
                  >
                    {manifestFile}
                    {finding.manifest_line ? `:${finding.manifest_line}` : ""}
                  </FileLink>
                </p>
                {finding.manifest_snippet && finding.manifest_line && (
                  <ContextSnippet
                    snippet={finding.manifest_snippet}
                    matchLine={finding.manifest_line}
                  />
                )}
              </div>
            )}
            <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span>
                <span className="font-medium">OSV:&nbsp;</span>
                <VulnLink id={finding.osv_id} className="text-xs" />
              </span>
              {finding.cve_id && (
                <span>
                  <span className="font-medium">CVE:&nbsp;</span>
                  <VulnLink id={finding.cve_id} className="text-xs" />
                </span>
              )}
              {(finding.cvss_score != null || finding.cvss_vector) && (
                <span>
                  <span className="font-medium">CVSS:</span>{" "}
                  {finding.cvss_score != null
                    ? finding.cvss_score.toFixed(1)
                    : finding.cvss_vector?.startsWith("CVSS:4.")
                      ? <span title="CVSS v4.0 score calculation not yet implemented">v4.0</span>
                      : "—"}
                  {finding.cvss_vector && (
                    <span className="font-mono ml-1 text-[10px]">({finding.cvss_vector})</span>
                  )}
                </span>
              )}
              {finding.ecosystem && (
                <span><span className="font-medium">Ecosystem:</span> {finding.ecosystem}</span>
              )}
              <span>
                <span className="font-medium">Scope:</span>{" "}
                {componentScopeLabel}
              </span>
              {finding.has_fix && (
                <span className="text-green-600 font-medium">✓ Fix available</span>
              )}
              {finding.eol_date && (
                <span><span className="font-medium">EOL date:</span> {finding.eol_date.slice(0, 10)}</span>
              )}
            </div>
            {finding.reachable_assessed_at && (
              <ReachabilityVerdict
                fields={finding}
                sourceUrlTemplate={sourceUrlTemplate}
                FileLink={FileLink}
              />
            )}
            {otherAliases.length > 0 && (
              <div className="flex flex-wrap gap-1.5 items-center text-xs">
                <span className="text-muted-foreground font-medium">Aliases:</span>
                {otherAliases.map((alias) => (
                  <VulnLink key={alias} id={alias} className="text-xs" />
                ))}
              </div>
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
  issue,
  sourceUrlTemplate,
}: {
  issue: SastIssue;
  sourceUrlTemplate: string | null | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  const summary =
    issue.latest_llm_summary
    ?? issue.latest_rule_message
    ?? issue.latest_rule_id.split(".").pop()?.replace(/-/g, " ")
    ?? issue.latest_rule_id;
  const isLlmRuleId = issue.latest_rule_id.startsWith("llm:");

  return (
    <>
      <TableRow className="cursor-pointer hover:bg-muted/50" onClick={() => setExpanded((x) => !x)}>
        <TableCell className="w-6">
          {expanded ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
        </TableCell>
        <TableCell className="w-24"><SeverityBadge severity={issue.latest_severity} /></TableCell>
        <TableCell className="text-sm text-muted-foreground line-clamp-1">{summary}</TableCell>
        <TableCell
          className="w-64 font-mono text-xs text-muted-foreground truncate"
          title={`${issue.latest_file_path}:${issue.latest_start_line}`}
        >
          {basename(issue.latest_file_path)}:{issue.latest_start_line}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={4} className="bg-muted/30 py-3 px-6 space-y-2">
            <p className="text-xs">
              <FileLink
                template={sourceUrlTemplate}
                file={issue.latest_file_path}
                line={issue.latest_start_line}
                className="font-mono"
              >
                {issue.latest_file_path}:{issue.latest_start_line}
              </FileLink>
            </p>
            {issue.latest_snippet && (
              <pre className="rounded bg-background border p-3 text-xs overflow-x-auto font-mono whitespace-pre-wrap">{issue.latest_snippet}</pre>
            )}
            {issue.latest_rule_message && issue.latest_rule_message !== summary && (
              <p className="text-sm text-muted-foreground">{issue.latest_rule_message}</p>
            )}
            {!isLlmRuleId && (
              <p className="font-mono text-xs text-muted-foreground">{issue.latest_rule_id}</p>
            )}
            {issue.latest_cwe_ids.length > 0 && (
              <div className="flex gap-1">{issue.latest_cwe_ids.map((c) => <Badge key={c} variant="outline" className="font-mono text-xs">{c}</Badge>)}</div>
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
                        <span key={f.id} className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase", severityClass(f.severity))}>
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
  const sarif = useSastSarif(id);
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
    (a, b) => (SEVERITY_ORDER[a.latest_severity as FindingSeverity] ?? 9) - (SEVERITY_ORDER[b.latest_severity as FindingSeverity] ?? 9),
  );
  const filteredSast = sastSeverities.size > 0
    ? sortedSast.filter((i) => sastSeverities.has(i.latest_severity))
    : sortedSast;

  // Live wall-clock for the elapsed-timer display. The hook ticks every
  // second while the scan is pending/running and freezes once terminal.
  // Bound explicitly into formatDuration below so React sees the JSX
  // dependency; reading-but-not-using the hook's return value isn't enough
  // when TanStack Query's structural sharing keeps `scan.data` ref-equal
  // between refetches.
  const status = scan.data?.status;
  const isLive = status === "pending" || status === "running";
  const now = useNow(1000, isLive);

  // When the scan transitions from running → terminal, force a refetch of
  // every per-scan dataset. The polling refetchInterval stops once status
  // is terminal, so without this push the SAST/SCA caches can race-lose
  // against the scan poll: scan poll lands first (status=success →
  // refetchInterval returns false → no more SAST polls), and the SAST
  // cache stays at its last value from before recheck-apply.
  const qc = useQueryClient();
  const prevStatusRef = useRef<string | undefined>(undefined);
  useEffect(() => {
    const prev = prevStatusRef.current;
    prevStatusRef.current = status;
    if (!id || !prev) return;
    const becameTerminal =
      prev !== status && (status === "success" || status === "failed" || status === "cancelled");
    if (becameTerminal) {
      qc.invalidateQueries({ queryKey: [...scansKey, id, "sast-findings"] });
      qc.invalidateQueries({ queryKey: [...scansKey, id, "findings"] });
      qc.invalidateQueries({ queryKey: [...scansKey, id, "components"] });
    }
  }, [status, id, qc]);

  if (scan.isLoading) return <div className="p-8 text-sm text-muted-foreground">Loading scan…</div>;
  if (!scan.data) return <div className="p-8 text-sm text-destructive">Scan not found.</div>;

  const s = scan.data;
  const isTerminal = s.status === "success" || s.status === "failed" || s.status === "cancelled";
  // "Fully ready" = scan is terminal-success AND every per-scan data query
  // has fresh post-terminal data. Without the !isFetching gate we'd render
  // the results view as soon as the scan_run flips to success — but the
  // SAST/SCA queries may still be holding cached data from a poll that
  // happened mid-recheck (when only the new detections were visible).
  // Showing the in-progress UI for the extra ~2s until the next poll lands
  // is far less confusing than briefly showing wrong counts.
  const dataIsFetching = sast.isFetching || findings.isFetching || components.isFetching;
  const showResults = isTerminal && s.status === "success" && !dataIsFetching;
  // Render the "Scan in progress" card while the scan is still moving OR
  // while we're waiting for the post-terminal refetch to land. Failed and
  // cancelled scans show neither — header status + error banner are enough.
  const showInProgress = !isTerminal || (s.status === "success" && !showResults);

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
            <div className="space-y-0.5">
              <div>
                <ScanStatusBadge status={s.status} />
              </div>
              {s.llm_request_count > 0 && (
                <p className="text-sm text-muted-foreground" title={`${s.llm_input_tokens.toLocaleString()} input + ${s.llm_output_tokens.toLocaleString()} output tokens. Cache read/creation tokens aren't included.`}>
                  {s.llm_request_count} LLM {s.llm_request_count === 1 ? "call" : "calls"}
                  {" · "}
                  {formatTokens(s.llm_input_tokens)} in / {formatTokens(s.llm_output_tokens)} out
                </p>
              )}
              {s.started_at && (
                <p className="text-sm text-muted-foreground">
                  {formatDuration(s.started_at, s.finished_at, now)}
                  {!s.finished_at && " elapsed"}
                </p>
              )}
              <p className="text-xs text-muted-foreground/80 italic pt-1">
                {formatDate(s.started_at ?? s.created_at)}
                {" · Audit view — triage on the "}
                <Link to={`/scopes/${s.scope_id}`} className="underline hover:text-foreground">scope page</Link>
              </p>
            </div>
          </div>
          {showResults && (
            <div className="flex flex-wrap gap-2">
              <Button asChild variant="outline" size="sm" className="gap-1.5">
                <Link to={`/scans/${id}/sbom`}><FileCode2 className="h-4 w-4" /> View SBOM</Link>
              </Button>
              <Button variant="outline" size="sm" className="gap-1.5" disabled={!sbom.data}
                onClick={() => downloadBlob(sbom.data!, `sbom-${repoName ?? "scan"}-${(id ?? "").slice(0, 8)}.cdx.json`)}>
                <Download className="h-4 w-4" /> Download SBOM
              </Button>
              <Button asChild variant="outline" size="sm" className="gap-1.5" disabled={!sarif.data}>
                <Link to={`/scans/${id}/sast-sarif`}><FileCode2 className="h-4 w-4" /> View SARIF</Link>
              </Button>
              <Button variant="outline" size="sm" className="gap-1.5" disabled={!sarif.data}
                onClick={() => downloadBlob(sarif.data!, `sast-${repoName ?? "scan"}-${(id ?? "").slice(0, 8)}.sarif.json`)}>
                <Download className="h-4 w-4" /> Download SARIF
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
        {s.warnings && s.warnings.length > 0 && (() => {
          const hasError = s.warnings.some((w) => w.severity === "error");
          return (
            <Card className={hasError ? "border-destructive/50" : "border-amber-200 dark:border-amber-900"}>
              <CardContent className="p-4 space-y-1">
                {s.warnings.map((w, i) => (
                  <div
                    key={i}
                    className={cn(
                      "flex gap-2 text-sm",
                      w.severity === "error"
                        ? "text-destructive"
                        : "text-amber-700 dark:text-amber-300",
                    )}
                  >
                    <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" /><span>{w.message}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          );
        })()}

        {/* Summary cards */}
        {showResults && (
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <SummaryCard label="Components" value={s.component_count} />
            <SummaryCard label="Critical" value={s.critical_count} severity="critical" />
            <SummaryCard label="High" value={s.high_count} severity="high" />
            <SummaryCard label="Medium" value={s.medium_count} severity="medium" />
            <SummaryCard label="Low" value={s.low_count} severity="low" />
          </div>
        )}

        {/* Tabs */}
        {showResults && (
          <Tabs defaultValue="findings">
            <TabsList>
              <TabsTrigger value="findings" className="gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5" />Raw SCA Findings
                {allFindings.length > 0 && <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">{allFindings.length}</span>}
              </TabsTrigger>
              <TabsTrigger value="sast" className="gap-1.5">
                <ScanSearch className="h-3.5 w-3.5" />Raw SAST Detections
                {allSast.length > 0 && <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">{allSast.length}</span>}
              </TabsTrigger>
              <TabsTrigger value="components" className="gap-1.5">
                <Package className="h-3.5 w-3.5" />Components
                {s.component_count > 0 && <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">{s.component_count}</span>}
              </TabsTrigger>
            </TabsList>

            <TabsContent value="findings" className="mt-4">
              <div className="flex flex-wrap items-center gap-y-2 gap-x-0 mb-3">
                <FilterGroup
                  items={["critical", "high", "medium", "low"] as const}
                  active={scaSeverities as ReadonlySet<"critical" | "high" | "medium" | "low">}
                  onToggle={(s) => toggleSet(scaSeverities, s, setScaSeverities)}
                  label={(s) => s.charAt(0).toUpperCase() + s.slice(1)}
                  colorFn={(s) => severityClass(s)}
                />
                <Pipe />
                <FilterGroup
                  items={["cve", "eol", "deprecated"] as const}
                  active={scaTypes as ReadonlySet<"cve" | "eol" | "deprecated">}
                  onToggle={(t) => toggleSet(scaTypes, t, setScaTypes)}
                  label={(t) => (t === "deprecated" ? "Deprecated" : t.toUpperCase())}
                />
                {(scaSeverities.size > 0 || scaTypes.size > 0) && (
                  <>
                    <Pipe />
                    <button
                      onClick={() => { setScaSeverities(new Set()); setScaTypes(new Set()); }}
                      className="text-xs text-muted-foreground underline underline-offset-2 px-1"
                    >
                      Clear
                    </button>
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
                          sourceUrlTemplate={sourceUrlTemplate}
                        />
                      ))}
                    </TableBody>
                  </Table>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="sast" className="mt-4">
              <div className="flex flex-wrap items-center gap-y-2 gap-x-0 mb-3">
                <FilterGroup
                  items={["critical", "high", "medium", "low", "info"] as const}
                  active={sastSeverities as ReadonlySet<"critical" | "high" | "medium" | "low" | "info">}
                  onToggle={(s) => toggleSet(sastSeverities, s, setSastSeverities)}
                  label={(s) => s.charAt(0).toUpperCase() + s.slice(1)}
                  colorFn={(s) => severityClass(s)}
                />
                {sastSeverities.size > 0 && (
                  <>
                    <Pipe />
                    <button
                      onClick={() => setSastSeverities(new Set())}
                      className="text-xs text-muted-foreground underline underline-offset-2 px-1"
                    >
                      Clear
                    </button>
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
                      {filteredSast.map((i) => (
                        <SastRow key={i.id} issue={i} sourceUrlTemplate={sourceUrlTemplate} />
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

        {showInProgress && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {s.current_phase
                  ? (s.phase_progress?.label ?? SCAN_PHASE_LABELS[s.current_phase])
                  : "Scan in progress…"}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {s.phase_progress && s.phase_progress.total > 0 && (() => {
                const unit = s.current_phase ? SCAN_PHASE_UNITS[s.current_phase] : undefined;
                const isCap = s.current_phase ? SCAN_PHASE_CAPS.has(s.current_phase) : false;
                return (
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>
                      {s.phase_progress.done} of {s.phase_progress.total}{unit ? ` ${unit}` : ""}
                      {isCap ? " (max)" : ""}
                    </span>
                    {!isCap && (
                      <span>{Math.round((s.phase_progress.done / s.phase_progress.total) * 100)}%</span>
                    )}
                  </div>
                  {!isCap && (
                    <div className="h-1.5 rounded bg-muted overflow-hidden">
                      <div
                        className="h-full bg-primary transition-all"
                        style={{ width: `${Math.min(100, (s.phase_progress.done / s.phase_progress.total) * 100)}%` }}
                      />
                    </div>
                  )}
                </div>
                );
              })()}
              <p className="text-sm text-muted-foreground">This page auto-refreshes. Results will appear once the scan completes.</p>
            </CardContent>
          </Card>
        )}
      </div>
    </TooltipProvider>
  );
}

function formatDuration(startedAt: string | null, finishedAt: string | null, now: number): string {
  if (!startedAt) return "";
  const end = finishedAt ? new Date(finishedAt).getTime() : now;
  const s = Math.max(0, Math.round((end - new Date(startedAt).getTime()) / 1000));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function formatTokens(n: number): string {
  if (n < 1000) return n.toString();
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(1)}M`;
}
