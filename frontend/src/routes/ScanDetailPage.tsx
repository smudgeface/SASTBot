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
  Info,
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
import { prettyEcosystem, prettyLicense } from "@/lib/componentLabels";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";
import { useNow } from "@/lib/useNow";
import { FilterGroup, Pipe, ToggleGroup } from "@/components/filters";
import { SortableTableHead } from "@/components/SortableTableHead";
import type { SortState } from "@/components/SortableTableHead";
import type { IssueSortKey } from "@/api/queries/scopes";
import type { ScanFindingsFilters, SastFindingsFilters } from "@/api/queries/scans";
import { ContextSnippet } from "@/components/ContextSnippet";
import { ReachabilityVerdict } from "@/components/ReachabilityVerdict";
import { SeverityBadge, severityClass } from "@/components/SeverityBadge";
import { VulnLink } from "@/components/VulnLink";
import { FileLink, basename } from "@/components/FileLink";
import { ScanStatusBadge } from "@/components/ScanStatusBadge";
import { SeveritySummary } from "@/components/SeveritySummary";
import { HighSeverityCallout } from "@/components/HighSeverityCallout";

const SEVERITY_ORDER: Record<FindingSeverity, number> = {
  critical: 0, high: 1, medium: 2, low: 3, unknown: 4,
};

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
  // Row shows the short LLM summary when available; tooltip and detail panel
  // keep the full raw OSV/NVD description.
  const summaryShort = finding.llm_summary ?? summary;
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
        <TableCell>
          {/* Two-row layout matching the scope page: summary on top (with
              full-text tooltip — truncated rows hide content), CVE/OSV
              id on the second line muted as an identifier. */}
          <div className="min-w-0">
            <div className="text-sm truncate" title={summary}>{summaryShort}</div>
            {isCve && (
              <div className="font-mono text-xs text-muted-foreground truncate">
                {finding.cve_id ?? finding.osv_id}
              </div>
            )}
          </div>
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
              <HighSeverityCallout
                title="Actively exploited"
                detail="listed in CISA KEV. Prioritize remediation."
              />
            )}
            {/* Full OSV summary (the collapsed row truncates with a
                tooltip; the panel shows it in full). */}
            {finding.summary && (
              <p className="text-sm">{finding.summary}</p>
            )}
            {finding.llm_summary && finding.llm_summary !== finding.summary && (
              <p className="text-sm text-muted-foreground">{finding.llm_summary}</p>
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
        <TableCell className="text-sm">
          <div className="line-clamp-1">{summary}</div>
        </TableCell>
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
            {issue.latest_snippet && !issue.latest_snippet.startsWith("__absence__:") && (
              <ContextSnippet
                snippet={issue.latest_snippet}
                matchLine={issue.latest_start_line}
                matchEndLine={issue.latest_end_line}
              />
            )}
            {issue.latest_snippet?.startsWith("__absence__:") && (
              <p className="text-xs italic text-muted-foreground">
                Observation about absent security controls — no specific code site.
              </p>
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

/** Single expandable row in the scan-page ComponentsTab. */
function ScanComponentRow({
  component, findings, expandedId, sourceUrlTemplate,
}: {
  component: SbomComponent;
  findings: ScanFinding[];
  expandedId: string | undefined;
  sourceUrlTemplate: string | null;
}) {
  const rowRef = useRef<HTMLTableRowElement>(null);
  const autoExpand = expandedId === component.id;
  const [expanded, setExpanded] = useState(autoExpand);

  // Sync expand + scroll when the URL targets this row. Instant scroll
  // (no smooth easing) — the tab/route change is already a hard transition.
  useEffect(() => {
    if (autoExpand) {
      setExpanded(true);
      rowRef.current?.scrollIntoView({ block: "center" });
    }
  }, [autoExpand]);

  const eco = prettyEcosystem(component.ecosystem);
  const occurrences = component.occurrences ?? [];
  const firstLicense = component.licenses[0] ? prettyLicense(component.licenses[0]) : null;
  const extraLicenses = component.licenses.length > 1 ? component.licenses.length - 1 : 0;

  return (
    <>
      <TableRow
        ref={rowRef}
        className="group cursor-pointer hover:bg-muted/40"
        onClick={() => setExpanded((v) => !v)}
      >
        <TableCell className="w-6 text-muted-foreground">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </TableCell>
        <TableCell className="font-mono text-sm">
          <span className="inline-flex items-center gap-1.5">
            {component.name}
            {component.is_dev_only && (
              <Badge
                variant="outline"
                className="text-[9px] px-1 py-0 text-blue-600 border-blue-400"
                title="cdxgen flagged this npm package as dev-only (lockfile dev: true)"
              >
                Dev
              </Badge>
            )}
          </span>
        </TableCell>
        <TableCell className="text-sm text-muted-foreground">{component.version ?? "—"}</TableCell>
        <TableCell className="text-sm text-muted-foreground">{eco}</TableCell>
        <TableCell className="text-sm text-muted-foreground">
          {firstLicense ? (
            <span>{firstLicense}{extraLicenses > 0 && <span className="text-xs ml-1">+{extraLicenses}</span>}</span>
          ) : "—"}
        </TableCell>
        <TableCell>
          {/* Non-clickable static finding chips — scan page is an audit view */}
          <div className="flex flex-wrap gap-1">
            {findings.length === 0
              ? <span className="text-xs text-muted-foreground">—</span>
              : findings.map((f) => (
                  <span key={f.id} className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase", severityClass(f.severity))}>
                    {f.finding_type === "cve" ? (f.cve_id ?? f.osv_id) : f.finding_type.toUpperCase()}
                  </span>
                ))}
          </div>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow className="bg-muted/20 hover:bg-muted/20">
          <TableCell colSpan={6} className="py-4 px-6">
            <div className="space-y-4 text-sm">
              {/* Evidence — identity proof. Small list ({lockfile,line,snippet}
                  for manifest-tracked; {component_root} for vendored). */}
              {(component.evidence && component.evidence.length > 0) || component.component_root ? (
                <div>
                  <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide mb-1">Evidence</p>
                  {component.component_root && (
                    <p className="font-mono text-xs mb-1">
                      <span className="text-muted-foreground mr-1">root:</span>
                      <FileLink template={sourceUrlTemplate} file={component.component_root}>
                        {component.component_root}
                      </FileLink>
                    </p>
                  )}
                  {component.evidence && component.evidence.length > 0 && (
                    <div className="space-y-2">
                      {component.evidence.map((e, i) => (
                        <div key={`${e.path}-${i}`}>
                          <p className="font-mono text-xs">
                            <FileLink template={sourceUrlTemplate} file={e.path} line={e.line ?? undefined}>
                              {e.path}{e.line != null ? `:${e.line}` : ""}
                            </FileLink>
                          </p>
                          {e.snippet && (
                            <ContextSnippet
                              snippet={e.snippet}
                              matchLine={e.line ?? undefined}
                              className="mt-1"
                            />
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ) : null}

              {/* License details */}
              {component.licenses.length > 0 && (
                <div>
                  <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide mb-1">Licenses</p>
                  <div className="flex flex-wrap gap-1.5">
                    {component.licenses.map((lic, i) => (
                      <Badge key={i} variant="secondary" className="text-xs font-normal">{prettyLicense(lic)}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Usage — where the component is imported / included from. */}
              {occurrences.length > 0 && (
                <div>
                  <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide mb-1">
                    Usage ({occurrences.length} location{occurrences.length !== 1 ? "s" : ""})
                  </p>
                  <ol className="space-y-0.5 font-mono text-xs">
                    {occurrences.slice(0, 15).map((occ, i) => (
                      <li key={i} className="text-muted-foreground">
                        <FileLink template={sourceUrlTemplate} file={occ.path} line={occ.line ?? undefined}>
                          {occ.path}{occ.line ? `:${occ.line}` : ""}
                        </FileLink>
                      </li>
                    ))}
                    {occurrences.length > 15 && (
                      <li className="text-muted-foreground italic">…and {occurrences.length - 15} more</li>
                    )}
                  </ol>
                </div>
              )}

              {/* LLM augmentation rationale (one-sentence "why this is here"). */}
              {component.llm_evidence && (
                <div>
                  <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide mb-1">LLM augmentation</p>
                  <p className="text-xs text-muted-foreground mb-1">{component.llm_evidence.llmReason}</p>
                  {component.llm_evidence.path && (
                    <p className="font-mono text-xs text-muted-foreground">
                      <FileLink template={sourceUrlTemplate} file={component.llm_evidence.path}>
                        {component.llm_evidence.path}
                      </FileLink>
                    </p>
                  )}
                  {component.llm_evidence.excerpt && (
                    <ContextSnippet
                      snippet={component.llm_evidence.excerpt}
                      className="mt-1 max-h-40"
                    />
                  )}
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function ComponentsTab({
  components, scanId, isLoading, onDisplayedTotalChange, expandedId, sourceUrlTemplate,
}: {
  components: SbomComponent[];
  scanId: string;
  isLoading: boolean;
  onDisplayedTotalChange?: (total: number) => void;
  expandedId?: string;
  sourceUrlTemplate?: string | null;
}) {
  // ComponentsTab needs every finding (not just one page) to build the
  // component-id → findings[] cross-reference for the per-row chip strip
  // and the "Only with findings" filter. Fetch up to the backend's
  // max page_size in one shot — practical scans don't exceed this.
  const { data: findingsPage } = useScanFindings(scanId, { page_size: 500 });
  const findings = findingsPage?.items ?? [];

  const [onlyWithFindings, setOnlyWithFindings] = useState(false);
  const findingsByComp = new Map<string, ScanFinding[]>();
  for (const f of findings) {
    const list = findingsByComp.get(f.component_id) ?? [];
    list.push(f);
    findingsByComp.set(f.component_id, list);
  }
  const withFindings = components.filter((c) => findingsByComp.has(c.id));
  const visible = onlyWithFindings ? withFindings : components;

  useEffect(() => {
    onDisplayedTotalChange?.(visible.length);
  }, [visible.length, onDisplayedTotalChange]);

  if (isLoading) return <Card><CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent></Card>;
  if (components.length === 0) return <Card><CardContent className="p-6 text-sm text-muted-foreground"><Package className="inline h-4 w-4 mr-1" />No components.</CardContent></Card>;

  return (
    <div className="space-y-3">
      {withFindings.length > 0 && (
        <ToggleGroup
          items={[{
            key: "only_with_findings",
            label: `Only with findings (${withFindings.length})`,
            active: onlyWithFindings,
            onToggle: () => setOnlyWithFindings((v) => !v),
          }]}
        />
      )}
      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-6" />
              <TableHead>Package</TableHead>
              <TableHead className="w-28">Version</TableHead>
              <TableHead className="w-28">Ecosystem</TableHead>
              <TableHead className="w-40">License</TableHead>
              <TableHead>Findings</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {visible.map((c) => {
              const cFindings = [...(findingsByComp.get(c.id) ?? [])].sort(
                (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
              );
              return (
                <ScanComponentRow
                  key={c.id}
                  component={c}
                  findings={cFindings}
                  expandedId={expandedId}
                  sourceUrlTemplate={sourceUrlTemplate ?? null}
                />
              );
            })}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}

// Compact paginator shared by the scan-page SCA + SAST tabs.
function Pager({
  page, pageSize, total, onPage,
}: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  if (totalPages <= 1) return null;
  return (
    <div className="flex items-center justify-between text-xs text-muted-foreground pt-2">
      <span>{(page - 1) * pageSize + 1}–{Math.min(page * pageSize, total)} of {total}</span>
      <div className="flex gap-1">
        <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹</Button>
        <Button variant="outline" size="sm" disabled={page >= totalPages} onClick={() => onPage(page + 1)}>›</Button>
      </div>
    </div>
  );
}

// Scan-page SCA findings tab — server-paged, server-sorted, server-filtered.
// Audit view, so triage / Jira affordances stay on the scope page.
function ScaFindingsTab({
  scanId, sourceUrlTemplate, onTotalChange,
}: {
  scanId: string;
  sourceUrlTemplate: string | null;
  onTotalChange?: (total: number) => void;
}) {
  const [filters, setFilters] = useState<ScanFindingsFilters>({ page: 1, page_size: 50 });
  const { data, isLoading } = useScanFindings(scanId, filters);
  useEffect(() => {
    if (data?.total != null) onTotalChange?.(data.total);
  }, [data?.total, onTotalChange]);

  const severitySet = new Set(filters.severities ?? []) as ReadonlySet<"critical" | "high" | "medium" | "low">;
  const typeSet = new Set(filters.finding_types ?? []) as ReadonlySet<"cve" | "eol" | "deprecated">;

  function toggleMulti<T extends string>(current: ReadonlySet<T>, key: keyof ScanFindingsFilters, value: T) {
    const next = new Set(current);
    next.has(value) ? next.delete(value) : next.add(value);
    setFilters((f) => ({ ...f, page: 1, [key]: next.size > 0 ? [...next] : undefined }));
  }

  const sortState: SortState<IssueSortKey> = {
    sort_by: filters.sort_by,
    sort_dir: filters.sort_dir ?? "asc",
  };
  const onSort = (next: SortState<IssueSortKey>) => {
    setFilters((f) => ({ ...f, page: 1, sort_by: next.sort_by, sort_dir: next.sort_dir }));
  };

  return (
    <>
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0 mb-3">
        <FilterGroup
          items={["critical", "high", "medium", "low"] as const}
          active={severitySet}
          onToggle={(s) => toggleMulti(severitySet, "severities", s)}
          label={(s) => s.charAt(0).toUpperCase() + s.slice(1)}
          colorFn={(s) => severityClass(s)}
        />
        <Pipe />
        <FilterGroup
          items={["cve", "eol", "deprecated"] as const}
          active={typeSet}
          onToggle={(t) => toggleMulti(typeSet, "finding_types", t)}
          label={(t) => (t === "deprecated" ? "Deprecated" : t.toUpperCase())}
        />
        {(severitySet.size > 0 || typeSet.size > 0) && (
          <>
            <Pipe />
            <button
              onClick={() => setFilters({ page: 1, page_size: 50 })}
              className="text-xs text-muted-foreground underline underline-offset-2 px-1"
            >
              Clear
            </button>
          </>
        )}
      </div>
      {isLoading ? (
        <Card><CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent></Card>
      ) : !data || data.total === 0 ? (
        <Card><CardContent className="p-6 text-sm text-muted-foreground">No findings match.</CardContent></Card>
      ) : (
        <>
          <Card>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <SortableTableHead columnKey="severity" state={sortState} onSort={onSort} className="w-24">
                    Severity
                  </SortableTableHead>
                  <SortableTableHead columnKey="summary" state={sortState} onSort={onSort}>
                    Summary
                  </SortableTableHead>
                  <SortableTableHead columnKey="location" state={sortState} onSort={onSort} className="w-64">
                    Location
                  </SortableTableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((f) => (
                  <FindingRow key={f.id} finding={f} sourceUrlTemplate={sourceUrlTemplate} />
                ))}
              </TableBody>
            </Table>
          </Card>
          <Pager
            page={filters.page ?? 1}
            pageSize={filters.page_size ?? 50}
            total={data.total}
            onPage={(p) => setFilters((f) => ({ ...f, page: p }))}
          />
        </>
      )}
    </>
  );
}

// Scan-page SAST detections tab — server-paged, sortable, severity- and
// status-filterable. Audit view; triage UI stays on the scope page.
function SastFindingsTab({
  scanId, sourceUrlTemplate, onTotalChange,
}: {
  scanId: string;
  sourceUrlTemplate: string | null;
  onTotalChange?: (total: number) => void;
}) {
  const [filters, setFilters] = useState<SastFindingsFilters>({ page: 1, page_size: 50 });
  const { data, isLoading } = useSastFindings(scanId, filters);
  useEffect(() => {
    if (data?.total != null) onTotalChange?.(data.total);
  }, [data?.total, onTotalChange]);

  const severitySet = new Set(filters.severities ?? []) as ReadonlySet<"critical" | "high" | "medium" | "low" | "info">;

  function toggleMulti<T extends string>(current: ReadonlySet<T>, key: keyof SastFindingsFilters, value: T) {
    const next = new Set(current);
    next.has(value) ? next.delete(value) : next.add(value);
    setFilters((f) => ({ ...f, page: 1, [key]: next.size > 0 ? [...next] : undefined }));
  }

  const sortState: SortState<IssueSortKey> = {
    sort_by: filters.sort_by,
    sort_dir: filters.sort_dir ?? "asc",
  };
  const onSort = (next: SortState<IssueSortKey>) => {
    setFilters((f) => ({ ...f, page: 1, sort_by: next.sort_by, sort_dir: next.sort_dir }));
  };

  return (
    <>
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0 mb-3">
        <FilterGroup
          items={["critical", "high", "medium", "low", "info"] as const}
          active={severitySet}
          onToggle={(s) => toggleMulti(severitySet, "severities", s)}
          label={(s) => s.charAt(0).toUpperCase() + s.slice(1)}
          colorFn={(s) => severityClass(s)}
        />
        {severitySet.size > 0 && (
          <>
            <Pipe />
            <button
              onClick={() => setFilters({ page: 1, page_size: 50 })}
              className="text-xs text-muted-foreground underline underline-offset-2 px-1"
            >
              Clear
            </button>
          </>
        )}
      </div>
      {isLoading ? (
        <Card><CardContent className="p-6 text-sm text-muted-foreground">Loading…</CardContent></Card>
      ) : !data || data.total === 0 ? (
        <Card><CardContent className="p-6 text-sm text-muted-foreground">No SAST detections match.</CardContent></Card>
      ) : (
        <>
          <Card>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <SortableTableHead columnKey="severity" state={sortState} onSort={onSort} className="w-24">
                    Severity
                  </SortableTableHead>
                  <SortableTableHead columnKey="summary" state={sortState} onSort={onSort}>
                    Summary
                  </SortableTableHead>
                  <SortableTableHead columnKey="location" state={sortState} onSort={onSort} className="w-64">
                    Location
                  </SortableTableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((i) => (
                  <SastRow key={i.id} issue={i} sourceUrlTemplate={sourceUrlTemplate} />
                ))}
              </TableBody>
            </Table>
          </Card>
          <Pager
            page={filters.page ?? 1}
            pageSize={filters.page_size ?? 50}
            total={data.total}
            onPage={(p) => setFilters((f) => ({ ...f, page: p }))}
          />
        </>
      )}
    </>
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
  const components = useScanComponents(id);
  const repos = useRepos();
  const sbom = useSbomJson(id);
  const sarif = useSastSarif(id);

  // Each tab manages its own filter/sort/page state and publishes the
  // server-side total back via `onTotalChange` so the tab pills can show
  // a live filtered count. ComponentsTab is unchanged — it still fetches
  // its own components + uses `useScanFindings` directly to cross-reference
  // findings-per-component for the "Findings" column.
  const [scaDisplayed, setScaDisplayed] = useState<number | null>(null);
  const [sastDisplayed, setSastDisplayed] = useState<number | null>(null);
  const [componentsDisplayed, setComponentsDisplayed] = useState<number | null>(null);

  // Repo name comes from the scan payload (works for every role); useRepos is
  // kept only for source_url_template (admin-only; FileLinks degrade to plain
  // spans for non-admins, same as before).
  const repo = repos.data?.items.find((r) => r.id === scan.data?.repo_id);
  const repoName = scan.data?.repo_name ?? undefined;
  const sourceUrlTemplate = repo?.source_url_template ?? null;
  useDocumentTitle(repoName ? `${repoName} scan — SASTBot` : "Scan — SASTBot");

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
  // "Fully ready" = scan is terminal-success AND the components query has
  // fresh post-terminal data. The SCA/SAST tabs live in sub-components
  // with their own queries; their loading states are handled inline so
  // they don't need to gate the outer view. Without this gate we'd render
  // the results view the instant the scan_run flips to success, while the
  // components cache may still be holding mid-recheck stale data.
  const dataIsFetching = components.isFetching;
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
                <span className="text-base font-normal text-muted-foreground font-mono"> · {s.scope_path}</span>
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
              <p className="text-sm text-muted-foreground">
                {s.triggered_by_user_email
                  ? `Triggered by ${s.triggered_by_user_name ? `${s.triggered_by_user_name} (${s.triggered_by_user_email})` : s.triggered_by_user_email}`
                  : s.triggered_by === "api"
                    ? "Triggered via API"
                    : s.triggered_by === "schedule"
                      ? "Triggered on schedule"
                      : "Triggered by a user (account removed)"}
              </p>
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
          // Card border tracks the strongest severity present. Pure-info warnings
          // get the default neutral border so an FYI doesn't look like a problem.
          const cardBorder = hasError
            ? "border-destructive/50"
            : "";
          return (
            <Card className={cardBorder}>
              <CardContent className="p-4 space-y-2">
                {s.warnings.map((w, i) => {
                  const isError = w.severity === "error";
                  const colorClass = isError
                    ? "text-destructive"
                    : "text-muted-foreground";
                  const Icon = isError ? AlertTriangle : Info;
                  // Normalise details: accept an array of {raw, reason} objects.
                  const parseErrorDetails = (() => {
                    if (!Array.isArray(w.details) || w.details.length === 0) return null;
                    const entries = (w.details as unknown[]).filter(
                      (d): d is { raw: string; reason: string } =>
                        typeof d === "object" && d !== null &&
                        "raw" in d && typeof (d as Record<string, unknown>).raw === "string" &&
                        "reason" in d && typeof (d as Record<string, unknown>).reason === "string",
                    );
                    return entries.length > 0 ? entries : null;
                  })();

                  return (
                    <div key={i} className={cn("text-sm", colorClass)}>
                      <div className="flex gap-2">
                        <Icon className="h-4 w-4 shrink-0 mt-0.5" />
                        <span>{w.message}</span>
                      </div>
                      {parseErrorDetails && (
                        <details className="mt-1 ml-6">
                          <summary className="cursor-pointer text-xs opacity-70 select-none hover:opacity-100">
                            {parseErrorDetails.length} raw payload{parseErrorDetails.length !== 1 ? "s" : ""}
                          </summary>
                          <div className="mt-1 space-y-1">
                            {parseErrorDetails.map((entry, j) => (
                              <div key={j} className="rounded border border-current/20 bg-muted/50 p-2 text-xs font-mono">
                                <div className="mb-0.5 font-sans font-medium opacity-70">reason: {entry.reason}</div>
                                <div className="whitespace-pre-wrap break-all">{entry.raw}</div>
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    </div>
                  );
                })}
              </CardContent>
            </Card>
          );
        })()}

        {/* Summary */}
        {showResults && (
          <SeveritySummary
            critical={s.critical_count}
            high={s.high_count}
            medium={s.medium_count}
            low={s.low_count}
            sca={scaDisplayed ?? 0}
            sast={sastDisplayed ?? s.sast_finding_count}
            components={s.component_count}
          />
        )}

        {/* Tabs */}
        {showResults && (
          <Tabs defaultValue="findings">
            <TabsList>
              <TabsTrigger value="findings" className="gap-1.5">
                <ShieldAlert className="h-3.5 w-3.5" />Raw SCA Findings
                {scaDisplayed != null && scaDisplayed > 0 && (
                  <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">{scaDisplayed}</span>
                )}
              </TabsTrigger>
              <TabsTrigger value="sast" className="gap-1.5">
                <ScanSearch className="h-3.5 w-3.5" />Raw SAST Detections
                {sastDisplayed != null && sastDisplayed > 0 && (
                  <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">{sastDisplayed}</span>
                )}
              </TabsTrigger>
              <TabsTrigger value="components" className="gap-1.5">
                <Package className="h-3.5 w-3.5" />Components
                {(() => {
                  // Until <ComponentsTab> mounts (it lacks forceMount), fall
                  // back to the full unfiltered count so the pill renders on
                  // initial page load. Once the tab is opened and the inner
                  // toggle changes, componentsDisplayed takes over.
                  const n = componentsDisplayed ?? s.component_count;
                  return n > 0 ? <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">{n}</span> : null;
                })()}
              </TabsTrigger>
            </TabsList>

            {/* forceMount on each tab so the sub-component queries fire on
                initial page load, not first click — keeps the tab pills
                populated before the user navigates into a tab. */}
            <TabsContent forceMount value="findings" className="mt-4 data-[state=inactive]:hidden">
              {id && (
                <ScaFindingsTab
                  scanId={id}
                  sourceUrlTemplate={sourceUrlTemplate}
                  onTotalChange={setScaDisplayed}
                />
              )}
            </TabsContent>

            <TabsContent forceMount value="sast" className="mt-4 data-[state=inactive]:hidden">
              {id && (
                <SastFindingsTab
                  scanId={id}
                  sourceUrlTemplate={sourceUrlTemplate}
                  onTotalChange={setSastDisplayed}
                />
              )}
            </TabsContent>

            <TabsContent value="components" className="mt-4">
              <ComponentsTab
                components={components.data ?? []}
                scanId={id ?? ""}
                isLoading={components.isLoading}
                onDisplayedTotalChange={setComponentsDisplayed}
                sourceUrlTemplate={sourceUrlTemplate}
              />
            </TabsContent>
          </Tabs>
        )}

        {showInProgress && (
          <Card>
            <CardHeader>
              <CardTitle className="text-base">
                {s.current_phase
                  ? SCAN_PHASE_LABELS[s.current_phase]
                  : "Scan in progress…"}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {s.phase_progress?.label && (
                <div className="text-xs text-muted-foreground">Tokens: {s.phase_progress.label}</div>
              )}
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
