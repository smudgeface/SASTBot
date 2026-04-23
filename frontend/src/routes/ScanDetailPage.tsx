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
  ScanSearch,
  Zap,
} from "lucide-react";

import {
  useScanDetail,
  useScanComponents,
  useScanFindings,
  useSbomJson,
  useSastFindings,
  useTriageSastFinding,
} from "@/api/queries/scans";
import { useRepos } from "@/api/queries/repos";
import type { FindingSeverity, SastFinding, SastTriageStatus, SbomComponent, ScanFinding } from "@/api/types";
import { useAuthStore } from "@/stores/auth";
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
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

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

function OptionalBadge() {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase bg-zinc-100 text-zinc-500 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700 cursor-default">
          DEV
        </span>
      </TooltipTrigger>
      <TooltipContent>Optional scope — dev dependency or indirect dependency not required for production</TooltipContent>
    </Tooltip>
  );
}

function FindingTypeBadge({ finding }: { finding: ScanFinding }) {
  if (finding.finding_type === "eol") {
    return (
      <div className="flex items-center gap-1">
        {finding.component_scope === "optional" ? <OptionalBadge /> : null}
        <span className={cn(
          "inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase",
          severityChipClass(finding.severity),
        )}>
          EOL
        </span>
      </div>
    );
  }
  if (finding.finding_type === "deprecated") {
    return (
      <div className="flex items-center gap-1">
        {finding.component_scope === "optional" ? <OptionalBadge /> : null}
        <span className="inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase bg-amber-100 text-amber-800 border-amber-200 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-900">
          DEPRECATED
        </span>
      </div>
    );
  }
  return (
    <div className="flex items-center gap-1">
      {finding.component_scope === "optional" ? <OptionalBadge /> : null}
      <SeverityBadge severity={finding.severity} />
    </div>
  );
}

function ReachableIcon({ reasoning }: { reasoning?: string | null }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex">
          <Zap className="h-3.5 w-3.5 text-blue-500 shrink-0" aria-label="Reachable" />
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <p className="font-medium">Confirmed Reachable</p>
        {reasoning ? <p className="mt-0.5 text-muted-foreground max-w-xs">{reasoning}</p> : null}
      </TooltipContent>
    </Tooltip>
  );
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
        <TableCell className="w-8">
          <div className="flex items-center gap-1">
            {expanded ? (
              <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
            )}
            {finding.confirmed_reachable ? (
              <ReachableIcon reasoning={finding.reachable_reasoning} />
            ) : null}
          </div>
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
              {isCve && finding.reachable_assessed_at ? (
                <div className="border-t pt-2 mt-1 space-y-0.5">
                  <p className="text-xs font-medium uppercase text-muted-foreground">Reachability</p>
                  <p className="text-xs">
                    <span className={cn("font-medium", finding.confirmed_reachable ? "text-yellow-600 dark:text-yellow-400" : "text-muted-foreground")}>
                      {finding.confirmed_reachable ? "⚡ Reachable" : "Not reachable"}
                    </span>
                    {finding.reachable_reasoning ? ` — ${finding.reachable_reasoning}` : null}
                  </p>
                  {finding.reachable_via_sast_fingerprint ? (
                    <p className="text-xs text-muted-foreground">
                      Via SAST finding <span className="font-mono">{finding.reachable_via_sast_fingerprint}</span>
                    </p>
                  ) : null}
                </div>
              ) : null}
            </div>
          </TableCell>
        </TableRow>
      ) : null}
    </>
  );
}

// ---------------------------------------------------------------------------
// SAST triage helpers
// ---------------------------------------------------------------------------

const TRIAGE_STATUS_LABEL: Record<SastTriageStatus, string> = {
  pending: "Pending",
  confirmed: "Confirmed",
  false_positive: "False Positive",
  suppressed: "Suppressed",
  error: "Error",
};

function TriageBadge({ status }: { status: SastTriageStatus }) {
  const cls = {
    pending: "bg-zinc-100 text-zinc-700 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-300 dark:border-zinc-700",
    confirmed: "bg-red-100 text-red-700 border-red-200 dark:bg-red-950 dark:text-red-300 dark:border-red-900",
    false_positive: "bg-emerald-100 text-emerald-700 border-emerald-200 dark:bg-emerald-950 dark:text-emerald-300 dark:border-emerald-900",
    suppressed: "bg-zinc-100 text-zinc-400 border-zinc-200 line-through dark:bg-zinc-900 dark:text-zinc-500",
    error: "bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-950 dark:text-amber-300 dark:border-amber-900",
  }[status];
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-medium", cls)}>
      {TRIAGE_STATUS_LABEL[status]}
    </span>
  );
}

function SastSeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === "high"
      ? "bg-orange-100 text-orange-700 border-orange-200 dark:bg-orange-950 dark:text-orange-300 dark:border-orange-900"
      : severity === "medium"
      ? "bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-950 dark:text-yellow-300 dark:border-yellow-900"
      : severity === "low"
      ? "bg-blue-100 text-blue-700 border-blue-200 dark:bg-blue-950 dark:text-blue-300 dark:border-blue-900"
      : severity === "critical"
      ? "bg-red-100 text-red-700 border-red-200 dark:bg-red-950 dark:text-red-300 dark:border-red-900"
      : "bg-zinc-100 text-zinc-500 border-zinc-200 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-700";
  return (
    <span className={cn("inline-flex items-center rounded border px-1.5 py-0.5 text-xs font-semibold uppercase", cls)}>
      {severity}
    </span>
  );
}

// ---------------------------------------------------------------------------
// SAST tab
// ---------------------------------------------------------------------------

// Derive a short, human-readable summary from a SAST finding.
// Prefers rule_message; falls back to the last segment of rule_id.
function sastSummary(f: SastFinding): string {
  if (f.rule_message) return f.rule_message;
  const parts = f.rule_id.split(".");
  return parts[parts.length - 1].replace(/-/g, " ");
}

function SastTab({
  scanId,
  isAdmin,
  hideDismissed,
  setHideDismissed,
}: {
  scanId: string;
  isAdmin: boolean;
  hideDismissed: boolean;
  setHideDismissed: (v: boolean) => void;
}) {
  const findings = useSastFindings(scanId);
  const triage = useTriageSastFinding(scanId);
  const [expanded, setExpanded] = useState<string | null>(null);

  if (findings.isLoading) {
    return (
      <Card>
        <CardContent className="p-6 text-sm text-muted-foreground">Loading SAST findings…</CardContent>
      </Card>
    );
  }

  const allSast = findings.data ?? [];
  const visible = hideDismissed
    ? allSast.filter((f) => f.triage_status !== "false_positive" && f.triage_status !== "suppressed")
    : allSast;
  const hasDismissed = allSast.some((f) => f.triage_status === "false_positive" || f.triage_status === "suppressed");

  if (allSast.length === 0) {
    return (
      <Card>
        <CardContent className="p-6 flex items-center gap-3 text-sm text-muted-foreground">
          <ScanSearch className="h-4 w-4 shrink-0" />
          No SAST findings for this scan.
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {hasDismissed ? (
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1.5 text-xs cursor-pointer select-none">
            <input
              type="checkbox"
              checked={hideDismissed}
              onChange={(e) => setHideDismissed(e.target.checked)}
              className="rounded"
            />
            Hide false positives &amp; suppressed
          </label>
        </div>
      ) : null}
      <Card>
        {visible.length === 0 ? (
          <CardContent className="p-6 text-sm text-muted-foreground">
            All findings are dismissed. Uncheck the filter to see them.
          </CardContent>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-4" />
                <TableHead className="w-24">Severity</TableHead>
                <TableHead>Summary</TableHead>
                <TableHead className="w-40">File : Line</TableHead>
                <TableHead className="w-32">Status</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visible.map((f: SastFinding) => {
                const isExpanded = expanded === f.id;
                const isDismissed = f.triage_status === "false_positive" || f.triage_status === "suppressed";
                return (
                  <>
                    <TableRow
                      key={f.id}
                      className="cursor-pointer hover:bg-muted/50"
                      onClick={() => setExpanded(isExpanded ? null : f.id)}
                    >
                      <TableCell className="w-4">
                        {isExpanded ? (
                          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                        )}
                      </TableCell>
                      <TableCell>
                        <SastSeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground max-w-sm truncate">
                        {sastSummary(f)}
                      </TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">
                        {f.file_path}:{f.start_line}
                      </TableCell>
                      <TableCell>
                        <TriageBadge status={f.triage_status} />
                      </TableCell>
                    </TableRow>
                    {isExpanded ? (
                      <TableRow key={`${f.id}-detail`}>
                        <TableCell colSpan={5} className="bg-muted/30 py-3 px-6">
                          <div className="space-y-3 text-sm">
                            {f.snippet ? (
                              <pre className="rounded bg-background border p-3 text-xs overflow-x-auto font-mono whitespace-pre-wrap">
                                {f.snippet}
                              </pre>
                            ) : null}
                            {f.rule_message ? (
                              <p className="text-muted-foreground">{f.rule_message}</p>
                            ) : null}
                            {f.triage_reasoning ? (
                              <div className="space-y-1">
                                <p className="text-xs font-medium uppercase text-muted-foreground">LLM reasoning</p>
                                <p className="text-xs">{f.triage_reasoning}</p>
                              </div>
                            ) : null}
                            {f.cwe_ids.length > 0 ? (
                              <div className="flex gap-1">
                                {f.cwe_ids.map((cwe) => (
                                  <Badge key={cwe} variant="outline" className="font-mono text-xs">
                                    {cwe}
                                  </Badge>
                                ))}
                              </div>
                            ) : null}
                            {isAdmin ? (
                              <div className="flex flex-wrap gap-2 pt-1">
                                {!isDismissed ? (
                                  <>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="text-xs h-7"
                                      disabled={triage.isPending}
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        triage.mutate({ findingId: f.id, status: "false_positive" });
                                      }}
                                    >
                                      Mark False Positive
                                    </Button>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      className="text-xs h-7"
                                      disabled={triage.isPending}
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        triage.mutate({ findingId: f.id, status: "suppressed" });
                                      }}
                                    >
                                      Suppress
                                    </Button>
                                    {f.triage_status !== "confirmed" ? (
                                      <Button
                                        size="sm"
                                        variant="outline"
                                        className="text-xs h-7 text-red-600"
                                        disabled={triage.isPending}
                                        onClick={(e) => {
                                          e.stopPropagation();
                                          triage.mutate({ findingId: f.id, status: "confirmed" });
                                        }}
                                      >
                                        Confirm
                                      </Button>
                                    ) : null}
                                  </>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="text-xs h-7"
                                    disabled={triage.isPending}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      triage.mutate({ findingId: f.id, status: "pending" });
                                    }}
                                  >
                                    Reset to Pending
                                  </Button>
                                )}
                              </div>
                            ) : null}
                          </div>
                        </TableCell>
                      </TableRow>
                    ) : null}
                  </>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SCA filter bar
// ---------------------------------------------------------------------------

const SCA_SEVERITIES: FindingSeverity[] = ["critical", "high", "medium", "low", "unknown"];
const SCA_TYPES: Array<{ value: string; label: string }> = [
  { value: "cve", label: "CVE" },
  { value: "eol", label: "EOL" },
  { value: "deprecated", label: "Deprecated" },
];

interface ScaFilterBarProps {
  findings: ScanFinding[];
  filterSeverities: Set<string>;
  setFilterSeverities: (s: Set<string>) => void;
  filterTypes: Set<string>;
  setFilterTypes: (s: Set<string>) => void;
  hideDevDeps: boolean;
  setHideDevDeps: (v: boolean) => void;
  hideNoFix: boolean;
  setHideNoFix: (v: boolean) => void;
  hideNonReachable: boolean;
  setHideNonReachable: (v: boolean) => void;
}

function ScaFilterBar({
  findings,
  filterSeverities,
  setFilterSeverities,
  filterTypes,
  setFilterTypes,
  hideDevDeps,
  setHideDevDeps,
  hideNoFix,
  setHideNoFix,
  hideNonReachable,
  setHideNonReachable,
}: ScaFilterBarProps) {
  const hasDevDeps = findings.some((f) => f.component_scope === "optional");
  const hasNoFix = findings.some((f) => f.finding_type === "cve" && !f.has_fix);
  const hasReachability = findings.some((f) => f.reachable_assessed_at !== null);
  const isFiltered =
    filterSeverities.size > 0 ||
    filterTypes.size > 0 ||
    hideDevDeps ||
    hideNoFix ||
    hideNonReachable;

  function toggleSeverity(s: string) {
    const next = new Set(filterSeverities);
    next.has(s) ? next.delete(s) : next.add(s);
    setFilterSeverities(next);
  }

  function toggleType(t: string) {
    const next = new Set(filterTypes);
    next.has(t) ? next.delete(t) : next.add(t);
    setFilterTypes(next);
  }

  return (
    <div className="mb-3 space-y-2">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
        {/* Severity chips */}
        <div className="flex items-center gap-1">
          <span className="text-muted-foreground uppercase font-medium tracking-wide mr-1">Severity</span>
          {SCA_SEVERITIES.map((s) => {
            const active = filterSeverities.has(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => toggleSeverity(s)}
                className={cn(
                  "rounded border px-2 py-0.5 text-xs font-semibold uppercase transition-opacity",
                  active ? severityChipClass(s) : "bg-muted text-muted-foreground border-border opacity-50",
                )}
              >
                {s}
              </button>
            );
          })}
        </div>

        {/* Type chips */}
        <div className="flex items-center gap-1">
          <span className="text-muted-foreground uppercase font-medium tracking-wide mr-1">Type</span>
          {SCA_TYPES.map(({ value, label }) => {
            const active = filterTypes.has(value);
            return (
              <button
                key={value}
                type="button"
                onClick={() => toggleType(value)}
                className={cn(
                  "rounded border px-2 py-0.5 text-xs font-medium transition-opacity",
                  active
                    ? "bg-foreground text-background border-foreground"
                    : "bg-muted text-muted-foreground border-border opacity-50",
                )}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Toggle filters */}
        <div className="flex items-center gap-3">
          {hasDevDeps ? (
            <label className="flex items-center gap-1.5 cursor-pointer select-none">
              <input type="checkbox" checked={hideDevDeps} onChange={(e) => setHideDevDeps(e.target.checked)} className="rounded" />
              Hide dev-only deps
            </label>
          ) : null}
          {hasNoFix ? (
            <label className="flex items-center gap-1.5 cursor-pointer select-none">
              <input type="checkbox" checked={hideNoFix} onChange={(e) => setHideNoFix(e.target.checked)} className="rounded" />
              Has fix available
            </label>
          ) : null}
          {hasReachability ? (
            <label className="flex items-center gap-1.5 cursor-pointer select-none">
              <input type="checkbox" checked={hideNonReachable} onChange={(e) => setHideNonReachable(e.target.checked)} className="rounded" />
              <Zap className="h-3 w-3 text-blue-500" />
              Reachable only
            </label>
          ) : null}
        </div>

        {/* Clear */}
        {isFiltered ? (
          <button
            type="button"
            className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground"
            onClick={() => {
              setFilterSeverities(new Set());
              setFilterTypes(new Set());
              setHideDevDeps(false);
              setHideNoFix(false);
              setHideNonReachable(false);
            }}
          >
            Clear filters
          </button>
        ) : null}
      </div>
    </div>
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
  const currentUser = useAuthStore((s) => s.user);
  const isAdmin = currentUser?.role === "admin";

  // SCA filter state
  const [filterSeverities, setFilterSeverities] = useState<Set<string>>(new Set());
  const [filterTypes, setFilterTypes] = useState<Set<string>>(new Set());
  const [hideDevDeps, setHideDevDeps] = useState(false);
  const [hideNoFix, setHideNoFix] = useState(false);
  const [hideNonReachable, setHideNonReachable] = useState(false);
  // SAST filter state
  const [hideDismissedSast, setHideDismissedSast] = useState(false);

  const repoName = repos.data?.find((r) => r.id === scan.data?.repo_id)?.name;
  const allFindings = findings.data ?? [];

  const sorted = sortFindings(
    allFindings.filter((f) => {
      if (filterSeverities.size > 0 && !filterSeverities.has(f.severity)) return false;
      if (filterTypes.size > 0 && !filterTypes.has(f.finding_type)) return false;
      if (hideDevDeps && f.component_scope === "optional") return false;
      if (hideNoFix && f.finding_type === "cve" && !f.has_fix) return false;
      if (hideNonReachable && f.finding_type === "cve" && f.reachable_assessed_at !== null && !f.confirmed_reachable) return false;
      return true;
    }),
  );

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
    <TooltipProvider>
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

      {/* Warnings banner */}
      {s.warnings && s.warnings.length > 0 ? (
        <Card className="border-amber-200 dark:border-amber-900">
          <CardContent className="p-4 space-y-1">
            {s.warnings.map((w, i) => (
              <div key={i} className="flex gap-2 text-sm text-amber-700 dark:text-amber-300">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>{w.message}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      ) : null}

      {/* Summary cards */}
      {isTerminal && s.status === "success" ? (
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
          <SummaryCard label="Components" value={s.component_count} />
          <SummaryCard label="Critical" value={s.critical_count} severity="critical" />
          <SummaryCard label="High" value={s.high_count} severity="high" />
          <SummaryCard label="Medium" value={s.medium_count} severity="medium" />
          <SummaryCard label="Low" value={s.low_count} severity="low" />
          <SummaryCard label="Reachable" value={s.confirmed_reachable_count} />
        </div>
      ) : null}

      {/* LLM usage card — only when at least one LLM call was made */}
      {isTerminal && s.status === "success" && s.llm_request_count > 0 ? (
        <Card>
          <CardContent className="p-4 flex flex-wrap gap-6 text-sm">
            <div>
              <p className="text-xs uppercase text-muted-foreground mb-0.5">LLM requests</p>
              <p className="font-semibold">{s.llm_request_count}</p>
            </div>
            <div>
              <p className="text-xs uppercase text-muted-foreground mb-0.5">Tokens (in/out)</p>
              <p className="font-semibold font-mono">
                {s.llm_input_tokens.toLocaleString()} / {s.llm_output_tokens.toLocaleString()}
              </p>
            </div>
            <div>
              <p className="text-xs uppercase text-muted-foreground mb-0.5">Budget used</p>
              <p className="font-semibold">
                {Math.round(((s.llm_input_tokens + s.llm_output_tokens) / 50000) * 100)}%
              </p>
            </div>
          </CardContent>
        </Card>
      ) : null}

      {/* Tabbed content: Findings + Components */}
      {isTerminal && s.status === "success" ? (
        <Tabs defaultValue="findings">
          <TabsList>
            <TabsTrigger value="findings" className="gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" />
              SCA Findings
              {allFindings.length > 0 ? (
                <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs font-mono">
                  {allFindings.length}
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
            <TabsTrigger value="sast" className="gap-1.5">
              <ScanSearch className="h-3.5 w-3.5" />
              SAST Findings
              {s.sast_finding_count > 0 ? (
                <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-xs font-mono">
                  {s.sast_finding_count}
                </span>
              ) : null}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="findings" className="mt-4">
            {/* Unified SCA filter bar */}
            <ScaFilterBar
              findings={allFindings}
              filterSeverities={filterSeverities}
              setFilterSeverities={setFilterSeverities}
              filterTypes={filterTypes}
              setFilterTypes={setFilterTypes}
              hideDevDeps={hideDevDeps}
              setHideDevDeps={setHideDevDeps}
              hideNoFix={hideNoFix}
              setHideNoFix={setHideNoFix}
              hideNonReachable={hideNonReachable}
              setHideNonReachable={setHideNonReachable}
            />
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
                  No findings match the current filters.
                </CardContent>
              </Card>
            ) : (
              <Card>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-8" />
                      <TableHead className="w-28">Severity</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead>CVE / ID</TableHead>
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

          <TabsContent value="sast" className="mt-4">
            <SastTab
              scanId={id!}
              isAdmin={isAdmin}
              hideDismissed={hideDismissedSast}
              setHideDismissed={setHideDismissedSast}
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
    </TooltipProvider>
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
