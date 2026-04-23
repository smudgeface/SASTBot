import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  ExternalLink,
  ShieldAlert,
  Zap,
} from "lucide-react";

import {
  useScopeDetail,
  useScopeSastIssues,
  useScopeScaIssues,
  useScopeComponents,
  useScopeScans,
  useTriageSastIssue,
  useDismissScaIssue,
  type SastIssueFilters,
  type ScaIssueFilters,
} from "@/api/queries/scopes";
import { useTriggerScan } from "@/api/queries/scans";
import { useMe } from "@/api/queries/auth";
import type { SastIssue, ScaIssue } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatRelative } from "@/lib/format";

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-600 border-red-400",
  high: "bg-orange-500/20 text-orange-600 border-orange-400",
  medium: "bg-yellow-500/20 text-yellow-600 border-yellow-400",
  low: "bg-blue-500/20 text-blue-600 border-blue-400",
  info: "bg-slate-500/20 text-slate-600 border-slate-400",
  unknown: "bg-slate-500/20 text-slate-500 border-slate-300",
};

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant="outline" className={`uppercase text-[10px] px-1.5 ${SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.unknown}`}>
      {severity}
    </Badge>
  );
}

const TRIAGE_COLORS: Record<string, string> = {
  pending: "text-amber-600 border-amber-400",
  confirmed: "text-red-600 border-red-400",
  false_positive: "text-slate-500 border-slate-400",
  suppressed: "text-slate-500 border-slate-400",
  error: "text-destructive border-destructive",
};

function TriageBadge({ status }: { status: string }) {
  const label = status.replace("_", " ");
  return (
    <Badge variant="outline" className={`capitalize text-[10px] ${TRIAGE_COLORS[status] ?? ""}`}>
      {label}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Filter bar primitives
// ---------------------------------------------------------------------------

/** Thin vertical line used to separate filter groups. */
function Pipe() {
  return <div className="self-stretch w-px bg-border mx-1" />;
}

/**
 * A group of mutually-exclusive filter chips joined by "|" separators.
 * Clicking an active chip deselects it (nothing selected = show all).
 */
function RadioGroup<T extends string>({
  items,
  active,
  onToggle,
  label,
  colorFn,
}: {
  items: readonly T[];
  active: T | undefined;
  onToggle: (v: T) => void;
  label?: (v: T) => string;
  colorFn?: (v: T) => string;
}) {
  const baseInactive = "border-transparent text-muted-foreground hover:border-border hover:text-foreground";
  return (
    <div className="flex items-center gap-0">
      {items.map((item, i) => (
        <div key={item} className="flex items-center">
          {i > 0 && (
            <span className="mx-1 text-[10px] text-muted-foreground/50 select-none">|</span>
          )}
          <button
            onClick={() => onToggle(item)}
            className={`rounded px-2 py-0.5 text-xs font-medium border transition-colors ${
              active === item
                ? (colorFn ? colorFn(item) : "bg-accent text-accent-foreground border-border")
                : baseInactive
            }`}
          >
            {label ? label(item) : item}
          </button>
        </div>
      ))}
    </div>
  );
}

/**
 * A group of independent boolean toggles — multiple can be active at once.
 * No "|" separators; items sit side by side with a small gap.
 */
function ToggleGroup({
  items,
}: {
  items: { key: string; label: string; active: boolean; onToggle: () => void }[];
}) {
  return (
    <div className="flex items-center gap-1.5">
      {items.map(({ key, label, active, onToggle }) => (
        <button
          key={key}
          onClick={onToggle}
          className={`rounded px-2 py-0.5 text-xs border transition-colors ${
            active
              ? "bg-accent text-accent-foreground border-border"
              : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
          }`}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pagination control
// ---------------------------------------------------------------------------

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
    <div className="flex items-center justify-between text-xs text-muted-foreground pt-2">
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

// ---------------------------------------------------------------------------
// SAST issues tab
// ---------------------------------------------------------------------------

function SastIssueRow({ issue, isAdmin }: { issue: SastIssue; isAdmin: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const triage = useTriageSastIssue();

  const act = (status: "confirmed" | "false_positive" | "suppressed" | "pending") => {
    triage.mutate({ issueId: issue.id, status });
  };

  return (
    <>
      <TableRow
        className="cursor-pointer hover:bg-muted/40"
        onClick={() => setExpanded((v) => !v)}
      >
        <TableCell className="w-6 text-muted-foreground">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </TableCell>
        <TableCell>
          <SeverityBadge severity={issue.latest_severity} />
        </TableCell>
        <TableCell className="max-w-xs">
          <div className="font-mono text-xs truncate">{issue.latest_rule_id}</div>
          {issue.latest_rule_message && (
            <div className="text-xs text-muted-foreground truncate">{issue.latest_rule_message}</div>
          )}
        </TableCell>
        <TableCell className="text-xs text-muted-foreground font-mono">
          {issue.latest_file_path}:{issue.latest_start_line}
        </TableCell>
        <TableCell>
          <TriageBadge status={issue.triage_status} />
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          {formatRelative(issue.last_seen_at)}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 p-4">
            {issue.latest_snippet && (
              <pre className="mb-3 overflow-x-auto rounded bg-background p-3 text-xs font-mono border">
                {issue.latest_snippet}
              </pre>
            )}
            {issue.triage_reasoning && (
              <p className="mb-3 text-sm">
                <span className="font-medium">LLM reasoning: </span>
                {issue.triage_reasoning}
              </p>
            )}
            {issue.latest_cwe_ids?.length > 0 && (
              <p className="mb-3 text-xs text-muted-foreground">CWE: {issue.latest_cwe_ids.join(", ")}</p>
            )}
            {isAdmin && (
              <div className="flex flex-wrap gap-2">
                {issue.triage_status !== "confirmed" && (
                  <Button size="sm" variant="destructive" disabled={triage.isPending} onClick={() => act("confirmed")}>
                    Confirm
                  </Button>
                )}
                {issue.triage_status !== "false_positive" && (
                  <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("false_positive")}>
                    False positive
                  </Button>
                )}
                {issue.triage_status !== "suppressed" && (
                  <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("suppressed")}>
                    Suppress
                  </Button>
                )}
                {issue.triage_status !== "pending" && (
                  <Button size="sm" variant="ghost" disabled={triage.isPending} onClick={() => act("pending")}>
                    Reset to pending
                  </Button>
                )}
              </div>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function SastIssuesTab({ scopeId }: { scopeId: string }) {
  const { data: user } = useMe();
  const isAdmin = user?.role === "admin";
  const [filters, setFilters] = useState<SastIssueFilters>({ page: 1, page_size: 50 });

  const { data, isLoading } = useScopeSastIssues(scopeId, filters);

  const SAST_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
  const SAST_STATUSES = ["pending", "confirmed", "false_positive", "suppressed"] as const;

  const hasFilter = !!(filters.severity || filters.triage_status || filters.include_resolved);

  return (
    <div className="space-y-3">
      {/* Filter bar — | separates radio groups; toggle groups have no | */}
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0">
        <RadioGroup
          items={SAST_SEVERITIES}
          active={filters.severity as typeof SAST_SEVERITIES[number] | undefined}
          onToggle={(s) => setFilters((f) => ({ ...f, page: 1, severity: f.severity === s ? undefined : s }))}
          colorFn={(s) => SEVERITY_COLORS[s] ?? ""}
        />
        <Pipe />
        <RadioGroup
          items={SAST_STATUSES}
          active={filters.triage_status as typeof SAST_STATUSES[number] | undefined}
          onToggle={(s) => setFilters((f) => ({ ...f, page: 1, triage_status: f.triage_status === s ? undefined : s }))}
          label={(s) => s.replace(/_/g, " ")}
        />
        <Pipe />
        <ToggleGroup
          items={[{
            key: "include_resolved",
            label: "Include resolved",
            active: !!filters.include_resolved,
            onToggle: () => setFilters((f) => ({ ...f, page: 1, include_resolved: !f.include_resolved })),
          }]}
        />
        {hasFilter && (
          <>
            <Pipe />
            <button
              className="text-xs text-muted-foreground underline underline-offset-2 px-1"
              onClick={() => setFilters({ page: 1, page_size: 50 })}
            >
              Clear
            </button>
          </>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : !data || data.total === 0 ? (
        <p className="text-sm text-muted-foreground py-6 text-center">No SAST issues match the current filters.</p>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-6" />
                <TableHead>Severity</TableHead>
                <TableHead>Rule</TableHead>
                <TableHead>Location</TableHead>
                <TableHead>Triage</TableHead>
                <TableHead>Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((issue) => (
                <SastIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} />
              ))}
            </TableBody>
          </Table>
          <Pager
            page={filters.page ?? 1}
            pageSize={filters.page_size ?? 50}
            total={data.total}
            onPage={(p) => setFilters((f) => ({ ...f, page: p }))}
          />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// SCA issues tab
// ---------------------------------------------------------------------------

function ScaIssueRow({ issue, isAdmin }: { issue: ScaIssue; isAdmin: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const dismiss = useDismissScaIssue();

  const act = (status: "active" | "acknowledged" | "wont_fix" | "false_positive") => {
    dismiss.mutate({ issueId: issue.id, status });
  };

  const isDev = issue.latest_component_scope === "optional";

  return (
    <>
      <TableRow
        className="cursor-pointer hover:bg-muted/40"
        onClick={() => setExpanded((v) => !v)}
      >
        <TableCell className="w-6 text-muted-foreground">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </TableCell>
        <TableCell>
          <SeverityBadge severity={issue.latest_severity} />
        </TableCell>
        <TableCell className="max-w-xs">
          <div className="font-medium text-sm">
            {issue.package_name}
            {issue.latest_package_version ? `@${issue.latest_package_version}` : ""}
          </div>
          <div className="flex flex-wrap gap-1 mt-0.5">
            <span className="text-[10px] text-muted-foreground uppercase font-medium">
              {issue.latest_finding_type}
            </span>
            {issue.latest_cve_id && (
              <span className="text-[10px] font-mono text-muted-foreground">{issue.latest_cve_id}</span>
            )}
            {isDev && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-slate-500 border-slate-300">
                DEV
              </Badge>
            )}
            {issue.latest_has_fix && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-green-600 border-green-400">
                has fix
              </Badge>
            )}
            {issue.confirmed_reachable && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-amber-600 border-amber-400 gap-0.5">
                <Zap className="h-2.5 w-2.5" /> reachable
              </Badge>
            )}
          </div>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground max-w-sm truncate">
          {issue.latest_summary}
        </TableCell>
        <TableCell>
          {issue.dismissed_status !== "active" && (
            <Badge variant="outline" className="capitalize text-[10px] text-slate-500 border-slate-400">
              {issue.dismissed_status.replace("_", " ")}
            </Badge>
          )}
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          {formatRelative(issue.last_seen_at)}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 p-4 space-y-3">
            {issue.latest_summary && (
              <p className="text-sm">{issue.latest_summary}</p>
            )}
            <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span><span className="font-medium">OSV ID:</span> {issue.osv_id}</span>
              {issue.latest_cvss_score != null && (
                <span><span className="font-medium">CVSS:</span> {issue.latest_cvss_score.toFixed(1)}</span>
              )}
              {issue.latest_ecosystem && (
                <span><span className="font-medium">Ecosystem:</span> {issue.latest_ecosystem}</span>
              )}
              {issue.reachable_reasoning && (
                <span><span className="font-medium">Reachability:</span> {issue.reachable_reasoning}</span>
              )}
            </div>
            {issue.latest_aliases.length > 0 && (
              <p className="text-xs text-muted-foreground">Aliases: {issue.latest_aliases.join(", ")}</p>
            )}
            {isAdmin && (
              <div className="flex flex-wrap gap-2 pt-1">
                {issue.dismissed_status !== "active" && (
                  <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("active")}>
                    Reopen
                  </Button>
                )}
                {issue.dismissed_status === "active" && (
                  <>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("acknowledged")}>
                      Acknowledge
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("wont_fix")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("false_positive")}>
                      False positive
                    </Button>
                  </>
                )}
              </div>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function ScaIssuesTab({ scopeId }: { scopeId: string }) {
  const { data: user } = useMe();
  const isAdmin = user?.role === "admin";
  const [filters, setFilters] = useState<ScaIssueFilters>({ page: 1, page_size: 50 });

  const { data, isLoading } = useScopeScaIssues(scopeId, filters);

  const SCA_SEVERITIES = ["critical", "high", "medium", "low"] as const;
  const SCA_TYPES = ["cve", "eol", "deprecated"] as const;

  const hasScaFilter = !!(
    filters.severity || filters.finding_type ||
    filters.reachable || filters.has_fix || filters.hide_dev || filters.include_resolved
  );

  return (
    <div className="space-y-3">
      {/* Filter bar — | = radio (pick one); no | = stackable toggles */}
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0">
        <RadioGroup
          items={SCA_SEVERITIES}
          active={filters.severity as typeof SCA_SEVERITIES[number] | undefined}
          onToggle={(s) => setFilters((f) => ({ ...f, page: 1, severity: f.severity === s ? undefined : s }))}
          colorFn={(s) => SEVERITY_COLORS[s] ?? ""}
        />
        <Pipe />
        <RadioGroup
          items={SCA_TYPES}
          active={filters.finding_type as typeof SCA_TYPES[number] | undefined}
          onToggle={(s) => setFilters((f) => ({ ...f, page: 1, finding_type: f.finding_type === s ? undefined : s }))}
          label={(t) => t.toUpperCase()}
        />
        <Pipe />
        <ToggleGroup
          items={[
            { key: "reachable", label: "Reachable", active: !!filters.reachable, onToggle: () => setFilters((f) => ({ ...f, page: 1, reachable: !f.reachable })) },
            { key: "has_fix",   label: "Has fix",   active: !!filters.has_fix,   onToggle: () => setFilters((f) => ({ ...f, page: 1, has_fix: !f.has_fix })) },
            { key: "hide_dev",  label: "Hide dev",  active: !!filters.hide_dev,  onToggle: () => setFilters((f) => ({ ...f, page: 1, hide_dev: !f.hide_dev })) },
          ]}
        />
        <Pipe />
        <ToggleGroup
          items={[{
            key: "include_resolved",
            label: "Include resolved",
            active: !!filters.include_resolved,
            onToggle: () => setFilters((f) => ({ ...f, page: 1, include_resolved: !f.include_resolved })),
          }]}
        />
        {hasScaFilter && (
          <>
            <Pipe />
            <button
              className="text-xs text-muted-foreground underline underline-offset-2 px-1"
              onClick={() => setFilters({ page: 1, page_size: 50 })}
            >
              Clear
            </button>
          </>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : !data || data.total === 0 ? (
        <p className="text-sm text-muted-foreground py-6 text-center">No SCA issues match the current filters.</p>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-6" />
                <TableHead>Severity</TableHead>
                <TableHead>Package</TableHead>
                <TableHead>Summary</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last seen</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((issue) => (
                <ScaIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} />
              ))}
            </TableBody>
          </Table>
          <Pager
            page={filters.page ?? 1}
            pageSize={filters.page_size ?? 50}
            total={data.total}
            onPage={(p) => setFilters((f) => ({ ...f, page: p }))}
          />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Components tab
// ---------------------------------------------------------------------------

function ComponentsTab({ scopeId }: { scopeId: string }) {
  const [page, setPage] = useState(1);
  const [hasFindings, setHasFindings] = useState(false);
  const { data, isLoading } = useScopeComponents(scopeId, { page, page_size: 50, has_findings: hasFindings || undefined });

  return (
    <div className="space-y-3">
      <div className="flex gap-2">
        <button
          onClick={() => { setHasFindings((v) => !v); setPage(1); }}
          className={`rounded px-2 py-0.5 text-xs border transition-colors ${
            hasFindings
              ? "bg-accent text-accent-foreground border-border"
              : "border-transparent text-muted-foreground hover:border-border"
          }`}
        >
          Only with findings
        </button>
      </div>
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : !data || data.total === 0 ? (
        <p className="text-sm text-muted-foreground py-6 text-center">No components in the most recent scan.</p>
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Package</TableHead>
                <TableHead>Version</TableHead>
                <TableHead>Ecosystem</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Scope</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className="font-mono text-sm">{c.name}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{c.version ?? "—"}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">{c.ecosystem ?? "—"}</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{c.component_type}</TableCell>
                  <TableCell className="text-xs">
                    {c.scope === "optional" ? (
                      <Badge variant="outline" className="text-[9px] text-slate-500">DEV</Badge>
                    ) : c.scope ?? "—"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Pager page={page} pageSize={50} total={data.total} onPage={setPage} />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recent scans drawer
// ---------------------------------------------------------------------------

function RecentScansSection({ scopeId }: { scopeId: string }) {
  const [open, setOpen] = useState(false);
  const { data: scans } = useScopeScans(scopeId, 10);

  return (
    <div className="border rounded-lg">
      <button
        className="flex w-full items-center justify-between px-4 py-3 text-sm font-medium hover:bg-muted/50"
        onClick={() => setOpen((v) => !v)}
        type="button"
      >
        <span>Recent scans</span>
        {open ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
      </button>
      {open && (
        <div className="border-t">
          {!scans || scans.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No scans yet.</p>
          ) : (
            <ul className="divide-y">
              {scans.map((s) => (
                <li key={s.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                  <div className="flex items-center gap-3">
                    <span
                      className={`inline-block h-2 w-2 rounded-full ${
                        s.status === "success"
                          ? "bg-green-500"
                          : s.status === "failed"
                          ? "bg-destructive"
                          : "bg-amber-400"
                      }`}
                    />
                    <span className="text-muted-foreground text-xs">
                      {s.finished_at ? formatRelative(s.finished_at) : "running…"}
                    </span>
                    {s.critical_count > 0 && (
                      <span className="text-[10px] text-destructive">{s.critical_count}C</span>
                    )}
                    {s.sast_finding_count > 0 && (
                      <span className="text-[10px] text-muted-foreground">{s.sast_finding_count} SAST</span>
                    )}
                  </div>
                  <Link
                    to={`/scans/${s.id}`}
                    className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                    onClick={(e) => e.stopPropagation()}
                  >
                    View <ExternalLink className="h-3 w-3" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main page
// ---------------------------------------------------------------------------

export default function ScopeDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data: scope, isLoading, isError } = useScopeDetail(id);
  const triggerScan = useTriggerScan();

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !scope) return <p className="text-sm text-destructive">Scope not found.</p>;

  const handleTriggerScan = () => {
    triggerScan.mutate(scope.repo_id);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">
            {scope.repo_name}
            {scope.path !== "/" && (
              <span className="text-muted-foreground font-normal"> · {scope.path}</span>
            )}
          </h1>
          <p className="text-sm text-muted-foreground">
            Branch: {scope.repo_branch}
            {scope.last_scan_completed_at && (
              <> · Last scan: {formatRelative(scope.last_scan_completed_at)}</>
            )}
          </p>
        </div>
        <Button
          size="sm"
          onClick={handleTriggerScan}
          disabled={triggerScan.isPending}
        >
          Scan now
        </Button>
      </div>

      {/* Summary chips */}
      <div className="flex flex-wrap gap-3">
        <Card className="flex-none">
          <CardContent className="px-4 py-3 flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-destructive" />
            <div>
              <div className="text-lg font-bold leading-none">{scope.active_sca_issue_count}</div>
              <div className="text-xs text-muted-foreground">SCA issues</div>
            </div>
          </CardContent>
        </Card>
        <Card className="flex-none">
          <CardContent className="px-4 py-3 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-orange-500" />
            <div>
              <div className="text-lg font-bold leading-none">{scope.active_sast_issue_count}</div>
              <div className="text-xs text-muted-foreground">SAST issues</div>
            </div>
          </CardContent>
        </Card>
        {(scope.critical_count > 0 || scope.high_count > 0) && (
          <Card className="flex-none">
            <CardContent className="px-4 py-3 flex items-center gap-2">
              <div className="flex gap-1.5">
                {scope.critical_count > 0 && (
                  <Badge variant="outline" className={SEVERITY_COLORS.critical}>
                    {scope.critical_count} Critical
                  </Badge>
                )}
                {scope.high_count > 0 && (
                  <Badge variant="outline" className={SEVERITY_COLORS.high}>
                    {scope.high_count} High
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>
        )}
        {scope.pending_triage_count > 0 && (
          <Card className="flex-none">
            <CardContent className="px-4 py-3 flex items-center gap-2">
              <Clock className="h-4 w-4 text-amber-500" />
              <div>
                <div className="text-lg font-bold leading-none">{scope.pending_triage_count}</div>
                <div className="text-xs text-muted-foreground">Pending triage</div>
              </div>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Main tabs */}
      <Tabs defaultValue="sca">
        <TabsList>
          <TabsTrigger value="sca">
            SCA Issues
            {scope.active_sca_issue_count > 0 && (
              <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">
                {scope.active_sca_issue_count}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="sast">
            SAST Issues
            {scope.active_sast_issue_count > 0 && (
              <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">
                {scope.active_sast_issue_count}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="components">Components</TabsTrigger>
        </TabsList>

        <TabsContent value="sca" className="mt-4">
          {id && <ScaIssuesTab scopeId={id} />}
        </TabsContent>
        <TabsContent value="sast" className="mt-4">
          {id && <SastIssuesTab scopeId={id} />}
        </TabsContent>
        <TabsContent value="components" className="mt-4">
          {id && <ComponentsTab scopeId={id} />}
        </TabsContent>
      </Tabs>

      {/* Recent scans */}
      {id && <RecentScansSection scopeId={id} />}
    </div>
  );
}
