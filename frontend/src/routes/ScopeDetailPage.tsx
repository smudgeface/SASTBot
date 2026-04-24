import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  ExternalLink,
  Loader2,
  RefreshCw,
  ShieldAlert,
  Unlink,
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
import {
  useLinkSastIssueToJira,
  useLinkScaIssueToJira,
  useRefreshJiraTicket,
  useScopeJiraTickets,
  useUnlinkSastIssueFromJira,
  useUnlinkScaIssueFromJira,
} from "@/api/queries/jira";
import type { JiraTicket } from "@/api/types";
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

const TRIAGE_LABELS: Record<string, string> = {
  pending: "pending",
  confirmed: "confirmed",
  false_positive: "invalid",
  suppressed: "won't fix",
  error: "error",
};

const SCA_STATUS_LABELS: Record<string, string> = {
  active: "active",
  acknowledged: "acknowledged",
  wont_fix: "won't fix",
  false_positive: "invalid",
};

function TriageBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={`capitalize text-[10px] ${TRIAGE_COLORS[status] ?? ""}`}>
      {TRIAGE_LABELS[status] ?? status.replace(/_/g, " ")}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Vuln link helpers
// ---------------------------------------------------------------------------

/** Show only the last two path segments to keep the Location column compact.
 *  Full path is always available in the row's title tooltip. */
function truncateFilePath(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  if (parts.length <= 2) return path;
  return "…/" + parts.slice(-2).join("/");
}

function vulnUrl(id: string): string {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

function VulnLink({ id, className }: { id: string; className?: string }) {
  return (
    <a
      href={vulnUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      className={`font-mono hover:underline text-blue-600 dark:text-blue-400 ${className ?? ""}`}
    >
      {id}
    </a>
  );
}

// ---------------------------------------------------------------------------
// Jira chip + link popover
// ---------------------------------------------------------------------------

const SC_COLORS: Record<string, string> = {
  new: "text-slate-500 border-slate-400",
  indeterminate: "text-blue-600 border-blue-400",
  done: "text-green-600 border-green-400",
};

function JiraChip({
  ticket,
  onRefresh,
  onUnlink,
  isPending,
}: {
  ticket: JiraTicket;
  onRefresh: () => void;
  onUnlink: () => void;
  isPending: boolean;
}) {
  const [open, setOpen] = useState(false);
  const scColor = SC_COLORS[ticket.status_category ?? ""] ?? SC_COLORS.new;
  const parts = [
    ticket.issue_key,
    ticket.status ?? "—",
    ticket.resolution ? `· ${ticket.resolution}` : null,
    ticket.assignee_name ? `· ${ticket.assignee_name.split(" ")[0]}` : null,
    ticket.fix_versions.length > 0 ? `· ${ticket.fix_versions[0]}` : null,
  ].filter(Boolean).join(" ");

  return (
    <div className="relative inline-block">
      <button
        onClick={() => setOpen((v) => !v)}
        className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-medium transition-colors ${scColor} ${ticket.sync_error ? "border-amber-400 text-amber-600" : ""}`}
      >
        {ticket.sync_error && <AlertTriangle className="h-2.5 w-2.5" />}
        {parts}
        {ticket.url && <ExternalLink className="h-2.5 w-2.5 opacity-60" />}
      </button>
      {open && (
        <div className="absolute z-50 left-0 top-full mt-1 w-64 rounded-md border bg-popover text-popover-foreground shadow-md p-3 space-y-2 text-xs">
          {ticket.url && (
            <a href={ticket.url} target="_blank" rel="noopener noreferrer"
              className="block font-medium hover:underline text-blue-600">
              {ticket.issue_key}: {ticket.summary ?? ""}
            </a>
          )}
          {ticket.resolution && (
            <p className="text-muted-foreground">Resolution: <span className="font-medium text-foreground">{ticket.resolution}</span></p>
          )}
          {ticket.sync_error && (
            <p className="text-amber-600">Sync error: {ticket.sync_error}</p>
          )}
          {ticket.last_synced_at && (
            <p className="text-muted-foreground">Last synced: {formatRelative(ticket.last_synced_at)}</p>
          )}
          <div className="flex gap-1.5 pt-1 border-t">
            <button onClick={() => { onRefresh(); setOpen(false); }} disabled={isPending}
              className="flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] hover:bg-muted disabled:opacity-50">
              <RefreshCw className="h-2.5 w-2.5" /> Refresh
            </button>
            <button onClick={() => { onUnlink(); setOpen(false); }} disabled={isPending}
              className="flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] hover:bg-muted text-destructive border-destructive/40 disabled:opacity-50">
              <Unlink className="h-2.5 w-2.5" /> Unlink
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function JiraLinkInline({
  onLink,
  isPending,
  error,
}: {
  onLink: (key: string) => void;
  isPending: boolean;
  error?: string;
}) {
  const [key, setKey] = useState("");
  const [open, setOpen] = useState(false);

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="text-[10px] text-muted-foreground hover:text-foreground underline underline-offset-2">
        + Link Jira ticket
      </button>
    );
  }

  return (
    <div className="flex items-center gap-1.5">
      <input
        type="text"
        placeholder="GOS-1234"
        value={key}
        onChange={(e) => setKey(e.target.value.toUpperCase())}
        onKeyDown={(e) => { if (e.key === "Enter" && key) onLink(key); if (e.key === "Escape") setOpen(false); }}
        className="h-6 w-28 rounded border border-border px-1.5 text-xs font-mono bg-background"
        autoFocus
      />
      <button onClick={() => { if (key) onLink(key); }} disabled={isPending || !key}
        className="flex items-center gap-0.5 rounded border px-1.5 py-0.5 text-[10px] hover:bg-muted disabled:opacity-50">
        {isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : "Link"}
      </button>
      <button onClick={() => { setOpen(false); setKey(""); }}
        className="text-[10px] text-muted-foreground hover:text-foreground">Cancel</button>
      {error && <span className="text-[10px] text-destructive">{error}</span>}
    </div>
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
 * A stackable filter group — items joined by "|" separators.
 * Multiple can be active simultaneously; nothing active = show all.
 */
function FilterGroup<T extends string>({
  items,
  active,
  onToggle,
  label,
  colorFn,
}: {
  items: readonly T[];
  active: ReadonlySet<T>;
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
              active.has(item)
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

function SastIssueRow({ issue, isAdmin, jiraTicket }: { issue: SastIssue; isAdmin: boolean; jiraTicket?: JiraTicket | null }) {
  const [expanded, setExpanded] = useState(false);
  const [linkError, setLinkError] = useState<string>();
  const triage = useTriageSastIssue();
  const linkJira = useLinkSastIssueToJira();
  const unlinkJira = useUnlinkSastIssueFromJira();
  const refreshJira = useRefreshJiraTicket();

  const handleLink = (key: string) => {
    setLinkError(undefined);
    linkJira.mutate({ issueId: issue.id, issueKey: key }, {
      onError: (err) => setLinkError(err instanceof Error ? err.message : "Link failed"),
    });
  };

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
        <TableCell>
          <span
            className="text-xs text-muted-foreground font-mono"
            title={`${issue.latest_file_path}:${issue.latest_start_line}`}
          >
            {truncateFilePath(issue.latest_file_path)}:{issue.latest_start_line}
          </span>
        </TableCell>
        <TableCell className="max-w-sm">
          <div className="text-sm text-muted-foreground truncate">
            {issue.latest_rule_message ?? issue.latest_rule_id.split(".").pop()?.replace(/-/g, " ")}
          </div>
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
            <div className="mb-3 flex flex-wrap gap-3 text-xs text-muted-foreground">
              <span><span className="font-medium">Rule: </span><span className="font-mono">{issue.latest_rule_id}</span></span>
              {issue.latest_cwe_ids?.length > 0 && (
                <span><span className="font-medium">CWE: </span>{issue.latest_cwe_ids.join(", ")}</span>
              )}
            </div>
            {/* Jira */}
            <div className="mb-3">
              {jiraTicket ? (
                <JiraChip
                  ticket={jiraTicket}
                  onRefresh={() => refreshJira.mutate(jiraTicket.issue_key)}
                  onUnlink={() => unlinkJira.mutate(issue.id)}
                  isPending={refreshJira.isPending || unlinkJira.isPending}
                />
              ) : isAdmin ? (
                <JiraLinkInline onLink={handleLink} isPending={linkJira.isPending} error={linkError} />
              ) : null}
            </div>
            {isAdmin && (
              <div className="flex flex-wrap gap-2 pt-1">
                {/* Open → show action buttons; triaged → show only Reopen */}
                {(issue.triage_status === "pending" || issue.triage_status === "error") ? (
                  <>
                    <Button size="sm" variant="destructive" disabled={triage.isPending} onClick={() => act("confirmed")}>
                      Confirm
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                  </>
                ) : (
                  <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("pending")}>
                    Reopen
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
  const { data: jiraTickets } = useScopeJiraTickets(scopeId);
  const ticketById = new Map((jiraTickets ?? []).map((t) => [t.id, t]));

  const SAST_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
  const SAST_STATUSES = ["pending", "confirmed", "false_positive", "suppressed"] as const;

  const severitySet = new Set(filters.severities ?? []) as ReadonlySet<typeof SAST_SEVERITIES[number]>;
  const statusSet   = new Set(filters.triage_statuses ?? []) as ReadonlySet<typeof SAST_STATUSES[number]>;

  function toggleSet<T extends string>(
    current: ReadonlySet<T>,
    key: keyof SastIssueFilters,
    value: T,
  ) {
    const next = new Set(current);
    next.has(value) ? next.delete(value) : next.add(value);
    setFilters((f) => ({ ...f, page: 1, [key]: next.size > 0 ? [...next] : undefined }));
  }

  const hasFilter = !!(filters.severities?.length || filters.triage_statuses?.length || filters.include_resolved);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0">
        <FilterGroup
          items={SAST_SEVERITIES}
          active={severitySet}
          onToggle={(s) => toggleSet(severitySet, "severities", s)}
          colorFn={(s) => SEVERITY_COLORS[s] ?? ""}
        />
        <Pipe />
        <FilterGroup
          items={SAST_STATUSES}
          active={statusSet}
          onToggle={(s) => toggleSet(statusSet, "triage_statuses", s)}
          label={(s) => TRIAGE_LABELS[s] ?? s.replace(/_/g, " ")}
        />
        <Pipe />
        <ToggleGroup
          items={[{
            key: "include_resolved",
            label: "include resolved",
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
          <Card>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <TableHead>Severity</TableHead>
                  <TableHead>Location</TableHead>
                  <TableHead>Summary</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((issue) => (
                  <SastIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} jiraTicket={issue.jira_ticket_id ? ticketById.get(issue.jira_ticket_id) : null} />
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
    </div>
  );
}

// ---------------------------------------------------------------------------
// SCA issues tab
// ---------------------------------------------------------------------------

function ScaIssueRow({ issue, isAdmin, jiraTicket }: { issue: ScaIssue; isAdmin: boolean; jiraTicket?: JiraTicket | null }) {
  const [expanded, setExpanded] = useState(false);
  const [linkError, setLinkError] = useState<string>();
  const dismiss = useDismissScaIssue();
  const linkJira = useLinkScaIssueToJira();
  const unlinkJira = useUnlinkScaIssueFromJira();
  const refreshJira = useRefreshJiraTicket();

  const handleLink = (key: string) => {
    setLinkError(undefined);
    linkJira.mutate({ issueId: issue.id, issueKey: key }, {
      onError: (err) => setLinkError(err instanceof Error ? err.message : "Link failed"),
    });
  };

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
              {issue.latest_finding_type === "deprecated" ? "Deprecated" : issue.latest_finding_type.toUpperCase()}
            </span>
            {issue.latest_cve_id && (
              <VulnLink id={issue.latest_cve_id} className="text-[10px]" />
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
              {SCA_STATUS_LABELS[issue.dismissed_status] ?? issue.dismissed_status.replace("_", " ")}
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
              <span>
                <span className="font-medium">OSV:&nbsp;</span>
                <VulnLink id={issue.osv_id} className="text-xs" />
              </span>
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
              <div className="flex flex-wrap gap-1.5 items-center text-xs">
                <span className="text-muted-foreground font-medium">Aliases:</span>
                {issue.latest_aliases
                  .filter((a) => a !== issue.osv_id && a !== issue.latest_cve_id)
                  .map((alias) => (
                    <VulnLink key={alias} id={alias} className="text-xs" />
                  ))}
              </div>
            )}
            {/* Jira */}
            <div>
              {jiraTicket ? (
                <JiraChip
                  ticket={jiraTicket}
                  onRefresh={() => refreshJira.mutate(jiraTicket.issue_key)}
                  onUnlink={() => unlinkJira.mutate(issue.id)}
                  isPending={refreshJira.isPending || unlinkJira.isPending}
                />
              ) : isAdmin ? (
                <JiraLinkInline onLink={handleLink} isPending={linkJira.isPending} error={linkError} />
              ) : null}
            </div>
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
                      Invalid
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
  const { data: jiraTickets } = useScopeJiraTickets(scopeId);
  const ticketById = new Map((jiraTickets ?? []).map((t) => [t.id, t]));

  const SCA_SEVERITIES = ["critical", "high", "medium", "low"] as const;
  const SCA_TYPES = ["cve", "eol", "deprecated"] as const;

  const severitySet = new Set(filters.severities ?? []) as ReadonlySet<typeof SCA_SEVERITIES[number]>;
  const typeSet     = new Set(filters.finding_types ?? []) as ReadonlySet<typeof SCA_TYPES[number]>;

  function toggleSet<T extends string>(
    current: ReadonlySet<T>,
    key: keyof ScaIssueFilters,
    value: T,
  ) {
    const next = new Set(current);
    next.has(value) ? next.delete(value) : next.add(value);
    setFilters((f) => ({ ...f, page: 1, [key]: next.size > 0 ? [...next] : undefined }));
  }

  const TYPE_LABELS: Record<string, string> = { cve: "cve", eol: "eol", deprecated: "deprecated" };

  const hasScaFilter = !!(
    filters.severities?.length || filters.finding_types?.length ||
    filters.reachable || filters.has_fix || filters.hide_dev || filters.include_resolved
  );

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0">
        <FilterGroup
          items={SCA_SEVERITIES}
          active={severitySet}
          onToggle={(s) => toggleSet(severitySet, "severities", s)}
          colorFn={(s) => SEVERITY_COLORS[s] ?? ""}
        />
        <Pipe />
        <FilterGroup
          items={SCA_TYPES}
          active={typeSet}
          onToggle={(s) => toggleSet(typeSet, "finding_types", s)}
          label={(t) => TYPE_LABELS[t] ?? t}
        />
        <Pipe />
        <ToggleGroup
          items={[
            { key: "reachable", label: "reachable", active: !!filters.reachable, onToggle: () => setFilters((f) => ({ ...f, page: 1, reachable: !f.reachable })) },
            { key: "has_fix",   label: "has fix",   active: !!filters.has_fix,   onToggle: () => setFilters((f) => ({ ...f, page: 1, has_fix: !f.has_fix })) },
            { key: "hide_dev",  label: "hide dev",  active: !!filters.hide_dev,  onToggle: () => setFilters((f) => ({ ...f, page: 1, hide_dev: !f.hide_dev })) },
          ]}
        />
        <Pipe />
        <ToggleGroup
          items={[{
            key: "include_resolved",
            label: "include resolved",
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
          <Card>
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
                  <ScaIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} jiraTicket={issue.jira_ticket_id ? ticketById.get(issue.jira_ticket_id) : null} />
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
          <Card>
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
          </Card>
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
        <div className="space-y-1">
          <Link to="/scopes" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" /> All scopes
          </Link>
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
        {(scope.critical_count > 0 || scope.high_count > 0 || scope.medium_count > 0 || scope.low_count > 0) && (
          <Card className="flex-none">
            <CardContent className="px-4 py-3 flex items-center gap-1.5 flex-wrap">
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
              {scope.medium_count > 0 && (
                <Badge variant="outline" className={SEVERITY_COLORS.medium}>
                  {scope.medium_count} Medium
                </Badge>
              )}
              {scope.low_count > 0 && (
                <Badge variant="outline" className={SEVERITY_COLORS.low}>
                  {scope.low_count} Low
                </Badge>
              )}
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

        {/* forceMount keeps all panels in the DOM so queries fire at page load,
            not on first click. data-[state=inactive]:hidden hides inactive panels
            without unmounting them — eliminates the loading-flash layout shift. */}
        <TabsContent forceMount value="sca" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <ScaIssuesTab scopeId={id} />}
        </TabsContent>
        <TabsContent forceMount value="sast" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <SastIssuesTab scopeId={id} />}
        </TabsContent>
        <TabsContent forceMount value="components" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <ComponentsTab scopeId={id} />}
        </TabsContent>
      </Tabs>

      {/* Recent scans */}
      {id && <RecentScansSection scopeId={id} />}
    </div>
  );
}
