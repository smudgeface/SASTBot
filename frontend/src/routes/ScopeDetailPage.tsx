import { useEffect, useRef, useState } from "react";
import { Link, useMatch, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Download,
  ExternalLink,
  FileText,
  Link2,
  Loader2,
  Package,
  Pencil,
  RefreshCw,
  ScanSearch,
  ShieldAlert,
  Trash2,
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
  useDeleteScopeComponent,
  usePatchScopeComponent,
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
import { useTriggerScan, useCancelScan } from "@/api/queries/scans";
import { useSettings } from "@/api/queries/settings";
import { useMe } from "@/api/queries/auth";
import type { SastIssue, ScaIssue, ScanRunSummary } from "@/api/types";
import { SCAN_PHASE_LABELS, SCAN_PHASE_UNITS, SCAN_PHASE_CAPS } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatDate, formatRelative } from "@/lib/format";
import { prettyEcosystem, prettyLicense } from "@/lib/componentLabels";
import { FilterGroup, Pipe, ToggleGroup } from "@/components/filters";
import { ContextSnippet } from "@/components/ContextSnippet";
import { ReachabilityVerdict } from "@/components/ReachabilityVerdict";
import { SeverityBadge, SEVERITY_COLORS } from "@/components/SeverityBadge";
import { VulnLink } from "@/components/VulnLink";
import { FileLink, basename } from "@/components/FileLink";
import { SeveritySummary } from "@/components/SeveritySummary";
import { HighSeverityCallout } from "@/components/HighSeverityCallout";

function ScanProgressBanner({ scan }: { scan: ScanRunSummary }) {
  const phase = scan.current_phase;
  const phaseLabel = phase
    ? (scan.phase_progress?.label ?? SCAN_PHASE_LABELS[phase])
    : "Starting…";
  const progress = scan.phase_progress;
  const unit = phase ? SCAN_PHASE_UNITS[phase] : undefined;
  const isCap = phase ? SCAN_PHASE_CAPS.has(phase) : false;
  const pct = progress && progress.total > 0 && !isCap
    ? Math.min(100, (progress.done / progress.total) * 100)
    : null;
  return (
    <div className="rounded-md border border-amber-200 dark:border-amber-900 bg-amber-50/50 dark:bg-amber-950/20 px-4 py-3 space-y-2">
      <div className="flex items-center justify-between text-sm">
        <span className="font-medium text-amber-700 dark:text-amber-300">
          {phaseLabel}
        </span>
        {progress && progress.total > 0 && (
          <span className="text-xs text-muted-foreground">
            {progress.done} of {progress.total}{unit ? ` ${unit}` : ""}
            {isCap ? " (max)" : ` · ${Math.round(pct ?? 0)}%`}
          </span>
        )}
      </div>
      {pct !== null && (
        <div className="h-1.5 rounded bg-muted overflow-hidden">
          <div
            className="h-full bg-amber-500 transition-all"
            style={{ width: `${pct}%` }}
          />
        </div>
      )}
    </div>
  );
}

// Jira statusCategory palette — used by the expanded JiraCard to show the
// ticket's own workflow state (new / indeterminate / done), distinct from
// SASTBot's own triage status.
const SC_COLORS: Record<string, string> = {
  new:          "text-purple-600 border-purple-400 bg-purple-50 dark:bg-purple-950/30",
  indeterminate:"text-blue-600 border-blue-400 bg-blue-50 dark:bg-blue-950",
  done:         "text-green-600 border-green-400 bg-green-50 dark:bg-green-950",
};
const SC_LABELS: Record<string, string> = {
  new:          "To do",
  indeterminate:"In Progress",
  done:         "Done",
};

// purple = to do (confirmed), blue = planned/in-progress, green = fixed/done, grey = dismissed
const TRIAGE_COLORS: Record<string, string> = {
  pending:        "text-amber-600 border-amber-400",
  confirmed:      "text-purple-600 border-purple-400 bg-purple-50 dark:bg-purple-950/30",
  planned:        "text-blue-600 border-blue-400",
  fixed:          "text-green-600 border-green-400",
  false_positive: "text-slate-500 border-slate-400",
  suppressed:     "text-slate-500 border-slate-400",
  error:          "text-destructive border-destructive",
};

const TRIAGE_LABELS: Record<string, string> = {
  pending:        "Pending",
  confirmed:      "To do",
  planned:        "Planned",
  fixed:          "Fixed",
  false_positive: "Invalid",
  suppressed:     "Won't fix",
  error:          "Error",
};

// SCA now shares TRIAGE_COLORS/TRIAGE_LABELS — same state vocabulary as SAST.
const SCA_STATUS_COLORS = TRIAGE_COLORS;
const SCA_STATUS_LABELS = TRIAGE_LABELS;

/** Unified status badge for SAST + SCA rows. Always shows the issue's actual
 *  status — we never override based on Jira linkage. The link/unlink flow is
 *  what transitions an issue into/out of "planned"; beyond that the Jira
 *  ticket is metadata, not status. */
function StatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={`text-[10px] ${TRIAGE_COLORS[status] ?? ""}`}>
      {TRIAGE_LABELS[status] ?? status.replace(/_/g, " ")}
    </Badge>
  );
}

// File-path / vuln-id link helpers live in @/components/FileLink and
// @/components/VulnLink — shared with the scan detail page.

/**
 * Derive a short one-line summary from a verbose rule message. Returns the
 * first sentence, capped at 100 chars. Used when no LLM summary exists yet.
 */
function shortRuleSummary(msg: string | null | undefined): string | null {
  if (!msg) return null;
  const trimmed = msg.trim();
  // First sentence: up to first ". " followed by uppercase/backtick, or period at end.
  const match = trimmed.match(/^[^.!?]*[.!?](?=\s|$)/);
  const first = match ? match[0] : trimmed;
  return first.length > 100 ? first.slice(0, 99).trimEnd() + "…" : first;
}

// Code snippet renderer (`ContextSnippet`) and reachability verdict are
// shared with the scan detail page — see @/components/ContextSnippet and
// @/components/ReachabilityVerdict.

// (ContextSnippet moved to @/components/ContextSnippet)

// ---------------------------------------------------------------------------
// (ReachabilityVerdict moved to @/components/ReachabilityVerdict)

// ---------------------------------------------------------------------------
// Jira ticket components
// ---------------------------------------------------------------------------

/**
 * Compact badge for the Status column when an issue has a linked Jira ticket.
 * Shows "Planned · {sub-state}" tinted by statusCategory.
 * When Jira is "done" but the issue is still planned, shows an amber ⚠ attention indicator.
 */
/**
 * Full Jira card shown in the expanded row.
 * Displays all metadata plus prominent Refresh + Unlink buttons.
 */
function JiraCard({
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
  const sc = ticket.status_category ?? "new";
  const scCls = SC_COLORS[sc] ?? SC_COLORS.new;

  return (
    <div className="rounded-md border bg-muted/30 p-3 space-y-2">
      {/* Header row: key + status category badge */}
      <div className="flex items-start justify-between gap-2">
        <div className="space-y-0.5 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            {ticket.url ? (
              <a href={ticket.url} target="_blank" rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="font-mono font-semibold text-sm text-blue-600 dark:text-blue-400 hover:underline flex items-center gap-1">
                {ticket.issue_key} <ExternalLink className="h-3 w-3 opacity-60" />
              </a>
            ) : (
              <span className="font-mono font-semibold text-sm">{ticket.issue_key}</span>
            )}
            <Badge variant="outline" className={`text-[10px] ${scCls}`}>
              {SC_LABELS[sc] ?? sc}
            </Badge>
            {ticket.resolution && (
              <span className="text-xs text-muted-foreground">· {ticket.resolution}</span>
            )}
          </div>
          {ticket.summary && (
            <p className="text-sm text-muted-foreground truncate max-w-md">{ticket.summary}</p>
          )}
        </div>
        {/* Actions */}
        <div className="flex gap-1.5 shrink-0">
          <button onClick={(e) => { e.stopPropagation(); onRefresh(); }} disabled={isPending}
            className="flex items-center gap-1 rounded border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50">
            <RefreshCw className="h-3 w-3" /> Refresh
          </button>
          <button onClick={(e) => { e.stopPropagation(); onUnlink(); }} disabled={isPending}
            className="flex items-center gap-1 rounded border px-2 py-1 text-xs text-destructive border-destructive/40 hover:bg-destructive/10 disabled:opacity-50">
            <Unlink className="h-3 w-3" /> Unlink
          </button>
        </div>
      </div>
      {/* Meta row */}
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        {ticket.status && (
          <span><span className="font-medium">Status:</span> {ticket.status}</span>
        )}
        {ticket.assignee_name && (
          <span><span className="font-medium">Assignee:</span> {ticket.assignee_name}</span>
        )}
        {ticket.fix_versions.length > 0 && (
          <span><span className="font-medium">Fix version:</span> {ticket.fix_versions.join(", ")}</span>
        )}
        {ticket.last_synced_at && (
          <span title={formatDate(ticket.last_synced_at)}>Synced {formatRelative(ticket.last_synced_at)}</span>
        )}
      </div>
      {ticket.sync_error && (
        <p className="text-xs text-amber-600 flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" /> {ticket.sync_error}
        </p>
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
        className="text-xs text-muted-foreground hover:text-foreground underline underline-offset-2">
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
        className="flex items-center gap-0.5 rounded border px-2 py-1 text-xs hover:bg-muted disabled:opacity-50">
        {isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Link"}
      </button>
      <button onClick={() => { setOpen(false); setKey(""); }}
        className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
      {error && <span className="text-xs text-destructive">{error}</span>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Filter bar primitives
// ---------------------------------------------------------------------------

/** Thin vertical line used to separate filter groups. */
// FilterGroup / Pipe / ToggleGroup live in @/components/filters and are
// shared with the scan detail page so both surfaces look identical.

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

function SastIssueRow({
  issue, isAdmin, jiraTicket, scopeId, autoExpand, sourceUrlTemplate, onUserInteraction,
}: {
  issue: SastIssue; isAdmin: boolean; jiraTicket?: JiraTicket | null;
  scopeId: string; autoExpand?: boolean; sourceUrlTemplate: string | null;
  onUserInteraction?: () => void;
}) {
  const [expanded, setExpanded] = useState(autoExpand ?? false);
  const [linkError, setLinkError] = useState<string>();
  const rowRef = useRef<HTMLTableRowElement>(null);

  // Sync expand state + scroll into view when the URL targets this row.
  // Instant scroll (no smooth easing) — tab switch is already a hard
  // transition; animation here adds latency without informing the user.
  useEffect(() => {
    if (autoExpand) {
      setExpanded(true);
      rowRef.current?.scrollIntoView({ block: "center" });
    }
  }, [autoExpand]);

  const copyLink = (e: React.MouseEvent) => {
    e.stopPropagation();
    // M6q: copy the path-based deep link, not the legacy ?issue= search param.
    navigator.clipboard.writeText(`${window.location.origin}/scopes/${scopeId}/sast/${issue.id}`);
  };
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

  const act = (status: "confirmed" | "false_positive" | "suppressed" | "pending" | "fixed" | "planned") => {
    triage.mutate({ issueId: issue.id, status });
  };

  // LLM-mode SAST rule_ids are `llm:CWE-XXX` placeholders — the CWE field
  // already conveys the same info, and the rule_message is essentially the
  // same as the LLM summary. Suppress redundant rendering when this is the
  // case so the panel reads like one coherent narrative instead of three
  // copies of the same sentence.
  const isLlmRule = issue.latest_rule_id.startsWith("llm:");
  const ruleMessageDuplicatesSummary =
    issue.latest_rule_message != null &&
    issue.latest_llm_summary != null &&
    issue.latest_rule_message.trim() === issue.latest_llm_summary.trim();

  return (
    <>
      <TableRow
        ref={rowRef}
        className={`group cursor-pointer hover:bg-muted/40${autoExpand ? " bg-primary/5 ring-1 ring-inset ring-primary/40" : ""}`}
        onClick={() => { setExpanded((v) => !v); onUserInteraction?.(); }}
      >
        <TableCell className="w-6 text-muted-foreground">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </TableCell>
        <TableCell>
          <SeverityBadge severity={issue.latest_severity} />
        </TableCell>
        <TableCell>
          <div className="flex items-center gap-1 group/summary">
            <span className="text-sm truncate">
              {issue.latest_llm_summary
                ?? shortRuleSummary(issue.latest_rule_message)
                ?? issue.latest_rule_id.split(".").pop()?.replace(/-/g, " ")}
            </span>
            <button
              onClick={copyLink}
              className="shrink-0 opacity-0 group-hover/summary:opacity-60 group-hover:opacity-60 hover:!opacity-100 transition-opacity text-muted-foreground"
              title="Copy link to this issue"
            >
              <Link2 className="h-3 w-3" />
            </button>
          </div>
        </TableCell>
        <TableCell className="overflow-hidden">
          <div
            className="truncate text-xs text-muted-foreground font-mono"
            title={`${issue.latest_file_path}:${issue.latest_start_line}`}
          >
            {basename(issue.latest_file_path)}:{issue.latest_start_line}
          </div>
          {/* Opengrep-era rules surface a meaningful rule slug here. LLM-mode
              rule_ids are bare `llm:CWE-XXX` placeholders that just duplicate
              the CWE info shown elsewhere in the panel — hide them. */}
          {!isLlmRule && (
            <div
              className="truncate text-[10px] text-muted-foreground font-mono mt-0.5"
              title={issue.latest_rule_id}
            >
              {issue.latest_rule_id.split(".").pop()}
            </div>
          )}
          {issue.latest_cwe_ids.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-0.5">
              <Badge
                variant="outline"
                className="text-[9px] px-1 py-0 text-purple-600 border-purple-400 font-mono"
                title={issue.latest_cwe_ids.join(", ")}
              >
                {issue.latest_cwe_ids[0]}
                {issue.latest_cwe_ids.length > 1 && ` +${issue.latest_cwe_ids.length - 1}`}
              </Badge>
            </div>
          )}
        </TableCell>
        <TableCell>
          <div className="flex flex-col gap-1 items-start">
            <div className="flex items-center gap-1">
              <StatusBadge status={issue.triage_status} />
              {issue.triage_status === "planned" && jiraTicket?.status_category === "done" && (
                <span title="Jira ticket is done — mark this issue as fixed">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                </span>
              )}
            </div>
          </div>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          <span title={formatDate(issue.last_seen_at)}>{formatRelative(issue.last_seen_at)}</span>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 p-4">
            {issue.latest_llm_summary && (
              <p className="mb-3 text-sm">{issue.latest_llm_summary}</p>
            )}
            {issue.latest_rule_message && !ruleMessageDuplicatesSummary && !isLlmRule && (
              <p className="mb-3 text-xs text-muted-foreground">
                <span className="font-medium">Rule description: </span>
                {issue.latest_rule_message}
              </p>
            )}
            <p className="mb-3 text-xs font-mono text-muted-foreground break-all">
              <FileLink
                template={sourceUrlTemplate}
                file={issue.latest_file_path}
                line={issue.latest_start_line}
              >
                {issue.latest_file_path}:{issue.latest_start_line}
              </FileLink>
            </p>
            {issue.latest_snippet && !issue.latest_snippet.startsWith("__absence__:") && (
              <ContextSnippet
                snippet={issue.latest_snippet}
                matchLine={issue.latest_start_line}
                matchEndLine={issue.latest_end_line}
                className="mb-3"
              />
            )}
            {issue.latest_snippet?.startsWith("__absence__:") && (
              <p className="mb-3 text-xs italic text-muted-foreground">
                Observation about absent security controls — no specific code site.
              </p>
            )}
            {issue.triage_reasoning && (
              <p className="mb-3 text-sm">
                <span className="font-medium">LLM reasoning: </span>
                {issue.triage_reasoning}
              </p>
            )}
            {/* Rule ID is informative for Opengrep-era findings (e.g.
                `eslint.detect-eval-with-expression`), but for LLM-mode the
                rule_id is just `llm:CWE-XXX` which is redundant with the
                CWE field. Hide the rule when it's an LLM placeholder. */}
            <div className="mb-3 flex flex-wrap gap-3 text-xs text-muted-foreground">
              {!isLlmRule && (
                <span><span className="font-medium">Rule: </span><span className="font-mono">{issue.latest_rule_id}</span></span>
              )}
              {issue.latest_cwe_ids?.length > 0 && (
                <span><span className="font-medium">CWE: </span>{issue.latest_cwe_ids.join(", ")}</span>
              )}
              {issue.triage_confidence != null && (
                <span>
                  <span className="font-medium">Confidence: </span>
                  {Math.round(issue.triage_confidence * 100)}%
                </span>
              )}
            </div>
            {/* Jira */}
            <div className="mb-3">
              {jiraTicket ? (
                <JiraCard
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
                {(issue.triage_status === "pending" || issue.triage_status === "error") ? (
                  // Open/pending → show decision buttons
                  <>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("confirmed")}>
                      Confirm
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                  </>
                ) : issue.triage_status === "confirmed" ? (
                  // Confirmed (To do) → forward to Planned, or dismiss / reopen.
                  // No "Mark fixed" here — fixes must transit through Planned.
                  <>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("planned")}>
                      Planned
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                    <Button size="sm" variant="ghost" disabled={triage.isPending} onClick={() => act("pending")}>
                      Reopen
                    </Button>
                  </>
                ) : issue.triage_status === "planned" ? (
                  // Planned (Jira ticket linked) → can mark fixed, dismiss, or reopen.
                  // Unlinking the ticket reverts to Confirmed (handled server-side).
                  <>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("fixed")}>
                      Mark fixed
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={triage.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                    <Button size="sm" variant="ghost" disabled={triage.isPending} onClick={() => act("pending")}>
                      Reopen
                    </Button>
                  </>
                ) : issue.triage_status === "fixed" ? (
                  // Fixed → can reopen if the fix was incorrect
                  <Button size="sm" variant="ghost" disabled={triage.isPending} onClick={() => act("pending")}>
                    Reopen
                  </Button>
                ) : (
                  // wont_fix / invalid → just Reopen
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

function SastIssuesTab({ scopeId, highlightIssueId, sourceUrlTemplate, onDisplayedTotalChange, onUserInteraction }: { scopeId: string; highlightIssueId?: string; sourceUrlTemplate: string | null; onDisplayedTotalChange?: (total: number) => void; onUserInteraction?: () => void }) {
  const { data: user } = useMe();
  const isAdmin = user?.role === "admin";
  const [filters, setFiltersRaw] = useState<SastIssueFilters>({ page: 1, page_size: 50 });
  // Wrap setFilters so any filter change also clears the URL row target —
  // a stale deep link shouldn't persist once the user moves on.
  const setFilters = (next: SastIssueFilters | ((f: SastIssueFilters) => SastIssueFilters)) => {
    setFiltersRaw(next);
    onUserInteraction?.();
  };

  const { data, isLoading } = useScopeSastIssues(scopeId, filters);
  const { data: jiraTickets } = useScopeJiraTickets(scopeId);
  const ticketById = new Map((jiraTickets ?? []).map((t) => [t.id, t]));

  // Publish the filtered total up to the page-level tab pill.
  useEffect(() => {
    if (data?.total != null) onDisplayedTotalChange?.(data.total);
  }, [data?.total, onDisplayedTotalChange]);

  const SAST_SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
  const SAST_STATUSES = ["pending", "confirmed", "planned", "fixed", "false_positive", "suppressed"] as const;

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

  // Count issues that need attention: planned + Jira ticket statusCategory = "done"
  const attentionCount = (data?.items ?? []).filter(
    (i) => i.triage_status === "planned" && ticketById.get(i.jira_ticket_id ?? "")?.status_category === "done",
  ).length;

  const hasFilter = !!(filters.severities?.length || filters.triage_statuses?.length || filters.include_resolved);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0">
        <FilterGroup
          items={SAST_SEVERITIES}
          active={severitySet}
          onToggle={(s) => toggleSet(severitySet, "severities", s)}
          label={(s) => s.charAt(0).toUpperCase() + s.slice(1)}
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
        {attentionCount > 0 && (
          <>
            <Pipe />
            <button
              className="flex items-center gap-1 text-xs text-amber-600 font-medium"
              title="Planned issues whose Jira ticket is marked Done — awaiting scan confirmation"
              onClick={() => setFilters({ page: 1, page_size: 50, triage_statuses: ["planned"] })}
            >
              <AlertTriangle className="h-3 w-3" /> {attentionCount} need{attentionCount === 1 ? "s" : ""} attention
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
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead>Summary</TableHead>
                  <TableHead className="w-64">Location</TableHead>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead className="w-24">Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((issue) => (
                  <SastIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} jiraTicket={issue.jira_ticket_id ? ticketById.get(issue.jira_ticket_id) : null} scopeId={scopeId} autoExpand={issue.id === highlightIssueId} sourceUrlTemplate={sourceUrlTemplate} onUserInteraction={onUserInteraction} />
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

function ScaIssueRow({
  issue, isAdmin, jiraTicket, scopeId, autoExpand, sourceUrlTemplate, onUserInteraction,
}: {
  issue: ScaIssue; isAdmin: boolean; jiraTicket?: JiraTicket | null;
  scopeId: string; autoExpand?: boolean; sourceUrlTemplate: string | null;
  onUserInteraction?: () => void;
}) {
  const [expanded, setExpanded] = useState(autoExpand ?? false);
  const [linkError, setLinkError] = useState<string>();
  const rowRef = useRef<HTMLTableRowElement>(null);
  const dismiss = useDismissScaIssue();
  const linkJira = useLinkScaIssueToJira();
  const unlinkJira = useUnlinkScaIssueFromJira();
  const refreshJira = useRefreshJiraTicket();

  // When the URL changes to target this row (e.g. from a clicked badge on the
  // Components tab), sync the local expand state and scroll into view. Use
  // an instant scroll — the tab switch is already a hard transition, the
  // smooth animation here just delays the user without informing them.
  useEffect(() => {
    if (autoExpand) {
      setExpanded(true);
      rowRef.current?.scrollIntoView({ block: "center" });
    }
  }, [autoExpand]);

  const copyLink = (e: React.MouseEvent) => {
    e.stopPropagation();
    // M6q: copy the path-based deep link, not the legacy ?issue= search param.
    navigator.clipboard.writeText(`${window.location.origin}/scopes/${scopeId}/sca/${issue.id}`);
  };

  const handleLink = (key: string) => {
    setLinkError(undefined);
    linkJira.mutate({ issueId: issue.id, issueKey: key }, {
      onError: (err) => setLinkError(err instanceof Error ? err.message : "Link failed"),
    });
  };

  const act = (status: "pending" | "confirmed" | "suppressed" | "false_positive" | "fixed" | "planned") => {
    dismiss.mutate({ issueId: issue.id, status });
  };

  // The honest dev/runtime classifier is `latest_is_dev_only` (cdxgen 12.2+
  // npm `dev: true` marker). The raw `latest_component_scope` (CycloneDX
  // required/optional) lumps devDeps with transitive runtime deps and is
  // shown only in the expanded metadata for completeness.
  const componentScopeLabel =
    issue.latest_component_scope === "required"
      ? "runtime"
      : (issue.latest_component_scope ?? "unknown");

  return (
    <>
      <TableRow
        ref={rowRef}
        className={`group cursor-pointer hover:bg-muted/40${autoExpand ? " bg-primary/5 ring-1 ring-inset ring-primary/40" : ""}`}
        onClick={() => { setExpanded((v) => !v); onUserInteraction?.(); }}
      >
        <TableCell className="w-6 text-muted-foreground">
          {expanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        </TableCell>
        <TableCell>
          <SeverityBadge severity={issue.latest_severity} />
        </TableCell>
        <TableCell>
          {/* Two-row layout: summary on top (with full-text tooltip since
              we truncate), CVE/OSV id on the second line muted so it
              reads as an identifier rather than competing for space.
              Distinguishes co-package issues (e.g. two ReDoS bugs in
              is-svg@2.1.0) without crowding the summary. */}
          <div className="flex items-start gap-1 group/summary min-w-0">
            <div className="min-w-0 flex-1">
              <div
                className="text-sm truncate"
                title={issue.latest_summary ?? issue.latest_llm_summary ?? undefined}
              >
                {issue.latest_llm_summary ?? issue.latest_summary}
              </div>
              <div className="font-mono text-xs text-muted-foreground truncate">
                {issue.latest_cve_id ?? issue.osv_id}
              </div>
            </div>
            <button
              onClick={copyLink}
              className="shrink-0 mt-0.5 opacity-0 group-hover/summary:opacity-60 group-hover:opacity-60 hover:!opacity-100 transition-opacity text-muted-foreground"
              title="Copy link to this issue"
            >
              <Link2 className="h-3 w-3" />
            </button>
          </div>
        </TableCell>
        <TableCell className="overflow-hidden">
          {issue.latest_manifest_file ? (
            <>
              <div
                className="truncate text-xs text-muted-foreground font-mono"
                title={`${issue.latest_manifest_file}${issue.latest_manifest_line ? `:${issue.latest_manifest_line}` : ""}`}
              >
                {basename(issue.latest_manifest_file)}
                {issue.latest_manifest_line ? `:${issue.latest_manifest_line}` : ""}
              </div>
              <div
                className="truncate text-[10px] text-muted-foreground font-mono mt-0.5"
                title={`${issue.package_name}${issue.latest_package_version ? `@${issue.latest_package_version}` : ""}`}
              >
                {issue.package_name}
                {issue.latest_package_version ? `@${issue.latest_package_version}` : ""}
              </div>
            </>
          ) : (
            <div
              className="truncate text-xs text-muted-foreground font-mono"
              title={`${issue.package_name}${issue.latest_package_version ? `@${issue.latest_package_version}` : ""}`}
            >
              {issue.package_name}
              {issue.latest_package_version ? `@${issue.latest_package_version}` : ""}
            </div>
          )}
          <div className="flex flex-wrap gap-1 mt-0.5">
            {issue.latest_finding_type === "cve" && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-red-600 border-red-400">
                CVE
              </Badge>
            )}
            {(issue.latest_finding_type === "eol" || issue.latest_finding_type === "deprecated") && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-gray-500 border-gray-400">
                EOL
              </Badge>
            )}
            {issue.latest_has_fix && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-green-600 border-green-400">
                Has fix
              </Badge>
            )}
            {issue.confirmed_reachable && (
              <Badge variant="outline" className="text-[9px] px-1 py-0 text-amber-600 border-amber-400 gap-0.5">
                <Zap className="h-2.5 w-2.5" /> Reachable
              </Badge>
            )}
            {issue.latest_is_dev_only && (
              <Badge
                variant="outline"
                className="text-[9px] px-1 py-0 text-blue-600 border-blue-400"
                title="cdxgen 12.2+ flagged this npm package as dev-only (lockfile dev: true)"
              >
                Dev
              </Badge>
            )}
            {issue.source === "nvd" && (
              <Badge
                variant="outline"
                className="text-[9px] px-1 py-0 text-slate-600 border-slate-400"
                title="Finding sourced from NVD (National Vulnerability Database) — not in OSV.dev"
              >
                NVD
              </Badge>
            )}
          </div>
        </TableCell>
        <TableCell>
          <div className="flex flex-col gap-1 items-start">
            <div className="flex items-center gap-1">
              <StatusBadge status={issue.dismissed_status} />
              {issue.dismissed_status === "planned" && jiraTicket?.status_category === "done" && (
                <span title="Jira ticket is done — mark this issue as fixed">
                  <AlertTriangle className="h-3.5 w-3.5 text-amber-500" />
                </span>
              )}
            </div>
          </div>
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          <span title={formatDate(issue.last_seen_at)}>{formatRelative(issue.last_seen_at)}</span>
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 p-4 space-y-3">
            {issue.latest_actively_exploited && (
              <HighSeverityCallout
                title="Actively exploited"
                detail="listed in CISA KEV. Prioritize remediation."
              />
            )}
            {/* Full OSV summary (collapsed row truncates with tooltip; the
                panel shows it in full — wraps naturally, no ellipsis). */}
            {issue.latest_summary && (
              <p className="text-sm">{issue.latest_summary}</p>
            )}
            {issue.latest_llm_summary && issue.latest_llm_summary !== issue.latest_summary && (
              <p className="text-sm text-muted-foreground">{issue.latest_llm_summary}</p>
            )}
            {issue.latest_manifest_file && (
              <div className="space-y-1">
                <p className="text-xs font-mono text-muted-foreground break-all">
                  <FileLink
                    template={sourceUrlTemplate}
                    file={issue.latest_manifest_file}
                    line={issue.latest_manifest_line}
                  >
                    {issue.latest_manifest_file}
                    {issue.latest_manifest_line ? `:${issue.latest_manifest_line}` : ""}
                  </FileLink>
                </p>
                {issue.latest_manifest_snippet && issue.latest_manifest_line && (
                  <ContextSnippet
                    snippet={issue.latest_manifest_snippet}
                    matchLine={issue.latest_manifest_line}
                  />
                )}
              </div>
            )}
            <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span>
                <span className="font-medium">OSV:&nbsp;</span>
                <VulnLink id={issue.osv_id} className="text-xs" />
              </span>
              {issue.latest_cve_id && (
                <span>
                  <span className="font-medium">CVE:&nbsp;</span>
                  <VulnLink id={issue.latest_cve_id} className="text-xs" />
                </span>
              )}
              {(issue.latest_cvss_score != null || issue.latest_cvss_vector) && (
                <span>
                  <span className="font-medium">CVSS:</span>{" "}
                  {issue.latest_cvss_score != null
                    ? issue.latest_cvss_score.toFixed(1)
                    : issue.latest_cvss_vector?.startsWith("CVSS:4.")
                      ? <span title="CVSS v4.0 score calculation not yet implemented">v4.0</span>
                      : "—"}
                  {issue.latest_cvss_vector && (
                    <span className="font-mono ml-1 text-[10px]">({issue.latest_cvss_vector})</span>
                  )}
                </span>
              )}
              {issue.latest_ecosystem && (
                <span><span className="font-medium">Ecosystem:</span> {issue.latest_ecosystem}</span>
              )}
              <span>
                <span className="font-medium">Scope:</span>{" "}
                {componentScopeLabel}
              </span>
            </div>
            {issue.reachable_assessed_at && (
              <ReachabilityVerdict
                fields={issue}
                sourceUrlTemplate={sourceUrlTemplate}
                FileLink={FileLink}
                admin={isAdmin ? {
                  isOpen:
                    issue.dismissed_status !== "false_positive" &&
                    issue.dismissed_status !== "suppressed" &&
                    issue.dismissed_status !== "fixed",
                  isPending: dismiss.isPending,
                  onDismiss: (s) => act(s),
                } : undefined}
              />
            )}
            {(() => {
              const otherAliases = issue.latest_aliases.filter(
                (a) => a !== issue.osv_id && a !== issue.latest_cve_id,
              );
              if (otherAliases.length === 0) return null;
              return (
                <div className="flex flex-wrap gap-1.5 items-center text-xs">
                  <span className="text-muted-foreground font-medium">Aliases:</span>
                  {otherAliases.map((alias) => (
                    <VulnLink key={alias} id={alias} className="text-xs" />
                  ))}
                </div>
              );
            })()}
            {/* Jira */}
            <div>
              {jiraTicket ? (
                <JiraCard
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
                {issue.dismissed_status === "pending" ? (
                  // Pending → confirm as real issue, or dismiss
                  <>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("confirmed")}>
                      Confirm
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                  </>
                ) : issue.dismissed_status === "confirmed" ? (
                  // Confirmed (To do) → forward to Planned, or dismiss / reopen.
                  // No "Mark fixed" here — fixes must transit through Planned.
                  <>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("planned")}>
                      Planned
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                    <Button size="sm" variant="ghost" disabled={dismiss.isPending} onClick={() => act("pending")}>
                      Reopen
                    </Button>
                  </>
                ) : issue.dismissed_status === "planned" ? (
                  // Planned (Jira ticket linked) → can mark fixed, dismiss, or reopen.
                  // Unlinking the ticket reverts to Confirmed (handled server-side).
                  <>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("fixed")}>
                      Mark fixed
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("suppressed")}>
                      Won't fix
                    </Button>
                    <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("false_positive")}>
                      Invalid
                    </Button>
                    <Button size="sm" variant="ghost" disabled={dismiss.isPending} onClick={() => act("pending")}>
                      Reopen
                    </Button>
                  </>
                ) : issue.dismissed_status === "fixed" ? (
                  // Fixed → can reopen if the fix was incorrect
                  <Button size="sm" variant="ghost" disabled={dismiss.isPending} onClick={() => act("pending")}>
                    Reopen
                  </Button>
                ) : (
                  // suppressed / false_positive → just Reopen
                  <Button size="sm" variant="outline" disabled={dismiss.isPending} onClick={() => act("pending")}>
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

function ScaIssuesTab({ scopeId, highlightIssueId, sourceUrlTemplate, onDisplayedTotalChange, onUserInteraction }: { scopeId: string; highlightIssueId?: string; sourceUrlTemplate: string | null; onDisplayedTotalChange?: (total: number) => void; onUserInteraction?: () => void }) {
  const { data: user } = useMe();
  const isAdmin = user?.role === "admin";
  const [filters, setFiltersRaw] = useState<ScaIssueFilters>({ page: 1, page_size: 50 });
  const [excludeDevOnly, setExcludeDevOnlyRaw] = useState(true);
  // Any filter / toggle change clears the URL row target so a stale deep link
  // doesn't persist once the user moves on.
  const setFilters = (next: ScaIssueFilters | ((f: ScaIssueFilters) => ScaIssueFilters)) => {
    setFiltersRaw(next);
    onUserInteraction?.();
  };
  const setExcludeDevOnly = (next: boolean | ((v: boolean) => boolean)) => {
    setExcludeDevOnlyRaw(next);
    onUserInteraction?.();
  };

  const { data, isLoading } = useScopeScaIssues(scopeId, { ...filters, exclude_dev_only: excludeDevOnly });
  const { data: jiraTickets } = useScopeJiraTickets(scopeId);
  const ticketById = new Map((jiraTickets ?? []).map((t) => [t.id, t]));

  useEffect(() => {
    if (data?.total != null) onDisplayedTotalChange?.(data.total);
  }, [data?.total, onDisplayedTotalChange]);

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

  const SCA_STATUSES = ["pending", "confirmed", "planned", "fixed", "suppressed", "false_positive"] as const;
  const TYPE_LABELS: Record<string, string> = { cve: "CVE", eol: "EOL", deprecated: "Deprecated" };

  const statusSet = new Set(filters.dismissed_statuses ?? []) as ReadonlySet<typeof SCA_STATUSES[number]>;

  const hasScaFilter = !!(
    filters.severities?.length || filters.finding_types?.length || filters.dismissed_statuses?.length ||
    filters.reachable || filters.has_fix || filters.include_resolved
  );

  const attentionCount = (data?.items ?? []).filter(
    (i) => i.dismissed_status === "planned" && ticketById.get(i.jira_ticket_id ?? "")?.status_category === "done",
  ).length;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-y-2 gap-x-0">
        <FilterGroup
          items={SCA_SEVERITIES}
          active={severitySet}
          onToggle={(s) => toggleSet(severitySet, "severities", s)}
          label={(s) => s.charAt(0).toUpperCase() + s.slice(1)}
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
        <FilterGroup
          items={SCA_STATUSES}
          active={statusSet}
          onToggle={(s) => toggleSet(statusSet, "dismissed_statuses", s)}
          label={(s) => SCA_STATUS_LABELS[s] ?? s.replace(/_/g, " ")}
          colorFn={(s) => SCA_STATUS_COLORS[s] ?? ""}
        />
        <Pipe />
        <ToggleGroup
          items={[
            { key: "reachable", label: "Reachable", active: !!filters.reachable, onToggle: () => setFilters((f) => ({ ...f, page: 1, reachable: !f.reachable })) },
            { key: "has_fix",   label: "Has fix",   active: !!filters.has_fix,   onToggle: () => setFilters((f) => ({ ...f, page: 1, has_fix: !f.has_fix })) },
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
        <Pipe />
        <button
          onClick={() => setExcludeDevOnly((v) => !v)}
          className={`rounded px-2 py-0.5 text-xs border transition-colors ${
            !excludeDevOnly
              ? "bg-accent text-accent-foreground border-border"
              : "border-transparent text-muted-foreground hover:border-border"
          }`}
        >
          Show dev-tool CVEs
        </button>
        {(data?.total_runtime != null || data?.total_dev != null) && (
          <span className="text-xs text-muted-foreground ml-1">
            {(data?.total_runtime ?? 0).toLocaleString()} runtime
            {(data?.total_dev ?? 0) > 0 && (
              <> / <span className="text-blue-600">{(data?.total_dev ?? 0).toLocaleString()} dev</span></>
            )}
          </span>
        )}
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
        {attentionCount > 0 && (
          <>
            <Pipe />
            <button
              className="flex items-center gap-1 text-xs text-amber-600 font-medium"
              title="Planned issues whose Jira ticket is marked Done — awaiting scan confirmation"
              onClick={() => setFilters({ page: 1, page_size: 50, dismissed_statuses: ["planned"] })}
            >
              <AlertTriangle className="h-3 w-3" /> {attentionCount} need{attentionCount === 1 ? "s" : ""} attention
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
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <TableHead className="w-24">Severity</TableHead>
                  <TableHead>Summary</TableHead>
                  <TableHead className="w-64">Location</TableHead>
                  <TableHead className="w-28">Status</TableHead>
                  <TableHead className="w-24">Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((issue) => (
                  <ScaIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} jiraTicket={issue.jira_ticket_id ? ticketById.get(issue.jira_ticket_id) : null} scopeId={scopeId} autoExpand={issue.id === highlightIssueId} sourceUrlTemplate={sourceUrlTemplate} onUserInteraction={onUserInteraction} />
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

/** Single expandable row in the scope-page ComponentsTab. */
function ScopeComponentRow({
  component, scopeId, sourceUrlTemplate, autoExpand, scaIssueMap, onUserInteraction,
}: {
  component: import("@/api/types").SbomComponent;
  scopeId: string;
  sourceUrlTemplate: string | null;
  autoExpand: boolean;
  scaIssueMap: Map<string, import("@/api/types").ScaIssue>;
  onUserInteraction?: () => void;
}) {
  const rowRef = useRef<HTMLTableRowElement>(null);
  // Local expand state — mirrors SCA/SAST rows so multiple rows can be open
  // simultaneously. URL only seeds the initial open + a subsequent open if
  // the URL changes to target this row.
  const [expanded, setExpanded] = useState(autoExpand);
  const deleteComponent = useDeleteScopeComponent();
  const patchComponent = usePatchScopeComponent();

  // Inline-edit state for name + component_root + evidence.
  // evidenceDraft is a newline-separated textarea string. Each line is a
  // path with an optional `:LINE` suffix (e.g. "package-lock.json:42").
  const [editingEvidence, setEditingEvidence] = useState(false);
  const [nameDraft, setNameDraft] = useState(component.name);
  const [rootDraft, setRootDraft] = useState(component.component_root ?? "");
  const [evidenceDraft, setEvidenceDraft] = useState(
    (component.evidence ?? [])
      .map((e) => (e.line != null ? `${e.path}:${e.line}` : e.path))
      .join("\n"),
  );

  useEffect(() => {
    if (autoExpand) {
      setExpanded(true);
      rowRef.current?.scrollIntoView({ block: "center" });
    }
  }, [autoExpand]);

  const toggle = () => {
    setExpanded((v) => !v);
    onUserInteraction?.();
  };
  const isExpanded = expanded;

  const handleDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    const label = `${component.name}${component.version ? `@${component.version}` : ""}`;
    if (!window.confirm(`Delete "${label}" from this scope?\n\nThe next scan may re-add it if it's found in the repo.`)) {
      return;
    }
    deleteComponent.mutate({ scopeId, componentId: component.id });
  };

  const eco = prettyEcosystem(component.ecosystem, component.discovery_method);
  const linkedScaIds = component.linked_issue_ids?.sca ?? [];

  // First license for inline display; rest go in expand panel.
  // prettyLicense() preserves SPDX casing but title-cases bare-word
  // labels like "CUSTOM" → "Custom".
  const firstLicense = component.licenses[0] ? prettyLicense(component.licenses[0]) : null;
  const extraLicenses = component.licenses.length > 1 ? component.licenses.length - 1 : 0;

  return (
    <>
      <TableRow
        ref={rowRef}
        className={`group cursor-pointer hover:bg-muted/40${autoExpand ? " bg-primary/5 ring-1 ring-inset ring-primary/40" : ""}`}
        onClick={toggle}
      >
        <TableCell className="w-6 text-muted-foreground">
          {isExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
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
            <span>{firstLicense}{extraLicenses > 0 && <span className="text-xs text-muted-foreground ml-1">+{extraLicenses} more</span>}</span>
          ) : "—"}
        </TableCell>
        <TableCell>
          {linkedScaIds.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {linkedScaIds.slice(0, 3).map((issueId) => {
                const issue = scaIssueMap.get(issueId);
                if (!issue) return null;
                const sev = issue.latest_severity;
                const sevColor = sev === "critical" ? "text-destructive border-destructive/60"
                  : sev === "high" ? "text-orange-600 border-orange-400"
                  : sev === "medium" ? "text-amber-600 border-amber-400"
                  : sev === "low" ? "text-blue-600 border-blue-400"
                  : "text-muted-foreground border-border";
                return (
                  <Link
                    key={issueId}
                    to={`/scopes/${scopeId}/sca/${issueId}`}
                    onClick={(e) => e.stopPropagation()}
                    title={issue.latest_cve_id ?? issue.osv_id}
                  >
                    <Badge variant="outline" className={`text-[9px] px-1 py-0 cursor-pointer hover:bg-muted ${sevColor}`}>
                      {issue.latest_cve_id ?? issue.osv_id}
                    </Badge>
                  </Link>
                );
              })}
              {linkedScaIds.length > 3 && (
                <span className="text-[10px] text-muted-foreground">+{linkedScaIds.length - 3}</span>
              )}
            </div>
          )}
        </TableCell>
        <TableCell className="text-right">
          <button
            type="button"
            onClick={handleDelete}
            disabled={deleteComponent.isPending}
            className="p-1 text-muted-foreground hover:text-destructive opacity-0 group-hover:opacity-100 transition disabled:opacity-50"
            title="Delete this component from the scope (manual cleanup)"
            aria-label="Delete component"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </TableCell>
      </TableRow>
      {isExpanded && (
        <TableRow className="bg-muted/20 hover:bg-muted/20">
          <TableCell colSpan={7} className="py-4 px-6">
            <div className="space-y-4 text-sm">
              {/* M7: Evidence files + component_root. Top of the panel; the
                   pencil opens an inline edit form for name + root + paths. */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide">Evidence</p>
                  {!editingEvidence && (
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setNameDraft(component.name);
                        setRootDraft(component.component_root ?? "");
                        setEvidenceDraft(
                          (component.evidence ?? [])
                            .map((e) => (e.line != null ? `${e.path}:${e.line}` : e.path))
                            .join("\n"),
                        );
                        setEditingEvidence(true);
                      }}
                      className="p-1 text-muted-foreground hover:text-foreground"
                      title="Edit name, component_root and evidence_paths"
                      aria-label="Edit evidence"
                    >
                      <Pencil className="h-3 w-3" />
                    </button>
                  )}
                </div>

                {editingEvidence ? (
                  <div className="space-y-2" onClick={(e) => e.stopPropagation()}>
                    <div>
                      <label className="block text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">
                        Name
                      </label>
                      <input
                        type="text"
                        value={nameDraft}
                        onChange={(e) => setNameDraft(e.target.value)}
                        placeholder="e.g. xenomai"
                        className="w-full font-mono text-xs px-2 py-1 border rounded bg-background"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">
                        Component root (shallowest unique directory)
                      </label>
                      <input
                        type="text"
                        value={rootDraft}
                        onChange={(e) => setRootDraft(e.target.value)}
                        placeholder="e.g. extern/Xenomai"
                        className="w-full font-mono text-xs px-2 py-1 border rounded bg-background"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] text-muted-foreground uppercase tracking-wide mb-0.5">
                        Evidence paths (one per line; append <span className="font-mono">:N</span> for a line number)
                      </label>
                      <textarea
                        rows={4}
                        value={evidenceDraft}
                        onChange={(e) => setEvidenceDraft(e.target.value)}
                        placeholder={"extern/Xenomai/include/xeno_config.h\npackage-lock.json:1234"}
                        className="w-full font-mono text-xs px-2 py-1 border rounded bg-background"
                      />
                    </div>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        disabled={patchComponent.isPending}
                        onClick={() => {
                          const trimmedName = nameDraft.trim();
                          if (trimmedName === "") {
                            window.alert("Name cannot be blank.");
                            return;
                          }
                          // Parse each non-empty line. A trailing `:N` (N a
                          // positive integer) is split off as the line number;
                          // anything else is treated as a bare path.
                          const evidence = evidenceDraft
                            .split("\n")
                            .map((s) => s.trim())
                            .filter((s) => s !== "")
                            .map((s) => {
                              const m = s.match(/^(.*):(\d+)$/);
                              if (m) return { path: m[1]!, line: parseInt(m[2]!, 10) };
                              return { path: s, line: null as number | null };
                            });
                          patchComponent.mutate(
                            {
                              scopeId,
                              componentId: component.id,
                              name: trimmedName !== component.name ? trimmedName : undefined,
                              component_root: rootDraft.trim() === "" ? null : rootDraft.trim(),
                              evidence,
                            },
                            {
                              onSuccess: () => setEditingEvidence(false),
                              onError: (err) => {
                                window.alert(`Save failed: ${(err as Error).message}`);
                              },
                            },
                          );
                        }}
                        className="px-2 py-1 text-xs bg-primary text-primary-foreground rounded hover:bg-primary/90 disabled:opacity-50"
                      >
                        {patchComponent.isPending ? "Saving…" : "Save"}
                      </button>
                      <button
                        type="button"
                        onClick={() => setEditingEvidence(false)}
                        className="px-2 py-1 text-xs border rounded hover:bg-muted"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <>
                    {component.component_root && (
                      <p className="font-mono text-xs mb-1">
                        <span className="text-muted-foreground mr-1">root:</span>
                        <FileLink template={sourceUrlTemplate} file={component.component_root}>
                          {component.component_root}
                        </FileLink>
                      </p>
                    )}
                    {component.evidence && component.evidence.length > 0 ? (
                      <div className="space-y-2">
                        {component.evidence.map((e, i) => (
                          <div key={`${e.path}-${i}`}>
                            <p className="font-mono text-xs">
                              <FileLink template={sourceUrlTemplate} file={e.path} line={e.line ?? undefined}>
                                {e.path}{e.line != null ? `:${e.line}` : ""}
                              </FileLink>
                            </p>
                            {e.snippet && (
                              <pre className="text-[10px] whitespace-pre-wrap bg-muted rounded px-2 py-1 mt-1 overflow-x-auto">
                                {e.snippet}
                              </pre>
                            )}
                          </div>
                        ))}
                      </div>
                    ) : !component.component_root ? (
                      <p className="text-xs text-muted-foreground italic">no evidence</p>
                    ) : null}
                  </>
                )}
              </div>

              {/* Usage — where the component is imported / included from.
                  Long list of clickable file:line links; no snippets. Empty
                  for components that the LLM added without any reference
                  sites (vendored libs that ship as headers/binaries). */}
              {(() => {
                const usage = component.usage ?? component.occurrences ?? [];
                if (usage.length === 0) return null;
                return (
                  <div>
                    <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide mb-1">
                      Usage ({usage.length} location{usage.length !== 1 ? "s" : ""})
                    </p>
                    <ol className="space-y-0.5 font-mono text-xs">
                      {usage.slice(0, 15).map((u, i) => (
                        <li key={`${u.path}-${i}`} className="text-muted-foreground">
                          <FileLink template={sourceUrlTemplate} file={u.path} line={u.line ?? undefined}>
                            {u.path}{u.line != null ? `:${u.line}` : ""}
                          </FileLink>
                        </li>
                      ))}
                      {usage.length > 15 && (
                        <li className="text-muted-foreground italic">…and {usage.length - 15} more</li>
                      )}
                    </ol>
                  </div>
                );
              })()}

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

              {/* LLM augmentation evidence */}
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
                    <pre className="text-[10px] whitespace-pre-wrap bg-muted rounded px-2 py-1 mt-1 overflow-hidden max-h-32">
                      {component.llm_evidence.excerpt}
                    </pre>
                  )}
                </div>
              )}

              {/* Linked SCA issues — fixed widths on severity + identifier so the
                  variable-length summary is what wraps, not the identifier. */}
              {linkedScaIds.length > 0 && (
                <div>
                  <p className="font-semibold text-xs text-muted-foreground uppercase tracking-wide mb-1">
                    Linked issues ({linkedScaIds.length})
                  </p>
                  <div className="space-y-1">
                    {linkedScaIds.map((issueId) => {
                      const issue = scaIssueMap.get(issueId);
                      if (!issue) return null;
                      const sev = issue.latest_severity;
                      const sevColor = sev === "critical" ? "text-destructive"
                        : sev === "high" ? "text-orange-600"
                        : sev === "medium" ? "text-amber-600"
                        : sev === "low" ? "text-blue-600"
                        : "text-muted-foreground";
                      return (
                        <div key={issueId} className="flex items-start gap-2">
                          <span className={`text-xs font-medium w-16 shrink-0 ${sevColor}`}>{sev.toUpperCase()}</span>
                          <Link
                            to={`/scopes/${scopeId}/sca/${issueId}`}
                            className="text-xs hover:underline font-mono w-56 shrink-0 break-all"
                          >
                            {issue.latest_cve_id ?? issue.osv_id}
                          </Link>
                          {issue.latest_summary && (
                            <span className="text-xs text-muted-foreground flex-1 min-w-0">{issue.latest_summary}</span>
                          )}
                        </div>
                      );
                    })}
                  </div>
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
  scopeId,
  sourceUrlTemplate,
  onDisplayedTotalChange,
  expandedId,
  onUserInteraction,
}: {
  scopeId: string;
  sourceUrlTemplate?: string | null;
  onDisplayedTotalChange?: (total: number) => void;
  expandedId?: string;
  onUserInteraction?: () => void;
}) {
  const [page, setPage] = useState(1);
  const [hasFindings, setHasFindings] = useState(false);
  const [excludeDevOnly, setExcludeDevOnly] = useState(true);
  const { data, isLoading } = useScopeComponents(scopeId, { page, page_size: 50, has_findings: hasFindings || undefined, exclude_dev_only: excludeDevOnly });

  // Fetch current SCA issues so we can show linked issue details in expand panels
  const { data: scaData } = useScopeScaIssues(scopeId, { page: 1, page_size: 500 });
  const scaIssueMap = new Map((scaData?.items ?? []).map((i) => [i.id, i]));

  const totalRuntime = data?.total_runtime ?? 0;
  const totalDev = data?.total_dev ?? 0;
  const totalAll = totalRuntime + totalDev;
  const visible = data?.total ?? 0;

  useEffect(() => {
    if (data?.total != null) onDisplayedTotalChange?.(data.total);
  }, [data?.total, onDisplayedTotalChange]);

  return (
    <div className="space-y-3">
      <ToggleGroup
        items={[
          {
            key: "has_findings",
            label: "Only with findings",
            active: hasFindings,
            onToggle: () => { setHasFindings((v) => !v); setPage(1); onUserInteraction?.(); },
          },
          {
            key: "show_dev",
            label: "Show dev-tool packages",
            active: !excludeDevOnly,
            onToggle: () => { setExcludeDevOnly((v) => !v); setPage(1); onUserInteraction?.(); },
          },
        ]}
      />
      {totalAll > 0 && (
        <p className="text-xs text-muted-foreground">
          {visible.toLocaleString()} of {totalAll.toLocaleString()} components shown
          {excludeDevOnly && totalDev > 0 && (
            <> · {totalDev.toLocaleString()} dev-tool {totalDev === 1 ? "package" : "packages"} hidden</>
          )}
        </p>
      )}
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : !data || data.total === 0 ? (
        <p className="text-sm text-muted-foreground py-6 text-center">
          {excludeDevOnly && totalDev > 0
            ? `No runtime components with findings. ${totalDev.toLocaleString()} dev-tool packages hidden.`
            : "No components in the most recent scan."}
        </p>
      ) : (
        <>
          <Card>
            <Table className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead className="w-6" />
                  <TableHead>Package</TableHead>
                  <TableHead className="w-28">Version</TableHead>
                  <TableHead className="w-28">Ecosystem</TableHead>
                  <TableHead className="w-40">License</TableHead>
                  <TableHead className="w-64">Issues</TableHead>
                  <TableHead className="w-12" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((c) => (
                  <ScopeComponentRow
                    key={c.id}
                    component={c}
                    scopeId={scopeId}
                    sourceUrlTemplate={sourceUrlTemplate ?? null}
                    autoExpand={expandedId === c.id}
                    scaIssueMap={scaIssueMap}
                    onUserInteraction={onUserInteraction}
                  />
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
  const cancelScan = useCancelScan();

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
              {scans.map((s) => {
                const isActive = s.status === "pending" || s.status === "running";
                return (
                <li key={s.id} className="flex items-center justify-between px-4 py-2.5 text-sm">
                  <div className="flex items-center gap-3">
                    <span
                      className={`inline-block h-2 w-2 rounded-full ${
                        s.status === "success"
                          ? "bg-green-500"
                          : s.status === "failed"
                          ? "bg-destructive"
                          : s.status === "cancelled"
                          ? "bg-muted-foreground/40"
                          : "bg-amber-400"
                      }`}
                    />
                    <span
                      className="text-muted-foreground text-xs"
                      title={s.finished_at ? formatDate(s.finished_at) : undefined}
                    >
                      {s.status === "running"
                        ? "running…"
                        : s.status === "pending"
                        ? "queued"
                        : s.status === "cancelled"
                        ? "cancelled"
                        : s.finished_at
                        ? formatRelative(s.finished_at)
                        : "—"}
                    </span>
                    {s.critical_count > 0 && (
                      <span className="text-[10px] text-destructive">{s.critical_count}C</span>
                    )}
                    {s.sast_finding_count > 0 && (
                      <span className="text-[10px] text-muted-foreground">{s.sast_finding_count} SAST</span>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    {isActive && (
                      <button
                        type="button"
                        className="text-xs text-destructive hover:underline disabled:opacity-50"
                        disabled={cancelScan.isPending}
                        onClick={(e) => { e.stopPropagation(); cancelScan.mutate(s.id); }}
                      >
                        Cancel
                      </button>
                    )}
                    <Link
                      to={`/scans/${s.id}`}
                      className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1"
                      onClick={(e) => e.stopPropagation()}
                    >
                      View <ExternalLink className="h-3 w-3" />
                    </Link>
                  </div>
                </li>
                );
              })}
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
  const [searchParams] = useSearchParams();
  // Legacy: support ?issue= search param for back-compat with existing links
  const highlightIssueIdLegacy = searchParams.get("issue") ?? undefined;
  const navigate = useNavigate();

  // M6q: URL-driven tab + row state via route matching
  const scaMatch = useMatch("/scopes/:id/sca");
  const scaRowMatch = useMatch("/scopes/:id/sca/:issueId");
  const sastMatch = useMatch("/scopes/:id/sast");
  const sastRowMatch = useMatch("/scopes/:id/sast/:issueId");
  const componentsMatch = useMatch("/scopes/:id/components");
  const componentsRowMatch = useMatch("/scopes/:id/components/:componentId");

  // Derive active tab from route match. Default to "sca".
  const activeTab = (
    scaMatch || scaRowMatch ? "sca"
    : sastMatch || sastRowMatch ? "sast"
    : componentsMatch || componentsRowMatch ? "components"
    : "sca"
  );

  // Derive expanded row ID from route match or legacy search param
  const expandedIssueId = scaRowMatch?.params.issueId ?? sastRowMatch?.params.issueId ?? highlightIssueIdLegacy;
  const expandedComponentId = componentsRowMatch?.params.componentId;

  const { data: scope, isLoading, isError } = useScopeDetail(id);
  const { data: appSettings } = useSettings();
  const { data: scans } = useScopeScans(id, 1);
  const triggerScan = useTriggerScan();
  const llmConfigured = !!(appSettings?.llm_base_url && appSettings?.llm_model && appSettings?.llm_credential_id);
  const activeScanStatus = scans?.[0]?.status;
  const isScanning = activeScanStatus === "pending" || activeScanStatus === "running" || triggerScan.isPending;

  // Tab pills reflect the *displayed* count after each tab's filters land.
  const [scaDisplayed, setScaDisplayed] = useState<number | null>(null);
  const [sastDisplayed, setSastDisplayed] = useState<number | null>(null);
  const [componentsDisplayed, setComponentsDisplayed] = useState<number | null>(null);

  if (isLoading) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (isError || !scope) return <p className="text-sm text-destructive">Scope not found.</p>;

  const handleTriggerScan = () => {
    triggerScan.mutate(scope.repo_id);
  };

  // Navigate to a tab URL when the Radix Tabs value changes
  const handleTabChange = (tab: string) => {
    if (!id) return;
    navigate(`/scopes/${id}/${tab}`, { replace: true });
  };

  // Subsequent interactions inside any tab — clicking a different row, hitting
  // a filter toggle, etc. — should clear the URL row param so a stale deep
  // link doesn't persist (and the highlight goes away as a consequence).
  // Tab switches already clear the row param via handleTabChange.
  const hasRouteRowTarget =
    !!scaRowMatch || !!sastRowMatch || !!componentsRowMatch;
  const clearRowTarget = () => {
    if (!id || !hasRouteRowTarget) return;
    navigate(`/scopes/${id}/${activeTab}`, { replace: true });
  };

  // SBOM download URL
  const sbomUrl = id && scope.last_scan_run_id ? `/api/scopes/${id}/sbom-json` : null;

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
              <span className="text-base font-normal text-muted-foreground font-mono"> · {scope.path}</span>
            )}
          </h1>
          <p className="text-sm text-muted-foreground">
            Branch: {scope.repo_branch}
            {scope.last_scan_completed_at && (
              <>
                {" · Last scan: "}
                <span title={formatDate(scope.last_scan_completed_at)}>
                  {formatRelative(scope.last_scan_completed_at)}
                </span>
              </>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* M6q: Scope SBOM — View opens the Monaco viewer at /scopes/:id/sbom;
              Download streams the file via the API endpoint. */}
          {sbomUrl && (
            <>
              <Button
                size="sm"
                variant="outline"
                asChild
                title="View the CycloneDX SBOM for the most recent scan of this scope"
              >
                <Link to={`/scopes/${id}/sbom`}>
                  <FileText className="h-3.5 w-3.5" />
                  View SBOM
                </Link>
              </Button>
              <Button
                size="sm"
                variant="outline"
                asChild
                title="Download the CycloneDX SBOM for the most recent scan of this scope"
              >
                <a href={sbomUrl} download>
                  <Download className="h-3.5 w-3.5" />
                  Download SBOM
                </a>
              </Button>
            </>
          )}
          <Button
            size="sm"
            onClick={handleTriggerScan}
            disabled={isScanning || !llmConfigured}
            title={!llmConfigured ? "LLM not configured — set up LLM settings before scanning" : undefined}
          >
            {isScanning ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Scanning…
              </>
            ) : (
              "Scan now"
            )}
          </Button>
        </div>
      </div>

      {/* Live progress banner — only while a scan is running */}
      {isScanning && scans?.[0] && (
        <ScanProgressBanner scan={scans[0]} />
      )}

      {/* Summary: stacked severity bar + totals */}
      <SeveritySummary
        critical={scope.critical_count}
        high={scope.high_count}
        medium={scope.medium_count}
        low={scope.low_count}
        sca={scope.active_sca_issue_count}
        sast={scope.active_sast_issue_count}
        pending={scope.pending_triage_count}
      />

      {/* Main tabs — M6q: value driven by URL route match */}
      <Tabs value={activeTab} onValueChange={handleTabChange}>
        <TabsList>
          <TabsTrigger value="sca" className="gap-1.5">
            <ShieldAlert className="h-3.5 w-3.5" />SCA Issues
            {scaDisplayed != null && scaDisplayed > 0 && (
              <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">
                {scaDisplayed}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="sast" className="gap-1.5">
            <ScanSearch className="h-3.5 w-3.5" />SAST Issues
            {sastDisplayed != null && sastDisplayed > 0 && (
              <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">
                {sastDisplayed}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="components" className="gap-1.5">
            <Package className="h-3.5 w-3.5" />Components
            {componentsDisplayed != null && componentsDisplayed > 0 && (
              <span className="ml-1.5 rounded-full bg-muted px-1.5 py-0.5 text-[10px]">
                {componentsDisplayed}
              </span>
            )}
          </TabsTrigger>
        </TabsList>

        {/* forceMount keeps all panels in the DOM so queries fire at page load,
            not on first click. data-[state=inactive]:hidden hides inactive panels
            without unmounting them — eliminates the loading-flash layout shift. */}
        <TabsContent forceMount value="sca" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <ScaIssuesTab scopeId={id} highlightIssueId={expandedIssueId} sourceUrlTemplate={scope?.source_url_template ?? null} onDisplayedTotalChange={setScaDisplayed} onUserInteraction={clearRowTarget} />}
        </TabsContent>
        <TabsContent forceMount value="sast" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <SastIssuesTab scopeId={id} highlightIssueId={expandedIssueId} sourceUrlTemplate={scope?.source_url_template ?? null} onDisplayedTotalChange={setSastDisplayed} onUserInteraction={clearRowTarget} />}
        </TabsContent>
        <TabsContent forceMount value="components" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <ComponentsTab scopeId={id} sourceUrlTemplate={scope?.source_url_template ?? null} onDisplayedTotalChange={setComponentsDisplayed} expandedId={expandedComponentId} onUserInteraction={clearRowTarget} />}
        </TabsContent>
      </Tabs>

      {/* Recent scans */}
      {id && <RecentScansSection scopeId={id} />}
    </div>
  );
}
