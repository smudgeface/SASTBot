import { useEffect, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import {
  AlertTriangle,
  ArrowLeft,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Clock,
  ExternalLink,
  Link2,
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
import { useTriggerScan, useCancelScan } from "@/api/queries/scans";
import { useSettings } from "@/api/queries/settings";
import { useMe } from "@/api/queries/auth";
import type { SastIssue, ScaIssue, ScanRunSummary } from "@/api/types";
import { SCAN_PHASE_LABELS } from "@/api/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";
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

// ---------------------------------------------------------------------------
// Severity summary — stacked bar + legend at top of scope page
// ---------------------------------------------------------------------------

const SEVERITY_BAR_COLOR: Record<"critical" | "high" | "medium" | "low", string> = {
  critical: "bg-red-500",
  high:     "bg-orange-500",
  medium:   "bg-yellow-500",
  low:      "bg-blue-500",
};

function ScanProgressBanner({ scan }: { scan: ScanRunSummary }) {
  const phase = scan.current_phase;
  const phaseLabel = phase
    ? (scan.phase_progress?.label ?? SCAN_PHASE_LABELS[phase])
    : "Starting…";
  const progress = scan.phase_progress;
  const pct = progress && progress.total > 0
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
            {progress.done} of {progress.total} · {Math.round(pct ?? 0)}%
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

function SeveritySummary({
  critical, high, medium, low, sca, sast, pending,
}: {
  critical: number; high: number; medium: number; low: number;
  sca: number; sast: number; pending: number;
}) {
  const total = critical + high + medium + low;
  const segments: { key: "critical" | "high" | "medium" | "low"; label: string; count: number }[] = [
    { key: "critical", label: "Critical", count: critical },
    { key: "high",     label: "High",     count: high },
    { key: "medium",   label: "Medium",   count: medium },
    { key: "low",      label: "Low",      count: low },
  ];

  return (
    <Card>
      <CardContent className="px-5 py-4 space-y-3">
        {total === 0 ? (
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <CheckCircle2 className="h-4 w-4 text-emerald-500" />
            No open issues in this scope.
          </div>
        ) : (
          <>
            <div className="flex h-2 w-full overflow-hidden rounded-full bg-muted">
              {segments.filter(s => s.count > 0).map((s) => (
                <div
                  key={s.key}
                  className={SEVERITY_BAR_COLOR[s.key]}
                  style={{ width: `${(s.count / total) * 100}%` }}
                  title={`${s.count} ${s.label}`}
                />
              ))}
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold leading-none">{total}</span>
              <span className="text-sm text-muted-foreground">Open Issues</span>
            </div>
            <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
              {segments.map((s) => (
                <span key={s.key} className="inline-flex items-center gap-1.5">
                  <span className={`inline-block h-2.5 w-2.5 rounded-sm ${SEVERITY_BAR_COLOR[s.key]} ${s.count === 0 ? "opacity-30" : ""}`} />
                  <span className={s.count === 0 ? "text-muted-foreground/60" : ""}>
                    {s.count} {s.label}
                  </span>
                </span>
              ))}
            </div>
          </>
        )}
        <div className="flex flex-wrap gap-x-4 gap-y-1 pt-2 text-xs text-muted-foreground border-t">
          <span><span className="font-medium text-foreground">{sca}</span> SCA</span>
          <span><span className="font-medium text-foreground">{sast}</span> SAST</span>
          {pending > 0 && (
            <span className="inline-flex items-center gap-1">
              <Clock className="h-3 w-3 text-amber-500" />
              <span className="font-medium text-foreground">{pending}</span> Pending triage
            </span>
          )}
        </div>
      </CardContent>
    </Card>
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

// ---------------------------------------------------------------------------
// Vuln link helpers
// ---------------------------------------------------------------------------

/** Keep the Location column compact — show only the file basename.
 *  The full path is always available in the title tooltip and in the
 *  expanded row detail. */
function truncateFilePath(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] ?? path;
}

/** Build a clickable source URL from a repo's template (with $FILE / $LINE
 *  placeholders) and the issue's path + line. Returns null if the template
 *  is missing or empty. */
function buildSourceUrl(template: string | null | undefined, file: string, line?: number | null): string | null {
  if (!template) return null;
  return template
    .replace(/\$FILE/g, encodeURI(file))
    .replace(/\$LINE/g, line != null ? String(line) : "");
}

/** Renders a file path; if a sourceUrlTemplate is provided, wraps it in an
 *  anchor that opens the path in the configured source viewer. */
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
      className={`hover:underline hover:text-foreground ${className ?? ""}`}
      onClick={(e) => e.stopPropagation()}
    >
      {children}
    </a>
  );
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

// ---------------------------------------------------------------------------
// Code snippet with highlighted match line
// ---------------------------------------------------------------------------

// What the backend SHOULD have stored per the SAST detection prompt
// (3 lines above match + the match span + 3 lines below). The LLM is
// inconsistent about following this rule — sometimes it emits 20+
// lines around the match. We treat 7 (3 + 1 + 3) as the canonical
// short-snippet length and fall back to a keyword-search heuristic
// when the snippet is longer.
const STORED_CONTEXT_LINES = 3;
// What we render once we know which line is the match. 1 above + match
// + 1 below keeps the panel scannable; operators can click the file
// link for full context.
const DISPLAYED_CONTEXT_LINES = 1;

/**
 * Best-effort: locate the snippet line that corresponds to the issue.
 * Used when the LLM emitted more context than the prompt asked for, so
 * the simple "match line is at index STORED_CONTEXT_LINES" assumption
 * doesn't hold. We search for distinctive identifiers and content
 * keywords from the issue's summary; first hit wins. Returns -1 if
 * nothing scores above the threshold.
 */
function findMatchIndexByKeywords(
  lines: string[],
  summary: string | null,
  ruleMessage: string | null,
): number {
  const summaryRaw = (summary ?? ruleMessage ?? "").trim();
  if (!summaryRaw) return -1;

  // First pass: distinctive UPPER_SNAKE_CASE identifiers in the summary.
  // For a finding like "GS_SUPER_USER_PASSWORD ..." this nails the line.
  const idents = summaryRaw.match(/[A-Z][A-Z0-9_]{3,}/g) ?? [];
  for (let i = 0; i < lines.length; i++) {
    for (const id of idents) {
      if (lines[i].includes(id)) return i;
    }
  }

  // Second pass: content keywords. Pick distinctive content words ≥5 chars,
  // skip common verbs/connectors. Score = number of keyword matches per line.
  const STOPWORDS = new Set([
    "allows", "enables", "exposes", "exploits", "grants", "leaves", "stores",
    "device", "system", "access", "remote", "attack", "attacker", "attackers",
    "unrestricted", "unauthenticated", "unauthorized",
    "potentially", "improperly", "without", "before", "after",
    "could", "would", "should", "their", "these", "those", "which",
    // Stems that fall out after singularizing
    "attacker", "exploit", "grant", "store",
  ]);
  // Naive stemming: drop trailing 's' for plurals so "passwords" matches
  // identifiers like GS_SUPER_USER_PASSWORD. Skips "ss"-ending words.
  const stem = (w: string): string =>
    w.length > 4 && w.endsWith("s") && !w.endsWith("ss") ? w.slice(0, -1) : w;

  const keywords = (summaryRaw.toLowerCase().match(/\b[a-z][a-z]{4,}\b/g) ?? [])
    .map(stem)
    .filter((w) => !STOPWORDS.has(w))
    .slice(0, 6);

  let bestIdx = -1;
  let bestScore = 0;
  for (let i = 0; i < lines.length; i++) {
    const lower = lines[i].toLowerCase();
    let score = 0;
    for (const kw of keywords) if (lower.includes(kw)) score++;
    if (score > bestScore) {
      bestScore = score;
      bestIdx = i;
    }
  }
  // Require at least one strong match to use this — otherwise fall back to
  // the offset-from-top assumption.
  return bestScore >= 1 ? bestIdx : -1;
}

/**
 * Renders a multi-line code snippet with the matching line highlighted.
 * `matchLine` is the 1-indexed line number in the original file.
 *
 * Two modes:
 * - Short snippet (≤ 2*STORED_CONTEXT_LINES + 2 lines): assume the LLM
 *   followed the spec — match line at index STORED_CONTEXT_LINES.
 * - Long snippet: keyword-search the summary against the snippet to
 *   find the actually-relevant line. Falls back to offset-from-top
 *   when no keyword matches.
 */
function ContextSnippet({
  snippet,
  matchLine,
  className,
  summary,
  ruleMessage,
}: {
  snippet: string;
  matchLine: number;
  className?: string;
  summary?: string | null;
  ruleMessage?: string | null;
}) {
  const allLines = snippet.split("\n");

  let fullHighlightIdx: number;
  if (allLines.length === 1) {
    fullHighlightIdx = 0;
  } else if (allLines.length > STORED_CONTEXT_LINES * 2 + 2) {
    // Long snippet — try keyword search first; fall back to offset-from-top.
    const keywordIdx = findMatchIndexByKeywords(allLines, summary ?? null, ruleMessage ?? null);
    fullHighlightIdx = keywordIdx >= 0
      ? keywordIdx
      : Math.min(STORED_CONTEXT_LINES, matchLine - 1);
  } else {
    fullHighlightIdx = Math.min(STORED_CONTEXT_LINES, matchLine - 1);
  }

  // Trim the rendered window to ±DISPLAYED_CONTEXT_LINES around the match.
  const startIdx = Math.max(0, fullHighlightIdx - DISPLAYED_CONTEXT_LINES);
  const endIdx = Math.min(allLines.length, fullHighlightIdx + DISPLAYED_CONTEXT_LINES + 1);
  const lines = allLines.slice(startIdx, endIdx);
  const highlightIdx = fullHighlightIdx - startIdx;
  // File line of lines[0]: match line minus the count of context lines
  // preceding the highlighted line in the trimmed window.
  const firstLineNumber = matchLine - highlightIdx;

  return (
    <div className={`overflow-x-auto rounded border bg-background text-xs font-mono ${className ?? ""}`}>
      <table className="w-full border-collapse">
        <tbody>
          {lines.map((line, i) => {
            const isMatch = i === highlightIdx;
            const lineNumber = firstLineNumber + i;
            return (
              <tr key={i} className={isMatch ? "bg-yellow-50 dark:bg-yellow-950/40" : ""}>
                <td className="select-none px-2 py-0.5 text-right text-muted-foreground/50 w-10 border-r border-border tabular-nums">
                  {lineNumber}
                </td>
                <td className="select-none px-1 py-0.5 text-center text-muted-foreground/60 w-4">
                  {isMatch ? "→" : " "}
                </td>
                <td className={`px-3 py-0.5 whitespace-pre ${isMatch ? "font-semibold" : ""}`}>
                  {line || " "}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reachability verdict — shown in the expanded SCA row when the LLM has
// assessed whether the vulnerability is reachable in this codebase.
// ---------------------------------------------------------------------------

const HIGH_CONFIDENCE_DISMISS_THRESHOLD = 0.85;

function ReachabilityVerdict({
  issue,
  isAdmin,
  onDismiss,
  isPending,
  sourceUrlTemplate,
}: {
  issue: ScaIssue;
  isAdmin: boolean;
  onDismiss: (status: "false_positive" | "suppressed") => void;
  isPending: boolean;
  sourceUrlTemplate: string | null;
}) {
  const reachable = issue.confirmed_reachable;
  const conf = issue.reachable_confidence;
  const sites = issue.reachable_call_sites ?? [];

  // Pre-existing data may have been assessed before we captured confidence —
  // render a degraded state without the confidence/CTA bits in that case.
  const hasStructuredVerdict = conf !== null;
  const highConfidenceNotReachable =
    hasStructuredVerdict && !reachable && conf! >= HIGH_CONFIDENCE_DISMISS_THRESHOLD;

  const tone = reachable
    ? "border-amber-400 bg-amber-50 dark:bg-amber-950/30"
    : "border-emerald-400 bg-emerald-50 dark:bg-emerald-950/30";

  const headlineColor = reachable ? "text-amber-700 dark:text-amber-400" : "text-emerald-700 dark:text-emerald-400";

  const isOpen = issue.dismissed_status !== "false_positive" && issue.dismissed_status !== "suppressed" && issue.dismissed_status !== "fixed";

  return (
    <div className={`rounded-md border ${tone} px-3 py-2 space-y-2`}>
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
        <span className={`text-sm font-semibold ${headlineColor}`}>
          {reachable ? "Reachable" : "Not reachable"}
        </span>
        {hasStructuredVerdict && (
          <span className="text-xs text-muted-foreground">
            · {Math.round(conf! * 100)}% confident
          </span>
        )}
        <span className="text-[10px] text-muted-foreground/70 ml-auto">
          {issue.reachable_model && `via ${issue.reachable_model}`}
        </span>
      </div>
      {issue.reachable_reasoning && (
        <p className="text-xs">{issue.reachable_reasoning}</p>
      )}
      {sites.length > 0 && (
        <div className="space-y-1">
          {sites.slice(0, 5).map((s, i) => (
            <div key={i} className="rounded border bg-background text-xs font-mono overflow-x-auto">
              <div className="flex items-center justify-between px-2 py-1 border-b text-[10px] text-muted-foreground">
                <FileLink template={sourceUrlTemplate} file={s.file} line={s.line} className="truncate">
                  {s.file}
                </FileLink>
                <FileLink template={sourceUrlTemplate} file={s.file} line={s.line} className="ml-2 shrink-0">
                  line {s.line}
                </FileLink>
              </div>
              <pre className="px-2 py-1 whitespace-pre">{s.snippet}</pre>
            </div>
          ))}
        </div>
      )}
      {isAdmin && highConfidenceNotReachable && isOpen && (
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-emerald-200 dark:border-emerald-900/40">
          <span className="text-xs text-muted-foreground">
            High-confidence verdict — apply directly:
          </span>
          <Button size="sm" variant="outline" disabled={isPending} onClick={() => onDismiss("false_positive")}>
            Mark Invalid
          </Button>
          <Button size="sm" variant="outline" disabled={isPending} onClick={() => onDismiss("suppressed")}>
            Mark Won't fix
          </Button>
        </div>
      )}
    </div>
  );
}

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
          <span>Synced {formatRelative(ticket.last_synced_at)}</span>
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
function Pipe() {
  return <div className="self-stretch w-px bg-border mx-1" />;
}

/**
 * Segmented control filter group — items share a connected border, no "|" separators.
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
  return (
    <div className="flex items-center">
      {items.map((item, i) => {
        const isFirst = i === 0;
        const isLast = i === items.length - 1;
        const isActive = active.has(item);
        return (
          <button
            key={item}
            onClick={() => onToggle(item)}
            className={cn(
              "relative px-2 py-0.5 text-xs font-medium border transition-colors",
              isFirst ? "rounded-l-sm" : "-ml-px",
              isLast ? "rounded-r-sm" : "",
              isActive
                ? cn("z-10", colorFn ? colorFn(item) : "bg-accent text-accent-foreground border-border")
                : "border-border/50 text-muted-foreground hover:bg-muted/30 hover:text-foreground hover:z-10",
            )}
          >
            {label ? label(item) : item}
          </button>
        );
      })}
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

function SastIssueRow({
  issue, isAdmin, jiraTicket, scopeId, autoExpand, sourceUrlTemplate,
}: {
  issue: SastIssue; isAdmin: boolean; jiraTicket?: JiraTicket | null;
  scopeId: string; autoExpand?: boolean; sourceUrlTemplate: string | null;
}) {
  const [expanded, setExpanded] = useState(autoExpand ?? false);
  const [linkError, setLinkError] = useState<string>();
  const rowRef = useRef<HTMLTableRowElement>(null);

  // Scroll into view when auto-expanded from a shared link
  useEffect(() => {
    if (autoExpand && rowRef.current) {
      rowRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [autoExpand]);

  const copyLink = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(`${window.location.origin}/scopes/${scopeId}?issue=${issue.id}`);
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
        className="group cursor-pointer hover:bg-muted/40"
        onClick={() => setExpanded((v) => !v)}
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
            {truncateFilePath(issue.latest_file_path)}:{issue.latest_start_line}
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
        <TableCell className="text-xs text-muted-foreground tabular-nums">
          {issue.triage_confidence != null
            ? `${Math.round(issue.triage_confidence * 100)}%`
            : "—"}
        </TableCell>
        <TableCell className="text-xs text-muted-foreground">
          {formatRelative(issue.last_seen_at)}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={7} className="bg-muted/30 p-4">
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
            {issue.latest_snippet && (
              <ContextSnippet
                snippet={issue.latest_snippet}
                matchLine={issue.latest_start_line}
                summary={issue.latest_llm_summary}
                ruleMessage={issue.latest_rule_message}
                className="mb-3"
              />
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

function SastIssuesTab({ scopeId, highlightIssueId, sourceUrlTemplate }: { scopeId: string; highlightIssueId?: string; sourceUrlTemplate: string | null }) {
  const { data: user } = useMe();
  const isAdmin = user?.role === "admin";
  const [filters, setFilters] = useState<SastIssueFilters>({ page: 1, page_size: 50 });

  const { data, isLoading } = useScopeSastIssues(scopeId, filters);
  const { data: jiraTickets } = useScopeJiraTickets(scopeId);
  const ticketById = new Map((jiraTickets ?? []).map((t) => [t.id, t]));

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
                  <TableHead className="w-20" title="Detection or triage confidence">Conf.</TableHead>
                  <TableHead className="w-24">Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.items.map((issue) => (
                  <SastIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} jiraTicket={issue.jira_ticket_id ? ticketById.get(issue.jira_ticket_id) : null} scopeId={scopeId} autoExpand={issue.id === highlightIssueId} sourceUrlTemplate={sourceUrlTemplate} />
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
  issue, isAdmin, jiraTicket, scopeId, autoExpand, sourceUrlTemplate,
}: {
  issue: ScaIssue; isAdmin: boolean; jiraTicket?: JiraTicket | null;
  scopeId: string; autoExpand?: boolean; sourceUrlTemplate: string | null;
}) {
  const [expanded, setExpanded] = useState(autoExpand ?? false);
  const [linkError, setLinkError] = useState<string>();
  const rowRef = useRef<HTMLTableRowElement>(null);
  const dismiss = useDismissScaIssue();
  const linkJira = useLinkScaIssueToJira();
  const unlinkJira = useUnlinkScaIssueFromJira();
  const refreshJira = useRefreshJiraTicket();

  useEffect(() => {
    if (autoExpand && rowRef.current) {
      rowRef.current.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }, [autoExpand]);

  const copyLink = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(`${window.location.origin}/scopes/${scopeId}?issue=${issue.id}`);
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
        className="group cursor-pointer hover:bg-muted/40"
        onClick={() => setExpanded((v) => !v)}
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
              {issue.latest_llm_summary ?? issue.latest_summary}
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
          {issue.latest_manifest_file ? (
            <>
              <div
                className="truncate text-xs text-muted-foreground font-mono"
                title={`${issue.latest_manifest_file}${issue.latest_manifest_line ? `:${issue.latest_manifest_line}` : ""}`}
              >
                {truncateFilePath(issue.latest_manifest_file)}
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
          {formatRelative(issue.last_seen_at)}
        </TableCell>
      </TableRow>
      {expanded && (
        <TableRow>
          <TableCell colSpan={6} className="bg-muted/30 p-4 space-y-3">
            {issue.latest_actively_exploited && (
              <div className="flex items-start gap-2 rounded border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0" />
                <span>
                  <span className="font-semibold">Actively exploited</span>
                  {" — "}listed in CISA KEV. Prioritize remediation.
                </span>
              </div>
            )}
            {issue.latest_llm_summary && (
              <p className="text-sm">{issue.latest_llm_summary}</p>
            )}
            {issue.latest_summary && issue.latest_summary !== issue.latest_llm_summary && (
              <p className="text-xs text-muted-foreground">
                <span className="font-medium">Advisory: </span>
                {issue.latest_summary}
              </p>
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
                issue={issue}
                isAdmin={isAdmin}
                onDismiss={(s) => act(s)}
                isPending={dismiss.isPending}
                sourceUrlTemplate={sourceUrlTemplate}
              />
            )}
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

function ScaIssuesTab({ scopeId, highlightIssueId, sourceUrlTemplate }: { scopeId: string; highlightIssueId?: string; sourceUrlTemplate: string | null }) {
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
                  <ScaIssueRow key={issue.id} issue={issue} isAdmin={isAdmin} jiraTicket={issue.jira_ticket_id ? ticketById.get(issue.jira_ticket_id) : null} scopeId={scopeId} autoExpand={issue.id === highlightIssueId} sourceUrlTemplate={sourceUrlTemplate} />
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
                    <TableCell className="font-mono text-sm">
                      <span className="inline-flex items-center gap-1.5">
                        {c.name}
                        {c.is_dev_only && (
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
                    <TableCell className="text-sm text-muted-foreground">{c.version ?? "—"}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{c.ecosystem ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{c.component_type}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {c.scope === "required" ? "runtime" : (c.scope ?? "—")}
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
                    <span className="text-muted-foreground text-xs">
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
  const highlightIssueId = searchParams.get("issue") ?? undefined;
  const { data: scope, isLoading, isError } = useScopeDetail(id);
  const { data: appSettings } = useSettings();
  const { data: scans } = useScopeScans(id, 1);
  const triggerScan = useTriggerScan();
  const llmConfigured = !!(appSettings?.llm_base_url && appSettings?.llm_model && appSettings?.llm_credential_id);
  const activeScanStatus = scans?.[0]?.status;
  const isScanning = activeScanStatus === "pending" || activeScanStatus === "running" || triggerScan.isPending;

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
          {id && <ScaIssuesTab scopeId={id} highlightIssueId={highlightIssueId} sourceUrlTemplate={scope?.source_url_template ?? null} />}
        </TabsContent>
        <TabsContent forceMount value="sast" className="mt-4 min-h-80 data-[state=inactive]:hidden">
          {id && <SastIssuesTab scopeId={id} highlightIssueId={highlightIssueId} sourceUrlTemplate={scope?.source_url_template ?? null} />}
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
