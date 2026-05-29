import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type {
  Paginated,
  SastIssue,
  ScaIssue,
  SbomComponent,
  ScanRunSummary,
  ScopeDetail,
  ScopeListItem,
} from "@/api/types";

export const scopesKey = ["scopes"] as const;

export function useScopes(options?: { repo_id?: string; include_inactive?: boolean }) {
  return useQuery<ScopeListItem[]>({
    queryKey: [...scopesKey, options],
    queryFn: () => {
      const params = new URLSearchParams();
      if (options?.repo_id) params.set("repo_id", options.repo_id);
      if (options?.include_inactive) params.set("include_inactive", "true");
      const qs = params.toString();
      return apiFetch<ScopeListItem[]>(`/api/scopes${qs ? `?${qs}` : ""}`);
    },
    // Poll every 3s while any scope has an active scan, so the live progress
    // cell stays current. Returning false stops the polling once everything is idle.
    refetchInterval: (q) => {
      const data = q.state.data as ScopeListItem[] | undefined;
      return data?.some((s) => s.active_scan) ? 3000 : false;
    },
  });
}

export function useScopeDetail(scopeId: string | undefined) {
  return useQuery<ScopeDetail>({
    queryKey: [...scopesKey, scopeId],
    queryFn: () => apiFetch<ScopeDetail>(`/api/scopes/${scopeId}`),
    enabled: !!scopeId,
  });
}

// Sort keys exposed by the SCA / SAST list endpoints. Keep these in sync
// with backend/src/schemas.ts (ScaSortBySchema / SastSortBySchema).
export type IssueSortKey = "severity" | "summary" | "location" | "status" | "last_seen";
export type IssueSortDir = "asc" | "desc";

export interface SastIssueFilters {
  page?: number;
  page_size?: number;
  severities?: string[];       // multi-select: show all in set (OR); empty = no filter
  triage_statuses?: string[];  // multi-select
  has_jira_ticket?: "yes" | "no";
  seen_since_last_scan?: "new" | "unchanged" | "resolved";
  include_resolved?: boolean;
  sort_by?: IssueSortKey;
  sort_dir?: IssueSortDir;
}

export function useScopeSastIssues(scopeId: string | undefined, filters: SastIssueFilters = {}) {
  return useQuery<Paginated<SastIssue>>({
    queryKey: [...scopesKey, scopeId, "sast-issues", filters],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.page) params.set("page", String(filters.page));
      if (filters.page_size) params.set("page_size", String(filters.page_size));
      filters.severities?.forEach((s) => params.append("severity", s));
      filters.triage_statuses?.forEach((s) => params.append("triage_status", s));
      if (filters.has_jira_ticket) params.set("has_jira_ticket", filters.has_jira_ticket);
      if (filters.seen_since_last_scan) params.set("seen_since_last_scan", filters.seen_since_last_scan);
      if (filters.include_resolved) params.set("include_resolved", "true");
      if (filters.sort_by) {
        params.set("sort_by", filters.sort_by);
        params.set("sort_dir", filters.sort_dir ?? "asc");
      }
      const qs = params.toString();
      return apiFetch<Paginated<SastIssue>>(`/api/scopes/${scopeId}/sast-issues${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scopeId,
  });
}

export interface ScaIssueFilters {
  page?: number;
  page_size?: number;
  severities?: string[];      // multi-select
  finding_types?: string[];   // multi-select
  dismissed_status?: string;
  dismissed_statuses?: string[];  // multi-select
  has_jira_ticket?: "yes" | "no";
  reachable?: boolean;
  has_fix?: boolean;
  seen_since_last_scan?: "new" | "unchanged" | "resolved";
  include_resolved?: boolean;
  /** When true (default), hides issues where latestIsDevOnly = true. */
  exclude_dev_only?: boolean;
  sort_by?: IssueSortKey;
  sort_dir?: IssueSortDir;
}

export function useScopeScaIssues(scopeId: string | undefined, filters: ScaIssueFilters = {}) {
  return useQuery<Paginated<ScaIssue>>({
    queryKey: [...scopesKey, scopeId, "sca-issues", filters],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.page) params.set("page", String(filters.page));
      if (filters.page_size) params.set("page_size", String(filters.page_size));
      filters.severities?.forEach((s) => params.append("severity", s));
      filters.finding_types?.forEach((t) => params.append("finding_type", t));
      if (filters.dismissed_status) params.set("dismissed_status", filters.dismissed_status);
      filters.dismissed_statuses?.forEach((s) => params.append("dismissed_statuses", s));
      if (filters.has_jira_ticket) params.set("has_jira_ticket", filters.has_jira_ticket);
      if (filters.reachable) params.set("reachable", "true");
      if (filters.has_fix) params.set("has_fix", "true");
      if (filters.seen_since_last_scan) params.set("seen_since_last_scan", filters.seen_since_last_scan);
      if (filters.include_resolved) params.set("include_resolved", "true");
      // Default: exclude dev-only (matches backend default of true). Pass false explicitly only when showing build-tool CVEs.
      if (filters.exclude_dev_only === false) params.set("exclude_dev_only", "false");
      if (filters.sort_by) {
        params.set("sort_by", filters.sort_by);
        params.set("sort_dir", filters.sort_dir ?? "asc");
      }
      const qs = params.toString();
      return apiFetch<Paginated<ScaIssue>>(`/api/scopes/${scopeId}/sca-issues${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scopeId,
  });
}

export type ScopeComponentDismissedStatus = "active" | "not_found" | "ignored";

export function useScopeComponents(
  scopeId: string | undefined,
  options?: {
    page?: number;
    page_size?: number;
    has_findings?: boolean;
    exclude_dev_only?: boolean;
    /** When provided, filters by dismissed_status IN <values>. Empty/omitted = active only. */
    dismissed_statuses?: ScopeComponentDismissedStatus[];
  },
) {
  return useQuery<Paginated<SbomComponent>>({
    queryKey: [...scopesKey, scopeId, "components", options],
    queryFn: () => {
      const params = new URLSearchParams();
      if (options?.page) params.set("page", String(options.page));
      if (options?.page_size) params.set("page_size", String(options.page_size));
      if (options?.has_findings) params.set("has_findings", "true");
      // Default: exclude dev-only. Pass false explicitly only when showing build-tool packages.
      if (options?.exclude_dev_only === false) params.set("exclude_dev_only", "false");
      // dismissed_statuses: when provided, pass each value; omit entirely for backend default (active).
      options?.dismissed_statuses?.forEach((s) => params.append("dismissed_statuses", s));
      const qs = params.toString();
      return apiFetch<Paginated<SbomComponent>>(`/api/scopes/${scopeId}/components${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scopeId,
  });
}

/**
 * Soft-ignore a scope_component. Cascades to suppress all pending/confirmed
 * SCA issues for this package. Sticky: future CVEs on the same package also
 * land as suppressed. Reversible via useUnignoreScopeComponent.
 *
 */
export function useIgnoreScopeComponent(scopeId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ componentId, reason }: { componentId: string; reason?: string }) =>
      apiFetch<{ ok: true; suppressed_sca_count: number }>(
        `/api/scopes/${scopeId}/components/${componentId}/ignore`,
        {
          method: "POST",
          body: reason ? JSON.stringify({ reason }) : JSON.stringify({}),
          headers: { "Content-Type": "application/json" },
        },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scope-components", scopeId] });
      queryClient.invalidateQueries({ queryKey: [...scopesKey, scopeId, "components"] });
      queryClient.invalidateQueries({ queryKey: [...scopesKey, scopeId, "sca-issues"] });
    },
  });
}

/**
 * Restore (un-ignore) a scope_component. Only reverts SCA suppressions that
 * were created by the ignore cascade (dismissed_reason='component_ignored').
 * Dev-tree-policy suppressions are left alone.
 *
 */
export function useUnignoreScopeComponent(scopeId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ componentId }: { componentId: string }) =>
      apiFetch<{ ok: true; restored_sca_count: number }>(
        `/api/scopes/${scopeId}/components/${componentId}/unignore`,
        { method: "POST", json: {} },
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scope-components", scopeId] });
      queryClient.invalidateQueries({ queryKey: [...scopesKey, scopeId, "components"] });
      queryClient.invalidateQueries({ queryKey: [...scopesKey, scopeId, "sca-issues"] });
    },
  });
}

/**
 * Fetch the most recent scan's SBOM JSON for a scope, pretty-printed for
 * display in the viewer. Hits the M6q scope-level SBOM endpoint which
 * serves the same payload the download button delivers — the
 * Content-Disposition header is harmless when fetched programmatically.
 */
export function useScopeSbomJson(scopeId: string | undefined) {
  return useQuery<string>({
    queryKey: [...scopesKey, scopeId, "sbom-json"],
    queryFn: async () => {
      const data = await apiFetch<unknown>(`/api/scopes/${scopeId}/sbom-json`);
      return JSON.stringify(data, null, 2);
    },
    enabled: !!scopeId,
    staleTime: Infinity, // SBOM for a completed scan never changes
  });
}

export function useScopeScans(scopeId: string | undefined, limit = 20) {
  const qc = useQueryClient();
  return useQuery<ScanRunSummary[]>({
    queryKey: [...scopesKey, scopeId, "scans"],
    queryFn: async () => {
      const data = await apiFetch<ScanRunSummary[]>(`/api/scopes/${scopeId}/scans?limit=${limit}`);
      // When a scan is active we poll; when the most recent run flips to a
      // terminal state, refresh the scope detail + issues so counts and
      // last-scan time update without a page reload.
      const top = data[0];
      if (top && (top.status === "success" || top.status === "failed")) {
        const cached = qc.getQueryData<ScanRunSummary[]>([...scopesKey, scopeId, "scans"]);
        const prevTop = cached?.[0];
        if (prevTop && (prevTop.status === "pending" || prevTop.status === "running")) {
          qc.invalidateQueries({ queryKey: scopesKey });
        }
      }
      return data;
    },
    enabled: !!scopeId,
    refetchInterval: (query) => {
      const top = query.state.data?.[0];
      return top && (top.status === "pending" || top.status === "running") ? 3000 : false;
    },
  });
}

/**
 * Operator-edit of identity fields on a scope_component. Used to backfill or
 * correct `component_root` and `evidence_paths` when the LLM picked something
 * wrong or left them empty. Server marks the row `source='manual_override'`
 * so values stick across scans.
 */
export function usePatchScopeComponent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      scopeId,
      componentId,
      name,
      component_root,
      evidence,
    }: {
      scopeId: string;
      componentId: string;
      name?: string;
      component_root?: string | null;
      evidence?: Array<{ path: string; line?: number | null }>;
    }) =>
      apiFetch<{ ok: true }>(`/api/scopes/${scopeId}/components/${componentId}`, {
        method: "PATCH",
        json: { name, component_root, evidence },
      }),
    onSuccess: (_data, vars) => {
      qc.invalidateQueries({ queryKey: [...scopesKey, vars.scopeId, "components"] });
    },
  });
}

/**
 * Manually delete a scope_component. Used to clean up residual duplicate rows
 * the deterministic matcher doesn't catch. Hard delete — the row is gone; if
 * it's a real component, the next scan re-emits it and componentMatch
 * collapses it back into the canonical row, so this is safe to use freely.
 */
export function useDeleteScopeComponent() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      scopeId,
      componentId,
    }: {
      scopeId: string;
      componentId: string;
    }) =>
      apiFetch<void>(`/api/scopes/${scopeId}/components/${componentId}`, {
        method: "DELETE",
      }),
    onSuccess: (_data, vars) => {
      // Invalidate the components list for this scope so the row disappears.
      qc.invalidateQueries({ queryKey: [...scopesKey, vars.scopeId, "components"] });
    },
  });
}

export function useTriageSastIssue() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      issueId,
      status,
      reason,
    }: {
      issueId: string;
      status: "confirmed" | "false_positive" | "suppressed" | "pending" | "fixed" | "planned";
      reason?: string;
    }) =>
      apiFetch<SastIssue>(`/api/sast-issues/${issueId}/triage`, {
        method: "POST",
        json: { status, reason },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: scopesKey });
    },
  });
}

export function useDismissScaIssue() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      issueId,
      status,
      reason,
    }: {
      issueId: string;
      status: "pending" | "confirmed" | "suppressed" | "false_positive" | "planned" | "fixed";
      reason?: string;
    }) =>
      apiFetch<ScaIssue>(`/api/sca-issues/${issueId}/dismiss`, {
        method: "POST",
        json: { status, reason },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: scopesKey });
    },
  });
}
