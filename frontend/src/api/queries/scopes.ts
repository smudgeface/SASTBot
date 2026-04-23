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
  });
}

export function useScopeDetail(scopeId: string | undefined) {
  return useQuery<ScopeDetail>({
    queryKey: [...scopesKey, scopeId],
    queryFn: () => apiFetch<ScopeDetail>(`/api/scopes/${scopeId}`),
    enabled: !!scopeId,
  });
}

export interface SastIssueFilters {
  page?: number;
  page_size?: number;
  severity?: string;
  triage_status?: string;
  has_jira_ticket?: "yes" | "no";
  seen_since_last_scan?: "new" | "unchanged" | "resolved";
  include_resolved?: boolean;
}

export function useScopeSastIssues(scopeId: string | undefined, filters: SastIssueFilters = {}) {
  return useQuery<Paginated<SastIssue>>({
    queryKey: [...scopesKey, scopeId, "sast-issues", filters],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.page) params.set("page", String(filters.page));
      if (filters.page_size) params.set("page_size", String(filters.page_size));
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.triage_status) params.set("triage_status", filters.triage_status);
      if (filters.has_jira_ticket) params.set("has_jira_ticket", filters.has_jira_ticket);
      if (filters.seen_since_last_scan) params.set("seen_since_last_scan", filters.seen_since_last_scan);
      if (filters.include_resolved) params.set("include_resolved", "true");
      const qs = params.toString();
      return apiFetch<Paginated<SastIssue>>(`/api/scopes/${scopeId}/sast-issues${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scopeId,
  });
}

export interface ScaIssueFilters {
  page?: number;
  page_size?: number;
  severity?: string;
  finding_type?: string;
  dismissed_status?: string;
  has_jira_ticket?: "yes" | "no";
  reachable?: boolean;
  has_fix?: boolean;
  hide_dev?: boolean;
  seen_since_last_scan?: "new" | "unchanged" | "resolved";
  include_resolved?: boolean;
}

export function useScopeScaIssues(scopeId: string | undefined, filters: ScaIssueFilters = {}) {
  return useQuery<Paginated<ScaIssue>>({
    queryKey: [...scopesKey, scopeId, "sca-issues", filters],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.page) params.set("page", String(filters.page));
      if (filters.page_size) params.set("page_size", String(filters.page_size));
      if (filters.severity) params.set("severity", filters.severity);
      if (filters.finding_type) params.set("finding_type", filters.finding_type);
      if (filters.dismissed_status) params.set("dismissed_status", filters.dismissed_status);
      if (filters.has_jira_ticket) params.set("has_jira_ticket", filters.has_jira_ticket);
      if (filters.reachable) params.set("reachable", "true");
      if (filters.has_fix) params.set("has_fix", "true");
      if (filters.hide_dev) params.set("hide_dev", "true");
      if (filters.seen_since_last_scan) params.set("seen_since_last_scan", filters.seen_since_last_scan);
      if (filters.include_resolved) params.set("include_resolved", "true");
      const qs = params.toString();
      return apiFetch<Paginated<ScaIssue>>(`/api/scopes/${scopeId}/sca-issues${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scopeId,
  });
}

export function useScopeComponents(
  scopeId: string | undefined,
  options?: { page?: number; page_size?: number; has_findings?: boolean },
) {
  return useQuery<Paginated<SbomComponent>>({
    queryKey: [...scopesKey, scopeId, "components", options],
    queryFn: () => {
      const params = new URLSearchParams();
      if (options?.page) params.set("page", String(options.page));
      if (options?.page_size) params.set("page_size", String(options.page_size));
      if (options?.has_findings) params.set("has_findings", "true");
      const qs = params.toString();
      return apiFetch<Paginated<SbomComponent>>(`/api/scopes/${scopeId}/components${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scopeId,
  });
}

export function useScopeScans(scopeId: string | undefined, limit = 20) {
  return useQuery<ScanRunSummary[]>({
    queryKey: [...scopesKey, scopeId, "scans"],
    queryFn: () => apiFetch<ScanRunSummary[]>(`/api/scopes/${scopeId}/scans?limit=${limit}`),
    enabled: !!scopeId,
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
      status: "confirmed" | "false_positive" | "suppressed" | "pending";
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
      status: "active" | "acknowledged" | "wont_fix" | "false_positive";
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
