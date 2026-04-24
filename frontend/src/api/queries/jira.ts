import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { JiraResolution, JiraTicket } from "@/api/types";
import { scopesKey } from "./scopes";

// ---------------------------------------------------------------------------
// Connection check + resolutions
// ---------------------------------------------------------------------------

export type JiraCheckResult =
  | { ok: true; account_name: string; account_email: string }
  | { ok: false; error: string };

export function useCheckJiraConnection() {
  return useMutation({
    mutationFn: () =>
      apiFetch<JiraCheckResult>("/admin/settings/jira/check", { method: "POST", json: {} }),
  });
}

export function useJiraResolutions(enabled = false) {
  return useQuery<JiraResolution[]>({
    queryKey: ["admin", "jira", "resolutions"],
    queryFn: () => apiFetch<JiraResolution[]>("/admin/jira/resolutions"),
    enabled,
    staleTime: 30 * 60 * 1000, // resolutions change rarely; cache 30 min
  });
}

// ---------------------------------------------------------------------------
// Link / unlink
// ---------------------------------------------------------------------------

export function useLinkSastIssueToJira() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ issueId, issueKey }: { issueId: string; issueKey: string }) =>
      apiFetch<JiraTicket>(`/api/sast-issues/${issueId}/jira-ticket`, {
        method: "POST",
        json: { issue_key: issueKey },
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: scopesKey }); },
  });
}

export function useUnlinkSastIssueFromJira() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (issueId: string) =>
      apiFetch<void>(`/api/sast-issues/${issueId}/jira-ticket`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: scopesKey }); },
  });
}

export function useLinkScaIssueToJira() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ issueId, issueKey }: { issueId: string; issueKey: string }) =>
      apiFetch<JiraTicket>(`/api/sca-issues/${issueId}/jira-ticket`, {
        method: "POST",
        json: { issue_key: issueKey },
      }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: scopesKey }); },
  });
}

export function useUnlinkScaIssueFromJira() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (issueId: string) =>
      apiFetch<void>(`/api/sca-issues/${issueId}/jira-ticket`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: scopesKey }); },
  });
}

// ---------------------------------------------------------------------------
// On-demand refresh
// ---------------------------------------------------------------------------

export function useRefreshJiraTicket() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (issueKey: string) =>
      apiFetch<JiraTicket>(`/admin/jira-tickets/${issueKey}/refresh`, { method: "POST", json: {} }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: scopesKey }); },
  });
}

// ---------------------------------------------------------------------------
// Fetch all JiraTickets linked to issues in a scope (for tab display)
// ---------------------------------------------------------------------------

export function useScopeJiraTickets(scopeId: string | undefined) {
  return useQuery<JiraTicket[]>({
    queryKey: [...scopesKey, scopeId, "jira-tickets"],
    queryFn: () =>
      apiFetch<JiraTicket[]>(`/api/scopes/${scopeId}/jira-tickets`),
    enabled: !!scopeId,
    staleTime: 2 * 60 * 1000,
  });
}
