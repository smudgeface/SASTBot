import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { Scan, SastFinding, SbomComponent, ScanFinding } from "@/api/types";

export const scansKey = ["scans"] as const;

/**
 * Auto-refetch `/scans` every 2s whenever any row is still pending or
 * running, so the UI feels live without manual refresh. Once everything
 * is terminal (`success` | `failed`) the refetch stops.
 */
export function useScans() {
  return useQuery<Scan[]>({
    queryKey: scansKey,
    queryFn: () => apiFetch<Scan[]>("/scans"),
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      const live = data.some((s) => s.status === "pending" || s.status === "running");
      return live ? 2000 : false;
    },
  });
}

export function useScanComponents(scanId: string | undefined) {
  return useQuery<SbomComponent[]>({
    queryKey: [...scansKey, scanId, "components"],
    queryFn: () => apiFetch<SbomComponent[]>(`/scans/${scanId}/components`),
    enabled: !!scanId,
    staleTime: Infinity,
  });
}

export function useSbomJson(scanId: string | undefined) {
  return useQuery<string>({
    queryKey: [...scansKey, scanId, "sbom"],
    queryFn: async () => {
      // apiFetch parses the JSON body; re-stringify pretty-printed for the editor.
      const data = await apiFetch<unknown>(`/scans/${scanId}/sbom`);
      return JSON.stringify(data, null, 2);
    },
    enabled: !!scanId,
    staleTime: Infinity, // SBOM for a completed scan never changes
  });
}

export function useScanDetail(scanId: string | undefined) {
  return useQuery<Scan>({
    queryKey: [...scansKey, scanId],
    queryFn: () => apiFetch<Scan>(`/scans/${scanId}`),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      const live = data.status === "pending" || data.status === "running";
      return live ? 2000 : false;
    },
  });
}

export function useScanFindings(
  scanId: string | undefined,
  options?: { severity?: string; package?: string },
) {
  return useQuery<ScanFinding[]>({
    queryKey: [...scansKey, scanId, "findings", options],
    queryFn: () => {
      const params = new URLSearchParams();
      if (options?.severity) params.set("severity", options.severity);
      if (options?.package) params.set("package", options.package);
      const qs = params.toString();
      return apiFetch<ScanFinding[]>(`/scans/${scanId}/findings${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scanId,
  });
}

/** Trigger a scan for a given repo (one run per active scope).
 *  Invalidates the scans list so the new pending rows appear immediately. */
export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (repoId: string) =>
      apiFetch<Scan[]>(`/admin/repos/${repoId}/scan`, { method: "POST" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: scansKey });
    },
  });
}

export function useSastFindings(
  scanId: string | undefined,
  options?: { severity?: string; triage_status?: string; file_path?: string },
) {
  return useQuery<SastFinding[]>({
    queryKey: [...scansKey, scanId, "sast-findings", options],
    queryFn: () => {
      const params = new URLSearchParams();
      if (options?.severity) params.set("severity", options.severity);
      if (options?.triage_status) params.set("triage_status", options.triage_status);
      if (options?.file_path) params.set("file_path", options.file_path);
      const qs = params.toString();
      return apiFetch<SastFinding[]>(`/scans/${scanId}/sast-findings${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scanId,
  });
}

export function useTriageSastFinding(scanId: string | undefined) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({
      findingId,
      status,
      reason,
    }: {
      findingId: string;
      status: "confirmed" | "false_positive" | "suppressed";
      reason?: string;
    }) =>
      apiFetch<SastFinding>(`/scans/${scanId}/sast-findings/${findingId}/triage`, {
        method: "POST",
        json: { status, reason },
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [...scansKey, scanId, "sast-findings"] });
    },
  });
}
