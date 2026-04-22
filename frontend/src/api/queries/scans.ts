import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { Scan, ScanFinding } from "@/api/types";

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

/** Trigger a scan for a given repo. Backend returns the freshly-created
 *  scan_runs row (status "pending"); we invalidate the scans list so the
 *  UI picks it up immediately. */
export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (repoId: string) =>
      apiFetch<Scan>(`/admin/repos/${repoId}/scan`, { method: "POST" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: scansKey });
    },
  });
}
