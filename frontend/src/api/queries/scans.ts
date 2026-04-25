import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
// useQueryClient kept for useTriggerScan

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

/** Cancel a pending or running scan run. Removes the BullMQ job if it's
 *  still queued; if the worker already picked it up, sets status=cancelled
 *  and the worker bails on its next phase boundary. Idempotent. */
export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (scanRunId: string) =>
      apiFetch<Scan>(`/scans/${scanRunId}/cancel`, { method: "POST" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: scansKey });
      qc.invalidateQueries({ queryKey: ["scopes"] });
    },
  });
}

/** Trigger a scan for a given repo (one run per active scope).
 *  Synchronously prepends the new pending run(s) onto the per-scope scans
 *  cache so the "Scanning…" spinner on /scopes/:id is up the instant the
 *  trigger HTTP call returns — without this the polling cache still holds
 *  the previous run's success/failed status until the next 3s tick and the
 *  button flickers back to "Scan now" in between. */
export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (repoId: string) =>
      apiFetch<Scan[]>(`/admin/repos/${repoId}/scan`, { method: "POST" }),
    onSuccess: (runs) => {
      // 1. Prepend each new run to its scope's scans cache (used by the
      //    polling hook on the scope detail page).
      for (const run of runs) {
        const key = ["scopes", run.scope_id, "scans"] as const;
        qc.setQueryData<{ id: string; status: string }[]>(key, (old) => {
          const stub = {
            id: run.id,
            status: run.status, // "pending" — guarantees isScanning=true
            triggered_by: run.triggered_by,
            started_at: run.started_at,
            finished_at: run.finished_at,
            error: run.error,
            component_count: run.component_count,
            critical_count: run.critical_count,
            high_count: run.high_count,
            sast_finding_count: 0,
            created_at: new Date().toISOString(),
          };
          return [stub, ...(old ?? [])];
        });
      }
      // 2. Standard invalidations so the audit list and any other consumers
      //    refresh from the server too.
      qc.invalidateQueries({ queryKey: scansKey });
      qc.invalidateQueries({ queryKey: ["scopes"] });
    },
  });
}

export function useSastFindings(
  scanId: string | undefined,
  options?: { severity?: string; file_path?: string },
) {
  return useQuery<SastFinding[]>({
    queryKey: [...scansKey, scanId, "sast-findings", options],
    queryFn: () => {
      const params = new URLSearchParams();
      if (options?.severity) params.set("severity", options.severity);
      if (options?.file_path) params.set("file_path", options.file_path);
      const qs = params.toString();
      return apiFetch<SastFinding[]>(`/scans/${scanId}/sast-findings${qs ? `?${qs}` : ""}`);
    },
    enabled: !!scanId,
  });
}
