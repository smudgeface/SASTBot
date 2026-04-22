import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { Scan } from "@/api/types";

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
