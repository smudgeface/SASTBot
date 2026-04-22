import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { Scan } from "@/api/types";

export const scansKey = ["scans"] as const;

export function useScans() {
  return useQuery<Scan[]>({
    queryKey: scansKey,
    queryFn: () => apiFetch<Scan[]>("/scans"),
  });
}
