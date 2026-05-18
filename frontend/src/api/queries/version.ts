import { useQuery } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";

export interface VersionInfo {
  app: string;
  schema: string;
  expected_schema: string;
  sastbot_dump_format_version: number;
}

export const versionKey = ["version"] as const;

export function useVersion() {
  return useQuery<VersionInfo>({
    queryKey: versionKey,
    queryFn: () => apiFetch<VersionInfo>("/version"),
    // Version info rarely changes — only re-fetch on mount.
    staleTime: 60_000,
    // Don't throw on error — the footer can silently show nothing.
    retry: 1,
  });
}
