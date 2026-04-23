import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { AdminSettings, AdminSettingsUpdate } from "@/api/types";

export const settingsKey = ["admin", "settings"] as const;

export function useSettings() {
  return useQuery<AdminSettings>({
    queryKey: settingsKey,
    queryFn: () => apiFetch<AdminSettings>("/admin/settings"),
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: AdminSettingsUpdate) =>
      apiFetch<AdminSettings>("/admin/settings", { method: "PUT", json: input }),
    onSuccess: (updated) => {
      qc.setQueryData(settingsKey, updated);
      qc.invalidateQueries({ queryKey: ["admin", "credentials"] });
    },
  });
}

export interface LlmCheckResult {
  success: boolean;
  latency_ms: number;
  model: string;
  input_tokens: number;
  output_tokens: number;
  error?: string;
}

export function useCheckLlm() {
  return useMutation({
    mutationFn: () =>
      apiFetch<LlmCheckResult>("/admin/settings/llm/check", { method: "POST" }),
  });
}
