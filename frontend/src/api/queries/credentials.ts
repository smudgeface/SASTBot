import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { Credential } from "@/api/types";

export const credentialsKey = ["admin", "credentials"] as const;

export function useCredentials() {
  return useQuery<Credential[]>({
    queryKey: credentialsKey,
    queryFn: () => apiFetch<Credential[]>("/admin/credentials"),
  });
}

export function useDeleteCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/admin/credentials/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: credentialsKey });
    },
  });
}
