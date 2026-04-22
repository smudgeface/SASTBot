import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type {
  Credential,
  CredentialCreateInput,
  CredentialRotateInput,
} from "@/api/types";

export const credentialsKey = ["admin", "credentials"] as const;

export function useCredentials() {
  return useQuery<Credential[]>({
    queryKey: credentialsKey,
    queryFn: () => apiFetch<Credential[]>("/admin/credentials"),
  });
}

export function useCreateCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CredentialCreateInput) =>
      apiFetch<Credential>("/admin/credentials", { method: "POST", json: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: credentialsKey }),
  });
}

export function useRenameCredential(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      apiFetch<Credential>(`/admin/credentials/${id}`, {
        method: "PATCH",
        json: { name },
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: credentialsKey }),
  });
}

export function useRotateCredential(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CredentialRotateInput) =>
      apiFetch<Credential>(`/admin/credentials/${id}/rotate`, {
        method: "POST",
        json: input,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: credentialsKey }),
  });
}

export function useDeleteCredential() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<void>(`/admin/credentials/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: credentialsKey });
    },
  });
}
