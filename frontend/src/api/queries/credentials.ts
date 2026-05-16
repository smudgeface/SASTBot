import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type {
  Credential,
  CredentialCreateInput,
  CredentialRotateInput,
  Paginated,
} from "@/api/types";

export const credentialsKey = ["admin", "credentials"] as const;

export interface CredentialsListFilters {
  page?: number;
  page_size?: number;
}

export function useCredentials(filters: CredentialsListFilters = {}) {
  return useQuery<Paginated<Credential>>({
    queryKey: [...credentialsKey, filters],
    queryFn: () => {
      const params = new URLSearchParams();
      if (filters.page) params.set("page", String(filters.page));
      if (filters.page_size) params.set("page_size", String(filters.page_size));
      const qs = params.toString();
      return apiFetch<Paginated<Credential>>(`/admin/credentials${qs ? `?${qs}` : ""}`);
    },
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
