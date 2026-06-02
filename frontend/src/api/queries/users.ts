import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { AdminUser } from "@/api/types";

export const usersQueryKey = ["admin", "users"] as const;

export function useUsers() {
  return useQuery<AdminUser[]>({
    queryKey: usersQueryKey,
    queryFn: () => apiFetch<AdminUser[]>("/admin/users"),
  });
}

export interface CreateUserInput {
  email: string;
  name?: string;
  role: "admin" | "user";
  password: string;
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateUserInput) =>
      apiFetch<AdminUser>("/admin/users", { method: "POST", json: input }),
    onSuccess: () => qc.invalidateQueries({ queryKey: usersQueryKey }),
  });
}

export interface UpdateUserInput {
  id: string;
  name?: string | null;
  role?: "admin" | "user";
  is_active?: boolean;
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: UpdateUserInput) =>
      apiFetch<AdminUser>(`/admin/users/${id}`, { method: "PATCH", json: body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: usersQueryKey }),
  });
}

export function useResetUserPassword() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      apiFetch<AdminUser>(`/admin/users/${id}/reset-password`, { method: "POST", json: { password } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: usersQueryKey }),
  });
}

export function useDeleteUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<{ ok: boolean }>(`/admin/users/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: usersQueryKey }),
  });
}
