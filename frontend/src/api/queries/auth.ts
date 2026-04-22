import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch, ApiError } from "@/api/client";
import type { User } from "@/api/types";
import { useAuthStore } from "@/stores/auth";

export const meQueryKey = ["me"] as const;

export function useMe() {
  const setUser = useAuthStore((s) => s.setUser);
  const clearUser = useAuthStore((s) => s.clearUser);

  return useQuery<User | null>({
    queryKey: meQueryKey,
    queryFn: async () => {
      try {
        const me = await apiFetch<User>("/auth/me");
        setUser(me);
        return me;
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          clearUser();
          return null;
        }
        throw err;
      }
    },
    staleTime: 60_000,
  });
}

export interface LoginInput {
  email: string;
  password: string;
}

export function useLogin() {
  const qc = useQueryClient();
  const setUser = useAuthStore((s) => s.setUser);

  return useMutation({
    mutationFn: (input: LoginInput) =>
      apiFetch<User>("/auth/login", { method: "POST", json: input }),
    onSuccess: (user) => {
      setUser(user);
      qc.setQueryData(meQueryKey, user);
      // Ensure downstream queries pick up the new auth state.
      qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}

export function useLogout() {
  const qc = useQueryClient();
  const clearUser = useAuthStore((s) => s.clearUser);

  return useMutation({
    mutationFn: () => apiFetch<void>("/auth/logout", { method: "POST" }),
    onSuccess: () => {
      clearUser();
      qc.clear();
    },
  });
}
