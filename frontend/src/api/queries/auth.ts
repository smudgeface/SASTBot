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

export const setupStatusQueryKey = ["setup-status"] as const;

/** Whether the instance still needs first-run admin setup. Public endpoint. */
export function useSetupStatus() {
  return useQuery<{ needs_setup: boolean }>({
    queryKey: setupStatusQueryKey,
    queryFn: () => apiFetch<{ needs_setup: boolean }>("/auth/setup-status"),
    staleTime: 30_000,
  });
}

export interface SetupInput {
  email: string;
  password: string;
}

/** Create the first admin account; the backend auto-logs-in on success. */
export function useSetup() {
  const qc = useQueryClient();
  const setUser = useAuthStore((s) => s.setUser);

  return useMutation({
    mutationFn: (input: SetupInput) =>
      apiFetch<User>("/auth/setup", { method: "POST", json: input }),
    onSuccess: (user) => {
      setUser(user);
      qc.setQueryData(meQueryKey, user);
      qc.setQueryData(setupStatusQueryKey, { needs_setup: false });
      qc.invalidateQueries({ queryKey: meQueryKey });
    },
  });
}

export interface ChangePasswordInput {
  current_password: string;
  new_password: string;
}

/** Self-service password change. Clears must_change_password on success. */
export function useChangePassword() {
  const qc = useQueryClient();
  const setUser = useAuthStore((s) => s.setUser);

  return useMutation({
    mutationFn: (input: ChangePasswordInput) =>
      apiFetch<User>("/auth/change-password", { method: "POST", json: input }),
    onSuccess: (user) => {
      setUser(user);
      qc.setQueryData(meQueryKey, user);
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
