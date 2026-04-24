import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiFetch } from "@/api/client";
import type { Repo, RepoUpsertInput } from "@/api/types";

export const reposKey = ["admin", "repos"] as const;
export const repoKey = (id: string) => ["admin", "repos", id] as const;

export function useRepos() {
  return useQuery<Repo[]>({
    queryKey: reposKey,
    queryFn: () => apiFetch<Repo[]>("/admin/repos"),
  });
}

export function useRepo(id: string | undefined) {
  return useQuery<Repo>({
    queryKey: id ? repoKey(id) : ["admin", "repos", "__none__"],
    queryFn: () => apiFetch<Repo>(`/admin/repos/${id}`),
    enabled: !!id,
  });
}

export function useCreateRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: RepoUpsertInput) =>
      apiFetch<Repo>("/admin/repos", { method: "POST", json: input }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: reposKey });
    },
  });
}

export function useUpdateRepo(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: RepoUpsertInput) =>
      apiFetch<Repo>(`/admin/repos/${id}`, { method: "PUT", json: input }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: reposKey });
      qc.invalidateQueries({ queryKey: repoKey(id) });
    },
  });
}

export function useDeleteRepo() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch<void>(`/admin/repos/${id}`, { method: "DELETE" }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: reposKey });
    },
  });
}

/** Delete the on-disk cached clone for a repo. Enabled only when the repo
 *  has `last_cloned_at` set. Clears `last_cloned_at` on the server and
 *  refreshes the list so the UI picks up the new state. */
export function usePurgeRepoCache() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<Repo>(`/admin/repos/${id}/purge-cache`, { method: "POST" }),
    onSuccess: (_repo, id) => {
      qc.invalidateQueries({ queryKey: reposKey });
      qc.invalidateQueries({ queryKey: repoKey(id) });
    },
  });
}

export type GitCheckResult =
  | { ok: true; branches: string[] }
  | { ok: false; error: string };

/** Run git ls-remote against the repo URL + credential to verify access. */
export function useCheckRepoConnection() {
  return useMutation({
    mutationFn: (id: string) =>
      apiFetch<GitCheckResult>(`/admin/repos/${id}/check-connection`, { method: "POST" }),
  });
}
