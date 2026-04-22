import { create } from "zustand";

import type { User } from "@/api/types";

interface AuthState {
  user: User | null;
  setUser: (user: User | null) => void;
  clearUser: () => void;
}

/**
 * Synchronous mirror of the `/auth/me` query. TanStack Query remains the source
 * of truth — this store only exists so code paths that don't want a hook (or
 * need a snapshot outside React) can read the current user cheaply.
 */
export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  setUser: (user) => set({ user }),
  clearUser: () => set({ user: null }),
}));
