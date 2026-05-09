import { useEffect, useState } from "react";

/**
 * Returns `Date.now()` and re-renders the caller every `intervalMs` while
 * `enabled` is true. Use it for live "elapsed since started" displays where
 * the displayed value depends on wall-clock time, not on data state.
 *
 * Why this exists: TanStack Query v5 uses structural sharing on returned
 * `data`, so when a refetch returns content-equal results the data reference
 * is preserved and the consuming component does NOT re-render. That meant
 * `formatDuration(started_at, undefined)` — which reads `Date.now()` at
 * render time — would never recompute on a long phase that doesn't update
 * its progress (e.g. cdxgen, or LLM detection while a single claude-p call
 * is mid-flight). This hook decouples the displayed elapsed time from
 * whether the underlying scan record happened to change.
 */
export function useNow(intervalMs: number, enabled: boolean): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [enabled, intervalMs]);
  return now;
}
