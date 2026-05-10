/**
 * Formatting helpers.
 *
 * `severityChipClass` is a thin wrapper around the canonical SEVERITY_COLORS
 * map in `components/SeverityBadge.tsx` — kept for callsites that style
 * non-Badge elements (filter buttons, finding chips, summary card text).
 * The palette itself lives in one place.
 */

import { severityClass } from "@/components/SeverityBadge";

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export function severityChipClass(severity: string | null | undefined): string {
  return severityClass(severity);
}

const DATE_FORMAT = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
});

export function formatDate(input: string | number | Date | null | undefined): string {
  if (!input) return "—";
  const d = input instanceof Date ? input : new Date(input);
  if (Number.isNaN(d.getTime())) return "—";
  return DATE_FORMAT.format(d);
}

export function formatRelative(input: string | number | Date | null | undefined): string {
  if (!input) return "—";
  const d = input instanceof Date ? input : new Date(input);
  if (Number.isNaN(d.getTime())) return "—";
  const diffMs = Date.now() - d.getTime();
  const s = Math.round(diffMs / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.round(h / 24);
  if (days < 30) return `${days}d ago`;
  return formatDate(d);
}

export function truncate(value: string, max = 12): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}…`;
}
