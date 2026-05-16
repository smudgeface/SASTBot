// Shared post-process sort helpers for SCA + SAST list endpoints.
//
// Both the scope-page (`/api/scopes/:id/sca-issues`, /sast-issues) and the
// scan-page (`/scans/:id/findings`, /sast-findings) routes need:
//   - a severity ordering that respects the human-meaningful sequence
//     (critical → high → medium → low → unknown) rather than alphabetical;
//   - a triage / dismissed status ordering matching the UI's filter
//     button row (pending → confirmed → planned → fixed → suppressed → invalid);
//   - null-safe string + number compare so a clicked column header
//     doesn't briefly show a sea of nulls at the top regardless of dir.
// Each comparator is meant to be combined with a stable id tie-break by
// the caller so paginated boundaries are deterministic across requests.

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, unknown: 4, info: 5,
};

const STATUS_ORDER: Record<string, number> = {
  pending: 0,
  confirmed: 1,
  planned: 2,
  fixed: 3,
  suppressed: 4,
  false_positive: 5,
  error: 6,
};

export function bySeverity(a: string, b: string): number {
  return (SEVERITY_ORDER[a] ?? 9) - (SEVERITY_ORDER[b] ?? 9);
}

export function byStatus(a: string, b: string): number {
  return (STATUS_ORDER[a] ?? 9) - (STATUS_ORDER[b] ?? 9);
}

export function dirSign(dir: "asc" | "desc"): 1 | -1 {
  return dir === "desc" ? -1 : 1;
}

export function cmpStr(a: string | null, b: string | null): number {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  return a.localeCompare(b);
}

export function cmpNum(a: number | null, b: number | null): number {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  return a - b;
}
