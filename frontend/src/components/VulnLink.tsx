// Anchor + URL helper for OSV / CVE / GHSA identifiers. Used by both detail
// pages (and previously duplicated verbatim in each).

import { cn } from "@/lib/utils";

export function vulnUrl(id: string): string {
  if (id.startsWith("CVE-")) return `https://nvd.nist.gov/vuln/detail/${id}`;
  if (id.startsWith("GHSA-")) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${id}`;
}

export function VulnLink({ id, className }: { id: string; className?: string }) {
  return (
    <a
      href={vulnUrl(id)}
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      className={cn("font-mono hover:underline text-blue-600 dark:text-blue-400", className)}
    >
      {id}
    </a>
  );
}
