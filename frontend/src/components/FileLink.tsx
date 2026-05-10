// File-path link helpers. The repo's `source_url_template` (with `$FILE` /
// `$LINE` placeholders) drives the rendered URL. With no template, the
// component renders a plain `<span>` — same children, no click target.

import { cn } from "@/lib/utils";

/** Last segment of a forward-or-back-slash separated path. Used to keep
 *  Location columns compact while the full path lives in the title attr. */
export function basename(path: string): string {
  const parts = path.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] ?? path;
}

/** Substitute $FILE / $LINE in the template. Returns null when no template
 *  is set. When the issue has no line, drop the entire fragment/query
 *  segment that contained $LINE so we don't leave an orphan `#` or
 *  `?line=`. */
export function buildSourceUrl(
  template: string | null | undefined,
  file: string,
  line?: number | null,
): string | null {
  if (!template) return null;
  let url = template.replace(/\$FILE/g, encodeURI(file));
  if (line != null) {
    url = url.replace(/\$LINE/g, String(line));
  } else {
    url = url.replace(/[#?][^#?]*\$LINE[^#?]*/g, "").replace(/\$LINE/g, "");
  }
  return url;
}

/** Renders a file path; if a sourceUrlTemplate is provided, wraps it in an
 *  anchor that opens the path in the configured source viewer. */
export function FileLink({
  template,
  file,
  line,
  className,
  children,
}: {
  template: string | null | undefined;
  file: string;
  line?: number | null;
  className?: string;
  children: React.ReactNode;
}) {
  const url = buildSourceUrl(template, file, line);
  if (!url) return <span className={className}>{children}</span>;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className={cn("hover:underline hover:text-foreground", className)}
      onClick={(e) => e.stopPropagation()}
    >
      {children}
    </a>
  );
}
