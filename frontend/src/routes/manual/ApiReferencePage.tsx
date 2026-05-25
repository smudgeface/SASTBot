import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Search } from "lucide-react";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

/**
 * Protocol reference page. Driven by /api/openapi.json at view time so the
 * docs cannot drift from the running backend. No swagger-ui dependency —
 * custom rendering matches the manual's look-and-feel.
 *
 * UI:
 *  - search box (matches path + summary substring, case-insensitive)
 *  - method-filter pills
 *  - endpoints grouped by tags[0]; each row expandable for parameters,
 *    request body schema, and response codes.
 *
 * Tradeoffs:
 *  - schema rendering is one level deep ($ref names are surfaced as text but
 *    not recursively expanded). Operators wanting nested detail can pop the
 *    raw openapi.json (link on this page) or hit /docs (backend Swagger UI).
 *  - if /api/openapi.json is unreachable (backend down), we show an inline
 *    error with a "retry" affordance.
 */

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
type Method = (typeof METHODS)[number];

interface OpenApiOperation {
  summary?: string;
  description?: string;
  tags?: string[];
  parameters?: OpenApiParameter[];
  requestBody?: OpenApiRequestBody;
  responses?: Record<string, OpenApiResponse>;
}

interface OpenApiParameter {
  name: string;
  in: "path" | "query" | "header" | "cookie";
  required?: boolean;
  description?: string;
  schema?: OpenApiSchema;
}

interface OpenApiRequestBody {
  required?: boolean;
  description?: string;
  content?: Record<string, { schema?: OpenApiSchema }>;
}

interface OpenApiResponse {
  description?: string;
  content?: Record<string, { schema?: OpenApiSchema }>;
}

interface OpenApiSchema {
  type?: string;
  format?: string;
  $ref?: string;
  items?: OpenApiSchema;
  properties?: Record<string, OpenApiSchema>;
  required?: string[];
  enum?: unknown[];
  description?: string;
}

interface OpenApiDoc {
  info?: { title?: string; version?: string };
  paths?: Record<string, Record<string, OpenApiOperation>>;
}

interface FlatEndpoint {
  method: Method;
  path: string;
  op: OpenApiOperation;
  tag: string;
}

async function fetchOpenApi(): Promise<OpenApiDoc> {
  // The OpenAPI schema is served at the root, NOT under /api/ — per the
  // CLAUDE.md routing rule, /healthz, /version, /openapi.json, and /docs
  // stay at the root regardless of the /api/* prefix used for domain routes.
  const res = await fetch("/openapi.json", { credentials: "include" });
  if (!res.ok) throw new Error(`Failed to load openapi.json (HTTP ${res.status})`);
  return (await res.json()) as OpenApiDoc;
}

export function ApiReferencePage() {
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ["manual", "openapi"],
    queryFn: fetchOpenApi,
    staleTime: 5 * 60 * 1000, // Cache for 5 min; manual visitors rarely care about live freshness.
  });

  const [search, setSearch] = useState("");
  const [methodFilter, setMethodFilter] = useState<Method | "ALL">("ALL");

  const allEndpoints = useMemo(() => flatten(data), [data]);
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return allEndpoints.filter((e) => {
      if (methodFilter !== "ALL" && e.method !== methodFilter) return false;
      if (!q) return true;
      const haystack = `${e.path} ${e.op.summary ?? ""} ${e.tag}`.toLowerCase();
      return haystack.includes(q);
    });
  }, [allEndpoints, search, methodFilter]);

  const grouped = useMemo(() => groupByTag(filtered), [filtered]);

  return (
    <article className="text-sm leading-6 text-foreground">
      <h1 className="mb-4 mt-2 border-b border-border pb-2 text-2xl font-semibold tracking-tight">
        API reference
      </h1>
      <p className="mb-3 text-muted-foreground">
        Rendered live from the backend's <code className="rounded bg-muted px-1 py-0.5 text-[0.85em]">/openapi.json</code>{" "}
        — there is no separately-maintained protocol document, so the catalogue
        below is always in sync with the running version.
      </p>
      {data?.info ? (
        <p className="mb-4 text-xs text-muted-foreground">
          {data.info.title ?? "SASTBot"} · API version {data.info.version ?? "(unknown)"}
        </p>
      ) : null}

      {isLoading ? (
        <p className="text-muted-foreground">Loading endpoint catalogue…</p>
      ) : null}

      {isError ? (
        <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm">
          <div className="mb-2">
            Could not load the API reference: {(error as Error)?.message ?? "unknown error"}
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            Retry
          </Button>
        </div>
      ) : null}

      {data ? (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
              <Input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search path, summary, or tag…"
                className="pl-7 text-xs"
              />
            </div>
            <div className="flex flex-wrap gap-1">
              <MethodPill active={methodFilter === "ALL"} onClick={() => setMethodFilter("ALL")} label="all" />
              {METHODS.map((m) => (
                <MethodPill
                  key={m}
                  active={methodFilter === m}
                  onClick={() => setMethodFilter(m)}
                  label={m}
                  variant="method"
                />
              ))}
            </div>
          </div>

          <p className="mb-4 text-xs text-muted-foreground">
            {filtered.length} of {allEndpoints.length} endpoint{allEndpoints.length === 1 ? "" : "s"} shown.
          </p>

          {grouped.length === 0 ? (
            <p className="text-muted-foreground">No endpoints match the current filter.</p>
          ) : (
            <div className="space-y-6">
              {grouped.map(({ tag, endpoints }) => (
                <section key={tag}>
                  <h2 className="mb-2 mt-4 text-base font-semibold tracking-tight">{tag}</h2>
                  <ul className="space-y-1">
                    {endpoints.map((e) => (
                      <EndpointRow key={`${e.method} ${e.path}`} endpoint={e} />
                    ))}
                  </ul>
                </section>
              ))}
            </div>
          )}

          <p className="mt-8 border-t border-border pt-3 text-xs text-muted-foreground">
            For nested schema detail, fetch the raw{" "}
            <a className="text-primary hover:underline" href="/openapi.json">
              openapi.json
            </a>{" "}
            or browse the backend's interactive docs at{" "}
            <a className="text-primary hover:underline" href="/docs">
              /docs
            </a>{" "}
            (Swagger UI).
          </p>
        </>
      ) : null}
    </article>
  );
}

function flatten(doc: OpenApiDoc | undefined): FlatEndpoint[] {
  if (!doc?.paths) return [];
  const out: FlatEndpoint[] = [];
  for (const [path, ops] of Object.entries(doc.paths)) {
    for (const [methodLc, op] of Object.entries(ops)) {
      const method = methodLc.toUpperCase() as Method;
      if (!(METHODS as readonly string[]).includes(method)) continue;
      const tag = (op as OpenApiOperation).tags?.[0] ?? "Misc";
      out.push({ method, path, op: op as OpenApiOperation, tag });
    }
  }
  out.sort((a, b) => {
    if (a.tag !== b.tag) return a.tag.localeCompare(b.tag);
    if (a.path !== b.path) return a.path.localeCompare(b.path);
    return a.method.localeCompare(b.method);
  });
  return out;
}

function groupByTag(eps: FlatEndpoint[]): { tag: string; endpoints: FlatEndpoint[] }[] {
  const map = new Map<string, FlatEndpoint[]>();
  for (const e of eps) {
    if (!map.has(e.tag)) map.set(e.tag, []);
    map.get(e.tag)!.push(e);
  }
  return Array.from(map.entries()).map(([tag, endpoints]) => ({ tag, endpoints }));
}

function EndpointRow({ endpoint }: { endpoint: FlatEndpoint }) {
  const [open, setOpen] = useState(false);
  const { method, path, op } = endpoint;
  return (
    <li className="rounded-md border border-border">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-start gap-2 px-3 py-2 text-left hover:bg-accent/40"
      >
        {open ? (
          <ChevronDown className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-muted-foreground" />
        )}
        <MethodBadge method={method} />
        <code className="font-mono text-xs text-foreground">{path}</code>
        {op.summary ? (
          <span className="ml-2 truncate text-xs text-muted-foreground">— {op.summary}</span>
        ) : null}
      </button>
      {open ? (
        <div className="border-t border-border/60 px-3 py-3 text-xs">
          {op.description ? (
            <p className="mb-3 text-muted-foreground">{op.description}</p>
          ) : null}
          {op.parameters && op.parameters.length > 0 ? (
            <div className="mb-3">
              <div className="mb-1 font-medium">Parameters</div>
              <ul className="space-y-1">
                {op.parameters.map((p) => (
                  <li key={`${p.in}:${p.name}`} className="font-mono text-[11px]">
                    <span className="text-primary">{p.name}</span>{" "}
                    <span className="text-muted-foreground">({p.in})</span>
                    {p.required ? <span className="text-destructive"> *</span> : null}
                    {p.schema?.type ? (
                      <span className="text-muted-foreground"> : {p.schema.type}</span>
                    ) : null}
                    {p.description ? (
                      <span className="ml-1 text-muted-foreground"> — {p.description}</span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {op.requestBody ? (
            <div className="mb-3">
              <div className="mb-1 font-medium">Request body</div>
              <div className="text-muted-foreground">
                {op.requestBody.required ? "required · " : ""}
                {describeContent(op.requestBody.content)}
                {op.requestBody.description ? ` — ${op.requestBody.description}` : null}
              </div>
            </div>
          ) : null}
          {op.responses ? (
            <div>
              <div className="mb-1 font-medium">Responses</div>
              <ul className="space-y-1">
                {Object.entries(op.responses).map(([code, resp]) => (
                  <li key={code} className="flex gap-2">
                    <code className="font-mono text-foreground">{code}</code>
                    <span className="text-muted-foreground">
                      {resp.description ?? "(no description)"}
                      {resp.content ? ` · ${describeContent(resp.content)}` : ""}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

function describeContent(content: OpenApiRequestBody["content"]): string {
  if (!content) return "";
  const types = Object.keys(content);
  if (types.length === 0) return "";
  return types.join(", ");
}

function MethodBadge({ method }: { method: Method }) {
  const color =
    method === "GET"
      ? "bg-emerald-600/20 text-emerald-700 dark:text-emerald-400"
      : method === "POST"
        ? "bg-sky-600/20 text-sky-700 dark:text-sky-400"
        : method === "PUT" || method === "PATCH"
          ? "bg-amber-600/20 text-amber-700 dark:text-amber-400"
          : "bg-rose-600/20 text-rose-700 dark:text-rose-400";
  return (
    <span className={cn("inline-block rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase", color)}>
      {method}
    </span>
  );
}

function MethodPill({
  label,
  active,
  onClick,
  variant,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  variant?: "method";
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "rounded-md border px-2 py-1 text-xs",
        active
          ? "border-primary bg-primary text-primary-foreground"
          : "border-border bg-background text-muted-foreground hover:bg-accent/40",
        variant === "method" && "font-mono uppercase",
      )}
    >
      {label}
    </button>
  );
}
