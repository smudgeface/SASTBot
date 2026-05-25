import { useParams, Link, Navigate } from "react-router-dom";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

import { findManualSection } from "@/manual";
import { MANUAL_ASSETS } from "@/manual/assets";
import { ApiReferencePage } from "./ApiReferencePage";

/**
 * Renders one manual section by slug.
 *  - markdown sections feed through react-markdown with a Tailwind-styled
 *    component map (h1..h6, p, ul, ol, code, pre, table, etc.)
 *  - the api-reference section dispatches to its dedicated React page.
 *
 * Internal links: markdown `[label](other-slug)` (no leading slash) is
 * treated as a manual-internal link and rewritten to /manual/<slug> so the
 * SPA router takes over. External `https://…` links open in a new tab.
 */
export function ManualSection() {
  const { slug } = useParams();
  const section = findManualSection(slug);

  if (!section) {
    return (
      <div className="text-sm text-muted-foreground">
        Section <code>{slug}</code> not found.{" "}
        <Link className="text-primary hover:underline" to="/manual">
          Back to index
        </Link>
        .
      </div>
    );
  }

  // Special case: api-reference is React, not markdown.
  if (section.kind === "api-reference") {
    return <ApiReferencePage />;
  }

  // Redirect /manual (no slug) to the welcome page so the URL is canonical.
  if (!slug) {
    return <Navigate to="/manual/index" replace />;
  }

  return <MarkdownPane body={section.body} />;
}

function MarkdownPane({ body }: { body: string }) {
  // Substitute `:::asset:<name>:::` tokens in the markdown source with the
  // bundled asset URL. Keeps the .md files free of build-tool-specific
  // import paths (they're plain markdown anyone can read on disk).
  const expanded = body.replace(/:::asset:([\w-]+):::/g, (_, name) => {
    const url = MANUAL_ASSETS[name];
    return url ?? `[missing asset: ${name}]`;
  });
  return (
    <article className="text-sm leading-6 text-foreground">
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={mdComponents}>
        {expanded}
      </ReactMarkdown>
    </article>
  );
}

// Tailwind-styled component map. Kept deliberately small and matches the rest
// of the app's design tokens (border, muted-foreground, etc.) — no separate
// CSS file, no typography plugin.
const mdComponents: Components = {
  h1: ({ children }) => (
    <h1 className="mb-4 mt-2 border-b border-border pb-2 text-2xl font-semibold tracking-tight">
      {children}
    </h1>
  ),
  h2: ({ children }) => (
    <h2 className="mb-3 mt-8 text-xl font-semibold tracking-tight">{children}</h2>
  ),
  h3: ({ children }) => (
    <h3 className="mb-2 mt-6 text-base font-semibold tracking-tight">{children}</h3>
  ),
  h4: ({ children }) => <h4 className="mb-2 mt-4 text-sm font-semibold">{children}</h4>,
  p: ({ children }) => <p className="mb-3">{children}</p>,
  ul: ({ children }) => <ul className="mb-3 list-disc space-y-1 pl-6">{children}</ul>,
  ol: ({ children }) => <ol className="mb-3 list-decimal space-y-1 pl-6">{children}</ol>,
  li: ({ children }) => <li className="pl-1">{children}</li>,
  a: ({ href, children }) => {
    // Manual-internal links use bare slugs (no leading slash / protocol).
    const isInternal =
      href !== undefined && !/^[a-z]+:\/\//i.test(href) && !href.startsWith("/") && !href.startsWith("#");
    if (isInternal && href) {
      return (
        <Link to={`/manual/${href}`} className="text-primary hover:underline">
          {children}
        </Link>
      );
    }
    if (href?.startsWith("/")) {
      // In-app route (not the manual). Use Link so it's an SPA nav.
      return (
        <Link to={href} className="text-primary hover:underline">
          {children}
        </Link>
      );
    }
    return (
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="text-primary hover:underline"
      >
        {children}
      </a>
    );
  },
  code: ({ className, children, ...props }) => {
    // Distinguish inline code from fenced blocks. react-markdown wraps fenced
    // code blocks with a <pre><code className="language-...">...</code></pre>;
    // when className is present we're inside a fenced block.
    const isInline = !/^language-/.test(className ?? "");
    if (isInline) {
      return (
        <code
          className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em] text-foreground"
          {...props}
        >
          {children}
        </code>
      );
    }
    return (
      <code className={className} {...props}>
        {children}
      </code>
    );
  },
  pre: ({ children }) => (
    <pre className="mb-3 overflow-x-auto rounded-md border border-border bg-muted/50 p-3 font-mono text-xs leading-5">
      {children}
    </pre>
  ),
  blockquote: ({ children }) => (
    <blockquote className="mb-3 border-l-4 border-primary/40 bg-muted/30 px-3 py-2 text-muted-foreground">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="my-6 border-border" />,
  table: ({ children }) => (
    <div className="mb-3 overflow-x-auto">
      <table className="w-full border-collapse text-left text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => (
    <thead className="border-b border-border text-muted-foreground">{children}</thead>
  ),
  tbody: ({ children }) => <tbody>{children}</tbody>,
  tr: ({ children }) => <tr className="border-b border-border/60">{children}</tr>,
  th: ({ children }) => <th className="px-3 py-2 font-medium">{children}</th>,
  td: ({ children }) => <td className="px-3 py-2 align-top">{children}</td>,
  img: ({ src, alt }) => (
    <img
      src={src}
      alt={alt ?? ""}
      className="mb-3 rounded-md border border-border"
      loading="lazy"
    />
  ),
};
