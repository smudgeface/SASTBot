import { ReactNode, useEffect } from "react";
import { Link, NavLink, Outlet } from "react-router-dom";
import { ArrowLeftRight, BookOpen, Moon, Sun } from "lucide-react";

import { useMe } from "@/api/queries/auth";
import { useVersion } from "@/api/queries/version";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { useThemeStore } from "@/stores/theme";
import { MANUAL_SECTIONS, type ManualSection } from "@/manual";

/**
 * Stripped-down shell for the user manual. Used for BOTH authenticated and
 * unauthenticated visitors — quick-start needs to be readable before login.
 *
 * Layout: left sidebar with TOC, right pane with the active section content.
 * Theme toggle in the header. A "Back to app" link if the visitor has an
 * active session, otherwise a "Sign in" link.
 */
export function ManualLayout() {
  const { data: user } = useMe();
  const { data: version } = useVersion();
  const { theme, toggleTheme } = useThemeStore();

  // Persisted theme class — same logic as AppShell, applied here for the
  // unauthenticated-path case where AppShell never mounts.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const root = document.documentElement;
    if (theme === "dark") root.classList.add("dark");
    else root.classList.remove("dark");
  }, [theme]);

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-foreground">
      <aside className="flex h-full w-72 flex-col border-r border-border bg-card/50">
        <div className="flex h-14 items-center gap-2 border-b border-border px-4">
          <BookOpen className="h-5 w-5 text-primary" />
          <span className="text-sm font-semibold tracking-tight">SASTBot manual</span>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          <ManualTOC />
        </nav>

        <div className="border-t border-border p-3 text-xs">
          <div className="mb-2 flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="flex-1 justify-start gap-2"
              onClick={toggleTheme}
              type="button"
            >
              {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
              <span>{theme === "dark" ? "Light" : "Dark"}</span>
            </Button>
          </div>
          <Link
            to={user ? "/scopes" : "/login"}
            className="mb-2 flex items-center gap-1.5 rounded-md border border-border bg-background px-2.5 py-1 text-xs hover:bg-accent"
          >
            <ArrowLeftRight className="h-3.5 w-3.5" />
            <span>{user ? "Back to SASTBot" : "Sign in"}</span>
          </Link>
          {version ? (
            <div className="space-y-0.5 text-[10px] leading-tight text-muted-foreground">
              <div>SASTBot v{version.app}</div>
              <div className="truncate">schema {version.schema.slice(0, 14)}</div>
            </div>
          ) : null}
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-3xl px-8 py-10">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

function ManualTOC() {
  const groups = groupSections(MANUAL_SECTIONS);
  return (
    <ul className="flex flex-col gap-2">
      {groups.map(({ group, sections }) => (
        <li key={group || "_ungrouped"}>
          {group ? (
            <div className="mb-1 px-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {group}
            </div>
          ) : null}
          <ul className="flex flex-col gap-0.5">
            {sections.map((s) => (
              <li key={s.slug}>
                <NavLink
                  to={`/manual/${s.slug}`}
                  className={({ isActive }) =>
                    cn(
                      "block rounded-md px-3 py-1.5 text-sm transition-colors",
                      isActive
                        ? "bg-accent text-accent-foreground"
                        : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                    )
                  }
                  // Highlight the "index" slug when the URL is just /manual.
                  end={s.slug === "index"}
                >
                  {s.title}
                </NavLink>
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}

function groupSections(sections: ManualSection[]): { group: string; sections: ManualSection[] }[] {
  const order: string[] = [];
  const map = new Map<string, ManualSection[]>();
  for (const s of sections) {
    if (!map.has(s.group)) {
      order.push(s.group);
      map.set(s.group, []);
    }
    map.get(s.group)!.push(s);
  }
  return order.map((group) => ({ group, sections: map.get(group)! }));
}

/** Plain wrapper for non-Outlet usage (e.g. the NotFound fallback inside the manual). */
export function ManualPaneWrapper({ children }: { children: ReactNode }) {
  return <div className="text-foreground">{children}</div>;
}
