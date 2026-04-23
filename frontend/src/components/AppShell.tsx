import { useEffect } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  FileSearch,
  Home,
  KeyRound,
  Layers,
  LogOut,
  Moon,
  Settings,
  ShieldCheck,
  Sun,
  GitBranch,
} from "lucide-react";

import { useLogout, useMe } from "@/api/queries/auth";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";
import { useThemeStore } from "@/stores/theme";

interface NavItem {
  to: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}

const MAIN_NAV: NavItem[] = [
  { to: "/scopes", label: "Scopes", icon: Layers },
  { to: "/dashboard", label: "Dashboard", icon: Home },
  { to: "/scans", label: "Scans (audit)", icon: FileSearch },
];

const ADMIN_NAV: NavItem[] = [
  { to: "/admin/repos", label: "Repositories", icon: GitBranch },
  { to: "/admin/settings", label: "Settings", icon: Settings },
  { to: "/admin/credentials", label: "Credentials", icon: KeyRound },
];

export function AppShell() {
  const { data: user } = useMe();
  const navigate = useNavigate();
  const logout = useLogout();
  const { theme, toggleTheme } = useThemeStore();

  // Ensure the persisted theme class is applied on mount.
  useEffect(() => {
    if (typeof document === "undefined") return;
    const root = document.documentElement;
    if (theme === "dark") root.classList.add("dark");
    else root.classList.remove("dark");
  }, [theme]);

  const handleLogout = async () => {
    try {
      await logout.mutateAsync();
    } finally {
      navigate("/login", { replace: true });
    }
  };

  const isAdmin = user?.role === "admin";

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background text-foreground">
      <aside className="flex h-full w-60 flex-col border-r border-border bg-card/50">
        <div className="flex h-14 items-center gap-2 border-b border-border px-4">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <span className="text-sm font-semibold tracking-tight">SASTBot</span>
        </div>

        <nav className="flex-1 overflow-y-auto px-2 py-3">
          <SidebarSection items={MAIN_NAV} />

          {isAdmin ? (
            <>
              <div className="my-3 px-3">
                <Separator />
              </div>
              <div className="mb-1 px-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Admin
              </div>
              <SidebarSection items={ADMIN_NAV} />
            </>
          ) : null}
        </nav>

        <div className="border-t border-border p-3 text-xs">
          <div className="mb-2 truncate text-muted-foreground" title={user?.email}>
            {user?.email ?? "—"}
          </div>
          <div className="flex items-center gap-2">
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
            <Button
              variant="outline"
              size="icon"
              onClick={handleLogout}
              disabled={logout.isPending}
              aria-label="Log out"
              type="button"
            >
              <LogOut className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

function SidebarSection({ items }: { items: NavItem[] }) {
  return (
    <ul className="flex flex-col gap-0.5">
      {items.map((item) => (
        <li key={item.to}>
          <NavLink
            to={item.to}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-2 rounded-md px-3 py-1.5 text-sm transition-colors",
                isActive
                  ? "bg-accent text-accent-foreground"
                  : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
              )
            }
          >
            <item.icon className="h-4 w-4" />
            <span>{item.label}</span>
          </NavLink>
        </li>
      ))}
    </ul>
  );
}
