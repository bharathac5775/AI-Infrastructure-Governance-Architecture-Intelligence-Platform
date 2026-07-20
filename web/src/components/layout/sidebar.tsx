import { NavLink } from "react-router-dom";
import { useState } from "react";
import { FileSearch, History, PanelLeftClose, PanelLeft } from "lucide-react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { useAnalysisRunState } from "@/lib/use-analysis";

const NAV = [
  { to: "/", label: "Analyze", icon: FileSearch, end: true },
  { to: "/reports", label: "Reports", icon: History, end: false },
];

// Collapsible left sidebar. Active item is the one place indigo appears here.
// Icons are 16px — not oversized. No nested groups; the app has two sections.
export function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  // Surfaced from any page so a run started on Analyze stays visible after
  // navigating away — the run itself lives in the shared mutation cache.
  const running = useAnalysisRunState()?.isPending ?? false;

  return (
    <aside
      className={cn(
        "flex shrink-0 flex-col border-r border-border bg-surface/50 transition-[width] duration-200 ease-smooth",
        collapsed ? "w-14" : "w-56"
      )}
    >
      <nav className="flex flex-1 flex-col gap-0.5 p-2">
        {!collapsed && (
          <p className="px-2.5 pb-1.5 pt-2 text-2xs font-medium uppercase tracking-wider text-muted-foreground/70">
            Workspace
          </p>
        )}
        {NAV.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              cn(
                "group relative flex items-center gap-3 rounded-md px-2.5 py-2 text-sm font-medium transition-all duration-175 ease-smooth",
                isActive
                  ? "bg-accent text-foreground"
                  : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                collapsed && "justify-center"
              )
            }
            title={collapsed ? label : undefined}
          >
            {({ isActive }) => (
              <>
                {/* Accent rail on the active item — the Linear signature. */}
                <span
                  className={cn(
                    "absolute left-0 top-1/2 h-4 w-0.5 -translate-y-1/2 rounded-r-full bg-primary transition-opacity duration-175",
                    isActive ? "opacity-100" : "opacity-0"
                  )}
                />
                <span className="relative shrink-0">
                  <Icon
                    className={cn(
                      "size-4 transition-colors",
                      isActive ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                    )}
                  />
                  {/* Pulsing dot marks an in-flight run when the label is hidden. */}
                  {to === "/" && running && collapsed && (
                    <span className="absolute -right-1 -top-1 flex size-2">
                      <span className="absolute inline-flex size-full animate-ping rounded-full bg-primary opacity-75" />
                      <span className="relative inline-flex size-2 rounded-full bg-primary" />
                    </span>
                  )}
                </span>
                {!collapsed && <span>{label}</span>}
                {to === "/" && running && !collapsed && (
                  <span className="ml-auto inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-2 py-0.5 text-2xs font-medium text-primary">
                    <span className="size-1.5 animate-pulse rounded-full bg-primary" />
                    Analyzing
                  </span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="p-2">
        <Button
          variant="ghost"
          size="icon"
          onClick={() => setCollapsed((c) => !c)}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="w-full text-muted-foreground hover:text-foreground"
        >
          {collapsed ? <PanelLeft className="size-4" /> : <PanelLeftClose className="size-4" />}
        </Button>
      </div>
    </aside>
  );
}
