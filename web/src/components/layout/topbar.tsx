import { Moon, Sun, Monitor, Circle, LayoutGrid, Check } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { api } from "@/lib/api";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// Sticky top bar: product name, backend health dot, theme toggle. Restrained —
// no logo blob, no gradient. The health dot is the only always-live signal.
export function Topbar() {
  const { theme, setTheme } = useTheme();
  const health = useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: 30_000,
    retry: false,
  });

  const healthy = health.data?.status === "healthy";
  const ThemeIcon = theme === "dark" ? Moon : theme === "light" ? Sun : Monitor;

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-background/80 px-4 backdrop-blur-sm">
      <div className="flex items-center gap-2.5">
        <span className="flex size-6 items-center justify-center rounded-md bg-primary/10 text-primary">
          <LayoutGrid className="size-3.5" />
        </span>
        <span className="text-sm font-semibold tracking-tight">Infrastructure Governance</span>
      </div>

      <div className="flex items-center gap-2">
        <span
          className={cn(
            "flex items-center gap-1.5 rounded-md border px-2 py-1 text-2xs font-medium transition-colors",
            health.isLoading
              ? "border-border text-muted-foreground"
              : healthy
                ? "border-success/25 bg-success/10 text-success"
                : "border-danger/25 bg-danger/10 text-danger"
          )}
        >
          <Circle
            className={cn(
              "size-2 fill-current",
              !health.isLoading && healthy && "animate-pulse"
            )}
          />
          {health.isLoading ? "Connecting" : healthy ? "API online" : "API offline"}
        </span>

        <div className="mx-0.5 h-5 w-px bg-border" />

        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Toggle theme"
              className="text-muted-foreground hover:text-foreground"
            >
              <ThemeIcon className="size-4" />
            </Button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={8}
              className="z-50 min-w-36 origin-top-right animate-scale-in rounded-lg border border-border bg-popover p-1 text-popover-foreground shadow-overlay"
            >
              {(["light", "dark", "system"] as const).map((t) => (
                <DropdownMenu.Item
                  key={t}
                  onSelect={() => setTheme(t)}
                  className={cn(
                    "flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm capitalize outline-none transition-colors focus:bg-accent",
                    theme === t ? "text-primary" : "text-foreground"
                  )}
                >
                  {t === "light" ? (
                    <Sun className="size-4" />
                  ) : t === "dark" ? (
                    <Moon className="size-4" />
                  ) : (
                    <Monitor className="size-4" />
                  )}
                  {t}
                  {theme === t && <Check className="ml-auto size-3.5" />}
                </DropdownMenu.Item>
              ))}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}
