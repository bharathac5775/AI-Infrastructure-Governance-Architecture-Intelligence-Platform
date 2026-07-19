import { Moon, Sun, Monitor, Circle } from "lucide-react";
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
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between border-b border-border bg-background px-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-semibold tracking-tight">Infrastructure Governance</span>
      </div>

      <div className="flex items-center gap-3">
        <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Circle
            className={cn(
              "size-2 fill-current",
              health.isLoading
                ? "text-muted-foreground"
                : healthy
                  ? "text-success"
                  : "text-danger"
            )}
          />
          {health.isLoading ? "Connecting" : healthy ? "API online" : "API offline"}
        </span>

        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <Button variant="ghost" size="icon" aria-label="Toggle theme">
              <ThemeIcon className="size-4" />
            </Button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={6}
              className="z-50 min-w-32 animate-fade-in rounded-md border border-border bg-popover p-1 text-popover-foreground shadow-overlay"
            >
              {(["light", "dark", "system"] as const).map((t) => (
                <DropdownMenu.Item
                  key={t}
                  onSelect={() => setTheme(t)}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm capitalize outline-none focus:bg-accent",
                    theme === t && "text-primary"
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
                </DropdownMenu.Item>
              ))}
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}
