import { Outlet } from "react-router-dom";
import { Topbar } from "@/components/layout/topbar";
import { Sidebar } from "@/components/layout/sidebar";
import { RunWatcher } from "@/components/run-watcher";

// App shell: sticky topbar spanning full width, sidebar + scrollable content
// below. Content area owns its own padding for consistency across pages.
export function AppShell() {
  return (
    <div className="flex h-screen flex-col overflow-hidden">
      {/* Delivers a finished analysis to its report even if the user navigated
          away from Analyze while it was running. Renders nothing. */}
      <RunWatcher />
      <Topbar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="scrollbar-thin flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1600px] px-8 py-7">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
