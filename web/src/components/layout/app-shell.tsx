import { Outlet } from "react-router-dom";
import { Topbar } from "@/components/layout/topbar";
import { Sidebar } from "@/components/layout/sidebar";

// App shell: sticky topbar spanning full width, sidebar + scrollable content
// below. Content area owns its own padding for consistency across pages.
export function AppShell() {
  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <Topbar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="scrollbar-thin flex-1 overflow-y-auto">
          <div className="mx-auto max-w-6xl px-6 py-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
