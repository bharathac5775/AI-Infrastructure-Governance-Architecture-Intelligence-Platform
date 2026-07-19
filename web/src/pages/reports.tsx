import { History } from "lucide-react";
import { PageHeader } from "@/components/layout/page-header";
import { EmptyState } from "@/components/ui/states";

// Placeholder — full history table / compare / export lands in Phase 5.
export function ReportsPage() {
  return (
    <div>
      <PageHeader title="Reports" description="Past governance analyses." />
      <EmptyState
        icon={<History />}
        title="Report history coming next"
        description="This screen is built in a later phase."
      />
    </div>
  );
}
