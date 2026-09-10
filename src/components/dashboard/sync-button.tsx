"use client";

import { useTransition } from "react";
import { RefreshCw } from "lucide-react";
import { syncTenableData } from "@/actions/sync-tenable";
import { Button } from "@/components/ui/button";

export function SyncButton() {
  const [pending, startTransition] = useTransition();

  return (
    <Button
      type="button"
      variant="outline"
      disabled={pending}
      onClick={() =>
        startTransition(async () => {
          const result = await syncTenableData();
          if (!result.ok) {
            alert(result.error);
            return;
          }
          alert(
            `Sync (${result.source}): ${result.assetsUpserted} activos, ${result.vulnsUpserted} vulns, ${result.findingsUpserted} hallazgos` +
              ("phases" in result && result.phases
                ? `\nFases: ${result.phases.join(" → ")}`
                : "")
          );
        })
      }
    >
      <RefreshCw className={pending ? "h-4 w-4 animate-spin" : "h-4 w-4"} />
      {pending ? "Sync por fases…" : "Sync Tenable (fases)"}
    </Button>
  );
}
