import { getFindings } from "@/lib/analytics";
import { FindingsExplorer } from "@/components/findings/findings-explorer";

export const dynamic = "force-dynamic";

export default async function CampaignBuilderPage() {
  let findings: Awaited<ReturnType<typeof getFindings>> = [];
  try {
    // Builder: abiertas + en curso (no resueltas)
    const [open, progress] = await Promise.all([
      getFindings({ status: "open", limit: 2000 }),
      getFindings({ status: "in_progress", limit: 500 }),
    ]);
    findings = [...open, ...progress];
  } catch {
    findings = [];
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Campaign Builder
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Filtra hallazgos abiertos/en curso y empaquétalos en una campaña de
          remediación para Sistemas.
        </p>
      </div>
      <FindingsExplorer findings={findings} mode="campaign" />
    </div>
  );
}
