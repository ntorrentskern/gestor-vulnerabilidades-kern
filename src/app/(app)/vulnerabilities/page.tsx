import { getFindings } from "@/lib/analytics";
import { FindingsExplorer } from "@/components/findings/findings-explorer";

export const dynamic = "force-dynamic";

function asSeverity(v?: string) {
  if (v === "critical" || v === "high" || v === "medium" || v === "low") {
    return v;
  }
  return undefined;
}

function asStatus(v?: string) {
  if (v === "open" || v === "in_progress" || v === "patched") return v;
  return undefined;
}

export default async function VulnerabilitiesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const params = await searchParams;

  let findings: Awaited<ReturnType<typeof getFindings>> = [];
  try {
    findings = await getFindings({
      severity: asSeverity(params.severity),
      status: asStatus(params.status),
      cve: params.cve,
      hostname: params.hostname,
      name: params.name,
      environment: params.environment,
      pluginId: params.pluginId ? Number(params.pluginId) : undefined,
      lastSeenFrom: params.lastSeenFrom,
      lastSeenTo: params.lastSeenTo,
      resolvedFrom: params.resolvedFrom,
      resolvedTo: params.resolvedTo,
      limit: 2000,
    });
  } catch {
    findings = [];
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          Vulnerabilidades
        </h1>
        <p className="mt-1 text-sm text-slate-500">
          Inventario de hallazgos con filtros por criticidad, estado, activo,
          CVE, fechas de último visto y resolución.
        </p>
      </div>
      <FindingsExplorer
        findings={findings}
        mode="browse"
        initialFilters={{
          severity: params.severity,
          status: params.status,
          hostname: params.hostname,
          name: params.name,
          cve: params.cve,
        }}
      />
    </div>
  );
}
