import {
  getAssetsWithMostCritical,
  getDashboardMetrics,
  getTopRepeatedVulnerabilities,
} from "@/lib/analytics";
import { SyncButton } from "@/components/dashboard/sync-button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { severityLabel } from "@/lib/utils";
import { db } from "@/db";
import { remediationCampaigns } from "@/db/schema";
import { desc } from "drizzle-orm";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export const dynamic = "force-dynamic";

export default async function DashboardPage() {
  let metrics = {
    assets: 0,
    vulnerabilities: 0,
    openFindings: 0,
    inProgress: 0,
    criticalOpen: 0,
    highOpen: 0,
    mediumOpen: 0,
    lowOpen: 0,
    patchedTotal: 0,
    patched90d: 0,
    severityBreakdown: [] as { severity: string; total: number }[],
  };
  let topVulns: Awaited<ReturnType<typeof getTopRepeatedVulnerabilities>> = [];
  let criticalAssets: Awaited<ReturnType<typeof getAssetsWithMostCritical>> = [];
  let campaigns: (typeof remediationCampaigns.$inferSelect)[] = [];
  let dbError: string | null = null;

  try {
    [metrics, topVulns, criticalAssets, campaigns] = await Promise.all([
      getDashboardMetrics(),
      getTopRepeatedVulnerabilities(10),
      getAssetsWithMostCritical(10),
      db
        .select()
        .from(remediationCampaigns)
        .orderBy(desc(remediationCampaigns.createdAt))
        .limit(5),
    ]);
  } catch (error) {
    dbError =
      error instanceof Error
        ? error.message
        : "No se pudo conectar a Neon. Revisa DATABASE_URL.";
  }

  const kpis = [
    { label: "Críticas abiertas", value: metrics.criticalOpen, tone: "text-red-700" },
    { label: "Altas abiertas", value: metrics.highOpen, tone: "text-orange-700" },
    { label: "Medias abiertas", value: metrics.mediumOpen, tone: "text-amber-700" },
    { label: "Bajas abiertas", value: metrics.lowOpen, tone: "text-emerald-700" },
    { label: "En remediación", value: metrics.inProgress, tone: "text-slate-900" },
    { label: "Resueltas (90 días)", value: metrics.patched90d, tone: "text-teal-700" },
    { label: "Resueltas (total)", value: metrics.patchedTotal, tone: "text-slate-900" },
    { label: "Activos", value: metrics.assets, tone: "text-slate-900" },
  ];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-slate-900">
            Dashboard
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            Priorización a partir de hallazgos Tenable · {metrics.openFindings}{" "}
            abiertos
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <SyncButton />
          <Link href="/vulnerabilities">
            <Button variant="outline">Ver vulnerabilidades</Button>
          </Link>
          <Link href="/campaigns/new">
            <Button>Crear campaña</Button>
          </Link>
        </div>
      </div>

      {dbError && (
        <div className="rounded-lg border border-amber-300 bg-amber-50 px-4 py-3 text-sm text-amber-900">
          <p className="font-medium">Base de datos no disponible</p>
          <p className="mt-1 text-amber-800">{dbError}</p>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {kpis.map((card) => (
          <Card key={card.label}>
            <CardContent className="pt-5">
              <p className="text-xs font-medium uppercase tracking-wide text-slate-500">
                {card.label}
              </p>
              <p
                className={`mt-2 text-3xl font-semibold tabular-nums ${card.tone}`}
              >
                {card.value}
              </p>
            </CardContent>
          </Card>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Top 10 vulnerabilidades más repetidas</CardTitle>
            <CardDescription>
              Activos con el hallazgo abierto (agrupación por plugin).
            </CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full text-left text-sm">
              <thead className="border-y border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-5 py-3">Severidad</th>
                  <th className="px-5 py-3">Nombre</th>
                  <th className="px-5 py-3">CVE</th>
                  <th className="px-5 py-3 text-right">Activos</th>
                </tr>
              </thead>
              <tbody>
                {topVulns.map((v) => (
                  <tr key={v.vulnId} className="border-b border-slate-100">
                    <td className="px-5 py-3">
                      <Badge
                        tone={
                          v.severity as "critical" | "high" | "medium" | "low"
                        }
                      >
                        {severityLabel(v.severity)}
                      </Badge>
                    </td>
                    <td className="max-w-xs truncate px-5 py-3" title={v.name}>
                      <Link
                        className="hover:underline"
                        href={`/vulnerabilities?name=${encodeURIComponent(v.name.slice(0, 40))}`}
                      >
                        {v.name}
                      </Link>
                    </td>
                    <td className="px-5 py-3 font-mono text-xs">
                      {v.cve ?? "—"}
                    </td>
                    <td className="px-5 py-3 text-right font-semibold tabular-nums">
                      {v.affectedAssets}
                    </td>
                  </tr>
                ))}
                {topVulns.length === 0 && (
                  <tr>
                    <td
                      colSpan={4}
                      className="px-5 py-8 text-center text-slate-500"
                    >
                      Sin datos todavía. Ejecuta Sync Tenable.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Activos con más críticas</CardTitle>
            <CardDescription>Hosts a priorizar.</CardDescription>
          </CardHeader>
          <CardContent className="overflow-x-auto p-0">
            <table className="w-full text-left text-sm">
              <thead className="border-y border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
                <tr>
                  <th className="px-5 py-3">Hostname</th>
                  <th className="px-5 py-3">Entorno</th>
                  <th className="px-5 py-3 text-right">Críticas</th>
                </tr>
              </thead>
              <tbody>
                {criticalAssets.map((a) => (
                  <tr key={a.assetId} className="border-b border-slate-100">
                    <td className="px-5 py-3">
                      <Link
                        className="font-medium hover:underline"
                        href={`/vulnerabilities?hostname=${encodeURIComponent(a.hostname)}&severity=critical`}
                      >
                        {a.hostname}
                      </Link>
                      <div className="text-xs text-slate-500">
                        {a.ipAddress ?? "—"} · {a.os ?? "—"}
                      </div>
                    </td>
                    <td className="px-5 py-3">{a.environment ?? "—"}</td>
                    <td className="px-5 py-3 text-right font-semibold tabular-nums text-red-700">
                      {a.criticalCount}
                    </td>
                  </tr>
                ))}
                {criticalAssets.length === 0 && (
                  <tr>
                    <td
                      colSpan={3}
                      className="px-5 py-8 text-center text-slate-500"
                    >
                      Sin datos todavía.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Campañas recientes</CardTitle>
          <CardDescription>Paquetes de remediación.</CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className="border-y border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
              <tr>
                <th className="px-5 py-3">Nombre</th>
                <th className="px-5 py-3">Asignado</th>
                <th className="px-5 py-3">Estado</th>
              </tr>
            </thead>
            <tbody>
              {campaigns.map((c) => (
                <tr key={c.id} className="border-b border-slate-100">
                  <td className="px-5 py-3 font-medium">{c.name}</td>
                  <td className="px-5 py-3">{c.assignedTo}</td>
                  <td className="px-5 py-3">
                    <Badge tone="neutral">{c.status}</Badge>
                  </td>
                </tr>
              ))}
              {campaigns.length === 0 && (
                <tr>
                  <td
                    colSpan={3}
                    className="px-5 py-8 text-center text-slate-500"
                  >
                    Aún no hay campañas.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
