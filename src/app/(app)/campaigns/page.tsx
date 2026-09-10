import { desc, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { campaignItems, remediationCampaigns } from "@/db/schema";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { formatDate } from "@/lib/utils";
import Link from "next/link";
import { Button } from "@/components/ui/button";

export const dynamic = "force-dynamic";

export default async function CampaignsPage() {
  let rows: {
    id: number;
    name: string;
    description: string | null;
    status: string;
    assignedTo: string;
    createdAt: Date;
    itemCount: number;
  }[] = [];

  try {
    rows = await db
      .select({
        id: remediationCampaigns.id,
        name: remediationCampaigns.name,
        description: remediationCampaigns.description,
        status: remediationCampaigns.status,
        assignedTo: remediationCampaigns.assignedTo,
        createdAt: remediationCampaigns.createdAt,
        itemCount: sql<number>`count(${campaignItems.assetVulnId})::int`,
      })
      .from(remediationCampaigns)
      .leftJoin(
        campaignItems,
        eq(campaignItems.campaignId, remediationCampaigns.id)
      )
      .groupBy(
        remediationCampaigns.id,
        remediationCampaigns.name,
        remediationCampaigns.description,
        remediationCampaigns.status,
        remediationCampaigns.assignedTo,
        remediationCampaigns.createdAt
      )
      .orderBy(desc(remediationCampaigns.createdAt));
  } catch {
    rows = [];
  }

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Campañas</h1>
          <p className="mt-1 text-sm text-slate-500">
            Paquetes de remediación enviados a Sistemas.
          </p>
        </div>
        <Link href="/campaigns/new">
          <Button>Nueva campaña</Button>
        </Link>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Listado</CardTitle>
          <CardDescription>
            Cada campaña agrupa varios `asset_vulns` (máquina + vulnerabilidad).
          </CardDescription>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full text-left text-sm">
            <thead className="border-y border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
              <tr>
                <th className="px-5 py-3">Nombre</th>
                <th className="px-5 py-3">Asignado</th>
                <th className="px-5 py-3">Ítems</th>
                <th className="px-5 py-3">Estado</th>
                <th className="px-5 py-3">Creada</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} className="border-b border-slate-100">
                  <td className="px-5 py-3">
                    <div className="font-medium">{c.name}</div>
                    <div className="max-w-md truncate text-xs text-slate-500">
                      {c.description ?? "Sin descripción"}
                    </div>
                  </td>
                  <td className="px-5 py-3">{c.assignedTo}</td>
                  <td className="px-5 py-3 tabular-nums">{c.itemCount}</td>
                  <td className="px-5 py-3">
                    <Badge tone="neutral">{c.status}</Badge>
                  </td>
                  <td className="px-5 py-3 text-xs text-slate-500">
                    {formatDate(c.createdAt)}
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-5 py-10 text-center text-slate-500">
                    No hay campañas. Crea una desde el Campaign Builder.
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
