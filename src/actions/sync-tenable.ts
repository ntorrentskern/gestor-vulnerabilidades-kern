"use server";

import { eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { assetVulns, assets, vulnerabilities } from "@/db/schema";
import {
  fetchTenableLiveData,
  runPhasedExport,
  type NormalizedAsset,
  type NormalizedFinding,
} from "@/lib/tenable/client";

function mapSeverity(
  risk?: string
): "critical" | "high" | "medium" | "low" {
  const value = (risk ?? "medium").toLowerCase();
  if (value === "critical") return "critical";
  if (value === "high") return "high";
  if (value === "low" || value === "info" || value === "informational") {
    return "low";
  }
  return "medium";
}

function formatOs(values?: string[]) {
  if (!values?.length) return null;
  const unique = Array.from(
    new Set(
      values
        .flatMap((v) => v.split(/[\n\r]+/))
        .map((v) => v.trim())
        .filter(Boolean)
    )
  );
  if (!unique.length) return null;
  if (unique.length === 1) return unique[0];
  return `${unique[0]} (+${unique.length - 1})`;
}

function getMockTenableData(): {
  assets: NormalizedAsset[];
  findings: NormalizedFinding[];
} {
  return {
    assets: [
      {
        hostname: "srv-web-01.corp.local",
        ipv4: "10.10.1.11",
        operating_system: ["Windows Server 2019"],
        tags: [{ key: "Environment", value: "production" }],
      },
      {
        hostname: "srv-db-01.corp.local",
        ipv4: "10.10.2.21",
        operating_system: ["RHEL 8"],
        tags: [{ key: "Environment", value: "production" }],
      },
    ],
    findings: [
      {
        asset: { hostname: "srv-web-01.corp.local" },
        plugin: {
          id: 19506,
          name: "Microsoft Windows SMB Shares Unprivileged Access",
          cve: ["CVE-2020-0796"],
          risk_factor: "Critical",
          cvss_base_score: 9.8,
        },
      },
    ],
  };
}

async function persistPayload(payload: {
  assets: NormalizedAsset[];
  findings: NormalizedFinding[];
}) {
  let assetsUpserted = 0;
  let vulnsUpserted = 0;
  let findingsUpserted = 0;

  for (const asset of payload.assets) {
    const environment =
      asset.tags?.find((t) => t.key.toLowerCase() === "environment")?.value ??
      "production";
    const os = formatOs(asset.operating_system);

    await db
      .insert(assets)
      .values({
        hostname: asset.hostname,
        ipAddress: asset.ipv4 ?? null,
        os,
        environment,
      })
      .onConflictDoUpdate({
        target: assets.hostname,
        set: {
          ipAddress: asset.ipv4 ?? null,
          os,
          environment,
        },
      });
    assetsUpserted += 1;
  }

  const pluginMap = new Map<
    number,
    {
      pluginId: number;
      name: string;
      cve: string | null;
      severity: "critical" | "high" | "medium" | "low";
      cvssScore: number | null;
    }
  >();

  for (const finding of payload.findings) {
    const plugin = finding.plugin;
    if (!plugin?.id) continue;
    pluginMap.set(plugin.id, {
      pluginId: plugin.id,
      name: plugin.name,
      cve: plugin.cve?.[0] ?? null,
      severity: mapSeverity(finding.severity ?? plugin.risk_factor),
      cvssScore: plugin.cvss_base_score ?? null,
    });
  }

  for (const vuln of pluginMap.values()) {
    await db
      .insert(vulnerabilities)
      .values(vuln)
      .onConflictDoUpdate({
        target: vulnerabilities.pluginId,
        set: {
          name: vuln.name,
          cve: vuln.cve,
          severity: vuln.severity,
          cvssScore: vuln.cvssScore,
        },
      });
    vulnsUpserted += 1;
  }

  if (payload.findings.length) {
    const assetRows = await db.select().from(assets);
    const vulnRows = await db.select().from(vulnerabilities);
    const assetByHost = new Map(assetRows.map((a) => [a.hostname, a.id]));
    const vulnByPlugin = new Map(vulnRows.map((v) => [v.pluginId, v.id]));

    for (const finding of payload.findings) {
      const assetId = assetByHost.get(finding.asset.hostname);
      const vulnId = vulnByPlugin.get(finding.plugin.id);
      if (!assetId || !vulnId) continue;

      const tenableState = (finding.state ?? "").toUpperCase();
      const isFixed = tenableState === "FIXED";
      const firstSeen = finding.first_found
        ? new Date(finding.first_found)
        : new Date();
      const lastSeen = finding.last_found
        ? new Date(finding.last_found)
        : isFixed
          ? finding.last_fixed
            ? new Date(finding.last_fixed)
            : null
          : firstSeen;
      const resolvedAt = isFixed
        ? finding.last_fixed
          ? new Date(finding.last_fixed)
          : new Date()
        : null;

      await db
        .insert(assetVulns)
        .values({
          assetId,
          vulnId,
          status: isFixed ? "patched" : "open",
          firstSeen,
          lastSeen,
          resolvedAt,
        })
        .onConflictDoUpdate({
          target: [assetVulns.assetId, assetVulns.vulnId],
          set: isFixed
            ? {
                status: "patched",
                lastSeen: lastSeen ?? new Date(),
                resolvedAt: resolvedAt ?? new Date(),
              }
            : {
                // Si vuelve a abrirse (reopened), quitar resolved
                status: "open",
                lastSeen: lastSeen ?? new Date(),
                resolvedAt: null,
              },
        });
      findingsUpserted += 1;
    }
  }

  return { assetsUpserted, vulnsUpserted, findingsUpserted };
}

export async function syncTenableData() {
  const session = await auth();
  if (!session?.user) {
    return { ok: false as const, error: "No autorizado" };
  }

  const mode = (process.env.TENABLE_SYNC_MODE ?? "export-mini").toLowerCase();

  try {
    if (mode === "phased" || mode === "export-phased") {
      let assetsUpserted = 0;
      let vulnsUpserted = 0;
      let findingsUpserted = 0;
      const phases: string[] = [];

      for await (const batch of runPhasedExport()) {
        const counts = await persistPayload(batch);
        assetsUpserted += counts.assetsUpserted;
        vulnsUpserted += counts.vulnsUpserted;
        findingsUpserted += counts.findingsUpserted;
        phases.push(
          `${batch.phase}(+${counts.findingsUpserted} findings)`
        );
        console.info(
          `[tenable] persistido ${batch.phase}: assets=${counts.assetsUpserted} vulns=${counts.vulnsUpserted} findings=${counts.findingsUpserted}`
        );
      }

      revalidatePath("/dashboard");
      revalidatePath("/campaigns");
      revalidatePath("/campaigns/new");

      return {
        ok: true as const,
        source: "tenable-phased" as const,
        assetsUpserted,
        vulnsUpserted,
        findingsUpserted,
        phases,
      };
    }

    const accessKey = process.env.TENABLE_ACCESS_KEY?.trim();
    const secretKey = process.env.TENABLE_SECRET_KEY?.trim();
    const useMock =
      process.env.USE_MOCK_TENABLE === "true" || !accessKey || !secretKey;

    const payload = useMock
      ? { ...getMockTenableData(), source: "mock" as const }
      : await fetchTenableLiveData();

    const counts = await persistPayload(payload);

    revalidatePath("/dashboard");
    revalidatePath("/campaigns");
    revalidatePath("/campaigns/new");

    return {
      ok: true as const,
      source: payload.source,
      ...counts,
    };
  } catch (error) {
    console.error("syncTenableData", error);
    return {
      ok: false as const,
      error: error instanceof Error ? error.message : "Error de sincronización",
    };
  }
}

export async function markFindingInProgress(assetVulnId: number) {
  const session = await auth();
  if (!session?.user) return { ok: false as const, error: "No autorizado" };

  await db
    .update(assetVulns)
    .set({ status: "in_progress" })
    .where(eq(assetVulns.id, assetVulnId));

  revalidatePath("/campaigns");
  return { ok: true as const };
}
