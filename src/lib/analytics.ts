import { and, asc, count, desc, eq, gte, lte, sql, type SQL } from "drizzle-orm";
import { db } from "@/db";
import { assetVulns, assets, vulnerabilities } from "@/db/schema";

export async function getDashboardMetrics() {
  const ninetyDaysAgo = new Date(Date.now() - 90 * 86400_000);

  const [
    [assetCount],
    [vulnCount],
    [openFindings],
    [inProgress],
    [criticalOpen],
    [highOpen],
    [mediumOpen],
    [lowOpen],
    [patchedTotal],
    [patched90d],
    severityBreakdown,
  ] = await Promise.all([
    db.select({ value: count() }).from(assets),
    db.select({ value: count() }).from(vulnerabilities),
    db
      .select({ value: count() })
      .from(assetVulns)
      .where(eq(assetVulns.status, "open")),
    db
      .select({ value: count() })
      .from(assetVulns)
      .where(eq(assetVulns.status, "in_progress")),
    db
      .select({ value: count() })
      .from(assetVulns)
      .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
      .where(
        and(
          eq(assetVulns.status, "open"),
          eq(vulnerabilities.severity, "critical")
        )
      ),
    db
      .select({ value: count() })
      .from(assetVulns)
      .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
      .where(
        and(eq(assetVulns.status, "open"), eq(vulnerabilities.severity, "high"))
      ),
    db
      .select({ value: count() })
      .from(assetVulns)
      .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
      .where(
        and(
          eq(assetVulns.status, "open"),
          eq(vulnerabilities.severity, "medium")
        )
      ),
    db
      .select({ value: count() })
      .from(assetVulns)
      .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
      .where(
        and(eq(assetVulns.status, "open"), eq(vulnerabilities.severity, "low"))
      ),
    db
      .select({ value: count() })
      .from(assetVulns)
      .where(eq(assetVulns.status, "patched")),
    db
      .select({ value: count() })
      .from(assetVulns)
      .where(
        and(
          eq(assetVulns.status, "patched"),
          gte(assetVulns.resolvedAt, ninetyDaysAgo)
        )
      ),
    db
      .select({
        severity: vulnerabilities.severity,
        total: count(),
      })
      .from(assetVulns)
      .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
      .where(eq(assetVulns.status, "open"))
      .groupBy(vulnerabilities.severity),
  ]);

  return {
    assets: assetCount?.value ?? 0,
    vulnerabilities: vulnCount?.value ?? 0,
    openFindings: openFindings?.value ?? 0,
    inProgress: inProgress?.value ?? 0,
    criticalOpen: criticalOpen?.value ?? 0,
    highOpen: highOpen?.value ?? 0,
    mediumOpen: mediumOpen?.value ?? 0,
    lowOpen: lowOpen?.value ?? 0,
    patchedTotal: patchedTotal?.value ?? 0,
    patched90d: patched90d?.value ?? 0,
    severityBreakdown,
  };
}

export async function getTopRepeatedVulnerabilities(limit = 10) {
  return db
    .select({
      vulnId: vulnerabilities.id,
      pluginId: vulnerabilities.pluginId,
      name: vulnerabilities.name,
      cve: vulnerabilities.cve,
      severity: vulnerabilities.severity,
      cvssScore: vulnerabilities.cvssScore,
      affectedAssets: count(),
    })
    .from(assetVulns)
    .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
    .where(eq(assetVulns.status, "open"))
    .groupBy(
      vulnerabilities.id,
      vulnerabilities.pluginId,
      vulnerabilities.name,
      vulnerabilities.cve,
      vulnerabilities.severity,
      vulnerabilities.cvssScore
    )
    .orderBy(desc(count()))
    .limit(limit);
}

export async function getAssetsWithMostCritical(limit = 10) {
  return db
    .select({
      assetId: assets.id,
      hostname: assets.hostname,
      ipAddress: assets.ipAddress,
      os: assets.os,
      environment: assets.environment,
      criticalCount: count(),
    })
    .from(assetVulns)
    .innerJoin(assets, eq(assetVulns.assetId, assets.id))
    .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
    .where(
      and(
        eq(assetVulns.status, "open"),
        eq(vulnerabilities.severity, "critical")
      )
    )
    .groupBy(
      assets.id,
      assets.hostname,
      assets.ipAddress,
      assets.os,
      assets.environment
    )
    .orderBy(desc(count()))
    .limit(limit);
}

export type FindingFilters = {
  severity?: "critical" | "high" | "medium" | "low";
  status?: "open" | "in_progress" | "patched";
  cve?: string;
  hostname?: string;
  name?: string;
  environment?: string;
  pluginId?: number;
  lastSeenFrom?: string;
  lastSeenTo?: string;
  firstSeenFrom?: string;
  firstSeenTo?: string;
  resolvedFrom?: string;
  resolvedTo?: string;
  /** Si true, solo open (legacy campaign). Default false = todos los estados filtrables */
  openOnly?: boolean;
  limit?: number;
};

export type FindingRow = {
  id: number;
  status: "open" | "in_progress" | "patched";
  firstSeen: Date;
  lastSeen: Date | null;
  resolvedAt: Date | null;
  hostname: string;
  ipAddress: string | null;
  environment: string | null;
  os: string | null;
  pluginId: number;
  cve: string | null;
  name: string;
  severity: "critical" | "high" | "medium" | "low";
  cvssScore: number | null;
};

function buildFindingConditions(filters: FindingFilters): SQL[] {
  const conditions: SQL[] = [];

  if (filters.openOnly) {
    conditions.push(eq(assetVulns.status, "open"));
  } else if (filters.status) {
    conditions.push(eq(assetVulns.status, filters.status));
  }

  if (filters.severity) {
    conditions.push(eq(vulnerabilities.severity, filters.severity));
  }
  if (filters.cve?.trim()) {
    conditions.push(
      sql`lower(coalesce(${vulnerabilities.cve}, '')) like ${`%${filters.cve.trim().toLowerCase()}%`}`
    );
  }
  if (filters.hostname?.trim()) {
    conditions.push(
      sql`lower(${assets.hostname}) like ${`%${filters.hostname.trim().toLowerCase()}%`}`
    );
  }
  if (filters.name?.trim()) {
    conditions.push(
      sql`lower(${vulnerabilities.name}) like ${`%${filters.name.trim().toLowerCase()}%`}`
    );
  }
  if (filters.environment?.trim()) {
    conditions.push(
      sql`lower(coalesce(${assets.environment}, '')) like ${`%${filters.environment.trim().toLowerCase()}%`}`
    );
  }
  if (filters.pluginId && Number.isFinite(filters.pluginId)) {
    conditions.push(eq(vulnerabilities.pluginId, filters.pluginId));
  }
  if (filters.lastSeenFrom) {
    conditions.push(gte(assetVulns.lastSeen, new Date(filters.lastSeenFrom)));
  }
  if (filters.lastSeenTo) {
    conditions.push(lte(assetVulns.lastSeen, new Date(filters.lastSeenTo)));
  }
  if (filters.firstSeenFrom) {
    conditions.push(gte(assetVulns.firstSeen, new Date(filters.firstSeenFrom)));
  }
  if (filters.firstSeenTo) {
    conditions.push(lte(assetVulns.firstSeen, new Date(filters.firstSeenTo)));
  }
  if (filters.resolvedFrom) {
    conditions.push(gte(assetVulns.resolvedAt, new Date(filters.resolvedFrom)));
  }
  if (filters.resolvedTo) {
    conditions.push(lte(assetVulns.resolvedAt, new Date(filters.resolvedTo)));
  }

  return conditions;
}

export async function getFindings(filters: FindingFilters = {}) {
  const conditions = buildFindingConditions(filters);

  return db
    .select({
      id: assetVulns.id,
      status: assetVulns.status,
      firstSeen: assetVulns.firstSeen,
      lastSeen: assetVulns.lastSeen,
      resolvedAt: assetVulns.resolvedAt,
      hostname: assets.hostname,
      ipAddress: assets.ipAddress,
      environment: assets.environment,
      os: assets.os,
      pluginId: vulnerabilities.pluginId,
      cve: vulnerabilities.cve,
      name: vulnerabilities.name,
      severity: vulnerabilities.severity,
      cvssScore: vulnerabilities.cvssScore,
    })
    .from(assetVulns)
    .innerJoin(assets, eq(assetVulns.assetId, assets.id))
    .innerJoin(vulnerabilities, eq(assetVulns.vulnId, vulnerabilities.id))
    .where(conditions.length ? and(...conditions) : undefined)
    .orderBy(
      asc(sql`case ${vulnerabilities.severity}
        when 'critical' then 1
        when 'high' then 2
        when 'medium' then 3
        else 4 end`),
      desc(vulnerabilities.cvssScore),
      desc(assetVulns.lastSeen)
    )
    .limit(filters.limit ?? 1000);
}

/** @deprecated usar getFindings({ openOnly: true }) */
export async function getOpenFindings(
  filters: Omit<FindingFilters, "openOnly" | "status"> = {}
) {
  return getFindings({ ...filters, openOnly: true });
}
