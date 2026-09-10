import { config } from "dotenv";
config({ path: ".env.local" });
config();
import { hash } from "bcryptjs";
import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import {
  assetVulns,
  assets,
  users,
  vulnerabilities,
} from "../src/db/schema";

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error("DATABASE_URL requerida para el seed");
  }

  const db = drizzle(neon(url));
  const passwordHash = await hash("admin123", 10);

  await db
    .insert(users)
    .values({
      username: "admin",
      passwordHash,
      role: "admin",
    })
    .onConflictDoUpdate({
      target: users.username,
      set: { passwordHash, role: "admin" },
    });

  const assetData = [
    {
      hostname: "srv-web-01.corp.local",
      ipAddress: "10.10.1.11",
      os: "Windows Server 2019",
      environment: "production",
    },
    {
      hostname: "srv-db-01.corp.local",
      ipAddress: "10.10.2.21",
      os: "RHEL 8",
      environment: "production",
    },
    {
      hostname: "lap-finanzas-44",
      ipAddress: "10.20.3.44",
      os: "Windows 11",
      environment: "corporate",
    },
    {
      hostname: "srv-app-staging",
      ipAddress: "10.30.1.5",
      os: "Ubuntu 22.04",
      environment: "staging",
    },
  ];

  for (const row of assetData) {
    await db
      .insert(assets)
      .values(row)
      .onConflictDoUpdate({
        target: assets.hostname,
        set: {
          ipAddress: row.ipAddress,
          os: row.os,
          environment: row.environment,
        },
      });
  }

  const vulnData = [
    {
      pluginId: 19506,
      cve: "CVE-2020-0796",
      name: "Microsoft Windows SMB Shares Unprivileged Access",
      severity: "critical" as const,
      cvssScore: 9.8,
    },
    {
      pluginId: 70658,
      cve: null,
      name: "SSH Weak Algorithms Supported",
      severity: "high" as const,
      cvssScore: 7.5,
    },
    {
      pluginId: 97737,
      cve: "CVE-2023-26369",
      name: "Adobe Acrobat Reader outdated",
      severity: "high" as const,
      cvssScore: 7.8,
    },
    {
      pluginId: 104743,
      cve: "CVE-2023-0286",
      name: "OpenSSL < 3.0.8 Multiple Vulnerabilities",
      severity: "critical" as const,
      cvssScore: 9.1,
    },
    {
      pluginId: 51192,
      cve: "CVE-2017-12345",
      name: "SSL Certificate Cannot Be Trusted",
      severity: "medium" as const,
      cvssScore: 5.3,
    },
  ];

  for (const row of vulnData) {
    await db
      .insert(vulnerabilities)
      .values(row)
      .onConflictDoUpdate({
        target: vulnerabilities.pluginId,
        set: {
          cve: row.cve,
          name: row.name,
          severity: row.severity,
          cvssScore: row.cvssScore,
        },
      });
  }

  const allAssets = await db.select().from(assets);
  const allVulns = await db.select().from(vulnerabilities);
  const byHost = Object.fromEntries(allAssets.map((a) => [a.hostname, a.id]));
  const byPlugin = Object.fromEntries(
    allVulns.map((v) => [v.pluginId, v.id])
  );

  const links: { hostname: string; pluginId: number }[] = [
    { hostname: "srv-web-01.corp.local", pluginId: 19506 },
    { hostname: "srv-web-01.corp.local", pluginId: 51192 },
    { hostname: "srv-db-01.corp.local", pluginId: 19506 },
    { hostname: "srv-db-01.corp.local", pluginId: 70658 },
    { hostname: "lap-finanzas-44", pluginId: 97737 },
    { hostname: "lap-finanzas-44", pluginId: 19506 },
    { hostname: "srv-app-staging", pluginId: 70658 },
    { hostname: "srv-app-staging", pluginId: 104743 },
  ];

  for (const link of links) {
    const assetId = byHost[link.hostname];
    const vulnId = byPlugin[link.pluginId];
    if (!assetId || !vulnId) continue;
    await db
      .insert(assetVulns)
      .values({ assetId, vulnId, status: "open" })
      .onConflictDoNothing({
        target: [assetVulns.assetId, assetVulns.vulnId],
      });
  }

  console.log("Seed OK");
  console.log("  Usuario: admin");
  console.log("  Contraseña: admin123");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
