import {
  pgTable,
  serial,
  text,
  varchar,
  integer,
  real,
  timestamp,
  pgEnum,
  unique,
  primaryKey,
} from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";

export const userRoleEnum = pgEnum("user_role", ["admin", "analyst", "viewer"]);

export const severityEnum = pgEnum("severity", [
  "critical",
  "high",
  "medium",
  "low",
]);

export const assetVulnStatusEnum = pgEnum("asset_vuln_status", [
  "open",
  "in_progress",
  "patched",
]);

export const campaignStatusEnum = pgEnum("campaign_status", [
  "draft",
  "active",
  "completed",
  "cancelled",
]);

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: varchar("username", { length: 255 }).notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: userRoleEnum("role").notNull().default("analyst"),
});

export const assets = pgTable("assets", {
  id: serial("id").primaryKey(),
  hostname: varchar("hostname", { length: 255 }).notNull().unique(),
  ipAddress: varchar("ip_address", { length: 45 }),
  os: text("os"),
  environment: varchar("environment", { length: 64 }).default("production"),
});

export const vulnerabilities = pgTable("vulnerabilities", {
  id: serial("id").primaryKey(),
  pluginId: integer("plugin_id").notNull().unique(),
  cve: varchar("cve", { length: 64 }),
  name: text("name").notNull(),
  severity: severityEnum("severity").notNull(),
  cvssScore: real("cvss_score"),
});

export const assetVulns = pgTable(
  "asset_vulns",
  {
    id: serial("id").primaryKey(),
    assetId: integer("asset_id")
      .notNull()
      .references(() => assets.id, { onDelete: "cascade" }),
    vulnId: integer("vuln_id")
      .notNull()
      .references(() => vulnerabilities.id, { onDelete: "cascade" }),
    status: assetVulnStatusEnum("status").notNull().default("open"),
    firstSeen: timestamp("first_seen", { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastSeen: timestamp("last_seen", { withTimezone: true }),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
  },
  (table) => [
    unique("asset_vulns_asset_vuln_uidx").on(table.assetId, table.vulnId),
  ]
);

export const remediationCampaigns = pgTable("remediation_campaigns", {
  id: serial("id").primaryKey(),
  name: varchar("name", { length: 255 }).notNull(),
  description: text("description"),
  status: campaignStatusEnum("status").notNull().default("draft"),
  assignedTo: varchar("assigned_to", { length: 128 }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const campaignItems = pgTable(
  "campaign_items",
  {
    campaignId: integer("campaign_id")
      .notNull()
      .references(() => remediationCampaigns.id, { onDelete: "cascade" }),
    assetVulnId: integer("asset_vuln_id")
      .notNull()
      .references(() => assetVulns.id, { onDelete: "cascade" }),
  },
  (table) => [
    primaryKey({ columns: [table.campaignId, table.assetVulnId] }),
  ]
);

export const usersRelations = relations(users, () => ({}));

export const assetsRelations = relations(assets, ({ many }) => ({
  assetVulns: many(assetVulns),
}));

export const vulnerabilitiesRelations = relations(
  vulnerabilities,
  ({ many }) => ({
    assetVulns: many(assetVulns),
  })
);

export const assetVulnsRelations = relations(assetVulns, ({ one, many }) => ({
  asset: one(assets, {
    fields: [assetVulns.assetId],
    references: [assets.id],
  }),
  vulnerability: one(vulnerabilities, {
    fields: [assetVulns.vulnId],
    references: [vulnerabilities.id],
  }),
  campaignItems: many(campaignItems),
}));

export const remediationCampaignsRelations = relations(
  remediationCampaigns,
  ({ many }) => ({
    items: many(campaignItems),
  })
);

export const campaignItemsRelations = relations(campaignItems, ({ one }) => ({
  campaign: one(remediationCampaigns, {
    fields: [campaignItems.campaignId],
    references: [remediationCampaigns.id],
  }),
  assetVuln: one(assetVulns, {
    fields: [campaignItems.assetVulnId],
    references: [assetVulns.id],
  }),
}));

export type User = typeof users.$inferSelect;
export type Asset = typeof assets.$inferSelect;
export type Vulnerability = typeof vulnerabilities.$inferSelect;
export type AssetVuln = typeof assetVulns.$inferSelect;
export type RemediationCampaign = typeof remediationCampaigns.$inferSelect;
