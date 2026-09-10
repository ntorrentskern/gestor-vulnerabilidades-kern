"use server";

import { inArray } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { db } from "@/db";
import { assetVulns, campaignItems, remediationCampaigns } from "@/db/schema";

const createCampaignSchema = z.object({
  name: z.string().min(3).max(255),
  description: z.string().max(2000).optional(),
  assignedTo: z.string().min(2).max(128),
  assetVulnIds: z.array(z.number().int().positive()).min(1),
});

export async function createRemediationCampaign(input: {
  name: string;
  description?: string;
  assignedTo: string;
  assetVulnIds: number[];
}) {
  const session = await auth();
  if (!session?.user) {
    return { ok: false as const, error: "No autorizado" };
  }

  const parsed = createCampaignSchema.safeParse(input);
  if (!parsed.success) {
    return { ok: false as const, error: "Datos de campaña inválidos" };
  }

  const { name, description, assignedTo, assetVulnIds } = parsed.data;

  const [campaign] = await db
    .insert(remediationCampaigns)
    .values({
      name,
      description: description || null,
      assignedTo,
      status: "active",
    })
    .returning();

  await db.insert(campaignItems).values(
    assetVulnIds.map((assetVulnId) => ({
      campaignId: campaign.id,
      assetVulnId,
    }))
  );

  await db
    .update(assetVulns)
    .set({ status: "in_progress" })
    .where(inArray(assetVulns.id, assetVulnIds));

  revalidatePath("/dashboard");
  revalidatePath("/campaigns");
  revalidatePath("/campaigns/new");

  return { ok: true as const, campaignId: campaign.id };
}

export async function listCampaigns() {
  return db.query.remediationCampaigns.findMany({
    orderBy: (c, { desc }) => [desc(c.createdAt)],
    with: {
      items: true,
    },
  });
}
