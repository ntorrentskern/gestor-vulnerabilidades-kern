import { config } from "dotenv";
config({ path: ".env.local" });
import { hash } from "bcryptjs";
import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import { eq } from "drizzle-orm";
import { users } from "../src/db/schema";

const EMAIL =
  process.env.ADMIN_EMAIL ?? "ntorrents_kern@kernpharma.com";

async function main() {
  const password = process.env.ADMIN_PASSWORD ?? process.argv[2];
  if (!password || password.length < 10) {
    throw new Error(
      "Pasa una password (>=10): npm run db:admin -- \"TuPasswordSegura\""
    );
  }

  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL missing");

  const db = drizzle(neon(url));
  const passwordHash = await hash(password, 12);

  const existing = await db
    .select()
    .from(users)
    .where(eq(users.username, EMAIL))
    .limit(1);

  if (existing.length) {
    await db
      .update(users)
      .set({ passwordHash, role: "admin" })
      .where(eq(users.username, EMAIL));
    console.log("Usuario actualizado:", EMAIL);
  } else {
    await db.insert(users).values({
      username: EMAIL,
      passwordHash,
      role: "admin",
    });
    console.log("Usuario creado:", EMAIL);
  }

  const demo = await db
    .select()
    .from(users)
    .where(eq(users.username, "admin"))
    .limit(1);
  if (demo.length) {
    const disabledHash = await hash(`disabled-${Date.now()}`, 12);
    await db
      .update(users)
      .set({ passwordHash: disabledHash, role: "viewer" })
      .where(eq(users.username, "admin"));
    console.log("Usuario demo 'admin' deshabilitado");
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
