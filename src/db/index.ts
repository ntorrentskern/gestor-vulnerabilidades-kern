import { neon } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-http";
import * as schema from "./schema";

type Db = ReturnType<typeof drizzle<typeof schema>>;

const globalForDb = globalThis as unknown as { __vulnDb?: Db };

function createDb(): Db {
  const url = process.env.DATABASE_URL;
  if (!url) {
    throw new Error(
      "DATABASE_URL no está definida. Añádela en .env.local (cadena de Neon)."
    );
  }
  return drizzle(neon(url), { schema });
}

function getDb(): Db {
  if (!globalForDb.__vulnDb) {
    globalForDb.__vulnDb = createDb();
  }
  return globalForDb.__vulnDb;
}

/** Cliente Drizzle (lazy) para no fallar el build sin DATABASE_URL. */
export const db = new Proxy({} as Db, {
  get(_target, prop, receiver) {
    const instance = getDb();
    const value = Reflect.get(instance as object, prop, receiver);
    return typeof value === "function"
      ? (value as (...args: unknown[]) => unknown).bind(instance)
      : value;
  },
});
