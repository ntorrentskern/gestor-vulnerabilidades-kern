# VulnTracker

Aplicación corporativa para gestionar y agrupar vulnerabilidades detectadas por Tenable.

## Stack

- Next.js (App Router) + Tailwind CSS
- Neon (PostgreSQL) + Drizzle ORM
- Auth.js (NextAuth) con proveedor de Credenciales + bcrypt

## Arranque rápido

1. Copia el entorno:

```bash
cp .env.example .env.local
```

2. Rellena en `.env.local`:

| Variable | Descripción |
|---|---|
| `DATABASE_URL` | Connection string de Neon |
| `AUTH_SECRET` | Secreto JWT (`openssl rand -base64 32`) |
| `AUTH_TRUST_HOST` | `true` en local |
| `TENABLE_ACCESS_KEY` / `TENABLE_SECRET_KEY` | API Tenable (opcional) |
| `USE_MOCK_TENABLE` | `true` para sync con datos demo |

3. Crea tablas y datos de prueba:

```bash
npm run db:push
npm run db:seed
```

4. Arranca:

```bash
npm run dev
```

Login: **admin** / **admin123**

## Rutas

- `/login` — acceso
- `/dashboard` — métricas y priorización
- `/campaigns/new` — Campaign Builder (filtros + checkboxes → paquete)
- `/campaigns` — listado de campañas

## Scripts útiles

- `npm run db:push` — aplica el schema a Neon
- `npm run db:seed` — usuario admin + hallazgos demo
- `npm run db:studio` — Drizzle Studio
