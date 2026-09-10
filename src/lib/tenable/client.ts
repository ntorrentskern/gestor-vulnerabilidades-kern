/**
 * Cliente Tenable Vulnerability Management (cloud.tenable.com).
 * Flujo oficial: POST export → poll status → download chunks (según van saliendo).
 */

const TENABLE_BASE = "https://cloud.tenable.com";

export type NormalizedAsset = {
  hostname: string;
  ipv4?: string;
  operating_system?: string[];
  tags?: { key: string; value: string }[];
  tenableUuid?: string;
};

export type NormalizedFinding = {
  asset: { hostname: string; ipv4?: string; uuid?: string };
  plugin: {
    id: number;
    name: string;
    cve?: string[];
    risk_factor?: string;
    cvss_base_score?: number;
  };
  severity?: string;
  state?: string;
  first_found?: string;
  last_found?: string;
  last_fixed?: string;
};

type ExportStatus = {
  status: string;
  reason?: string;
  chunks_available?: number[];
  chunks_failed?: number[];
  total_chunks?: number;
  chunks_available_count?: number;
  finished_chunks?: number;
};

function envNumber(name: string, fallback: number) {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function getKeys() {
  const accessKey = process.env.TENABLE_ACCESS_KEY?.trim();
  const secretKey = process.env.TENABLE_SECRET_KEY?.trim();
  if (!accessKey || !secretKey) {
    throw new Error("Faltan TENABLE_ACCESS_KEY o TENABLE_SECRET_KEY");
  }
  return { accessKey, secretKey };
}

function headers() {
  const { accessKey, secretKey } = getKeys();
  return {
    Accept: "application/json",
    "Content-Type": "application/json",
    "User-Agent": "VulnTracker/0.1.0 (Next.js; corporate-vuln-mgmt)",
    "X-ApiKeys": `accessKey=${accessKey};secretKey=${secretKey}`,
  };
}

async function tenableFetch(path: string, init?: RequestInit) {
  const res = await fetch(`${TENABLE_BASE}${path}`, {
    ...init,
    headers: { ...headers(), ...(init?.headers ?? {}) },
    cache: "no-store",
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    const err = new Error(
      `Tenable ${init?.method ?? "GET"} ${path} → ${res.status}: ${body.slice(0, 400)}`
    ) as Error & { status?: number; body?: string };
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return res;
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

type RecentJob = { uuid?: string; status?: string };

async function clearStaleExports(kind: "assets" | "vulns") {
  const listPath =
    kind === "assets" ? "/assets/export/status" : "/vulns/export/status";
  try {
    const res = await tenableFetch(listPath);
    const json = (await res.json()) as
      | RecentJob[]
      | { exports?: RecentJob[] };
    const jobs = Array.isArray(json) ? json : (json.exports ?? []);
    let cancelled = 0;
    for (const job of jobs) {
      const status = (job.status ?? "").toUpperCase();
      if (!job.uuid) continue;
      if (status !== "QUEUED" && status !== "PROCESSING") continue;
      try {
        await tenableFetch(`/${kind}/export/${job.uuid}/cancel`, {
          method: "POST",
        });
        cancelled += 1;
      } catch {
        /* ignore */
      }
    }
    if (cancelled > 0) {
      console.info(`[tenable] cancelados ${cancelled} exports ${kind} pendientes`);
      await sleep(2000);
    }
  } catch (e) {
    console.warn(`[tenable] no se pudo listar/cancelar exports ${kind}:`, e);
  }
}

async function startExport(
  kind: "assets" | "vulns",
  body: Record<string, unknown>
): Promise<string> {
  const path = kind === "assets" ? "/assets/export" : "/vulns/export";
  try {
    const start = await tenableFetch(path, {
      method: "POST",
      body: JSON.stringify(body),
    });
    const json = (await start.json()) as { export_uuid: string };
    return json.export_uuid;
  } catch (e) {
    const err = e as Error & { status?: number; body?: string };
    if (err.status === 409 && err.body) {
      try {
        const parsed = JSON.parse(err.body) as { active_job_id?: string };
        if (parsed.active_job_id) {
          console.info(
            `[tenable] ${kind} reutiliza job activo ${parsed.active_job_id}`
          );
          return parsed.active_job_id;
        }
      } catch {
        /* fallthrough */
      }
    }
    throw e;
  }
}

async function collectExportChunks<T>(
  kind: "assets" | "vulns",
  exportUuid: string
): Promise<T[]> {
  const maxWaitMs = envNumber("TENABLE_EXPORT_TIMEOUT_MS", 20 * 60_000);
  const pollMs = envNumber("TENABLE_EXPORT_POLL_MS", 5_000);
  const started = Date.now();
  const downloaded = new Set<number>();
  const items: T[] = [];
  let lastLogAt = 0;
  let lastStatus = "";

  const statusPath =
    kind === "assets"
      ? `/assets/export/${exportUuid}/status`
      : `/vulns/export/${exportUuid}/status`;

  while (Date.now() - started < maxWaitMs) {
    const res = await tenableFetch(statusPath);
    const json = (await res.json()) as ExportStatus;
    const status = (json.status ?? "").toUpperCase();

    const available = json.chunks_available ?? [];
    for (const chunkId of available) {
      if (downloaded.has(chunkId)) continue;
      const chunkPath =
        kind === "assets"
          ? `/assets/export/${exportUuid}/chunks/${chunkId}`
          : `/vulns/export/${exportUuid}/chunks/${chunkId}`;
      const chunkRes = await tenableFetch(chunkPath);
      const data = (await chunkRes.json()) as T[] | T;
      if (Array.isArray(data)) items.push(...data);
      else if (data) items.push(data);
      downloaded.add(chunkId);
      console.info(
        `[tenable] ${kind} chunk ${chunkId} ok (${downloaded.size}/${json.total_chunks ?? "?"})`
      );
    }

    if (status === "FINISHED") {
      if (json.chunks_failed?.length) {
        console.warn(
          `[tenable] ${kind} finished with failed chunks:`,
          json.chunks_failed,
          json.reason ?? ""
        );
      }
      return items;
    }

    if (status === "ERROR" || status === "CANCELLED" || status === "CANCELED") {
      throw new Error(
        `Export ${kind} → ${status}${json.reason ? `: ${json.reason}` : ""} (${exportUuid})`
      );
    }

    const now = Date.now();
    const shouldLog =
      status !== lastStatus ||
      status === "PROCESSING" ||
      now - lastLogAt >= 30_000;
    if (shouldLog) {
      console.info(
        `[tenable] ${kind} ${status} · chunks ${downloaded.size}/${json.total_chunks ?? "?"} · ${(
          (now - started) /
          1000
        ).toFixed(0)}s`
      );
      lastLogAt = now;
      lastStatus = status;
    }
    await sleep(pollMs);
  }

  throw new Error(
    `Timeout (${Math.round(maxWaitMs / 60000)} min) esperando export de ${kind} (${exportUuid}). ` +
      `Chunks descargados: ${downloaded.size}.`
  );
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v.length > 0);
}

function normalizeAsset(raw: Record<string, unknown>): NormalizedAsset | null {
  const network = (raw.network as Record<string, unknown> | undefined) ?? {};
  const hostnames = [
    ...asStringArray(raw.hostnames),
    ...asStringArray(raw.fqdns),
    ...asStringArray(network.hostnames),
    ...asStringArray(network.fqdns),
  ];
  const ipv4s = [
    ...asStringArray(raw.ipv4s),
    ...asStringArray(network.ipv4s),
  ];
  const os = [
    ...asStringArray(raw.operating_systems),
    ...asStringArray(raw.operating_system as unknown as string[]),
  ]
    .flatMap((entry) => entry.split(/[\n\r,;]+/))
    .map((s) => s.trim())
    .filter(Boolean);

  const hostname =
    hostnames[0] ??
    ipv4s[0] ??
    (typeof raw.id === "string" ? `tenable-${raw.id}` : null);

  if (!hostname) return null;

  const tagsRaw =
    (raw.tags as { key?: string; value?: string }[] | undefined) ?? [];
  const tags = tagsRaw
    .filter((t) => t.key && t.value)
    .map((t) => ({ key: t.key!, value: t.value! }));

  return {
    hostname: hostname.toLowerCase(),
    ipv4: ipv4s[0],
    operating_system: os.length ? os : undefined,
    tags: tags.length ? tags : undefined,
    tenableUuid: typeof raw.id === "string" ? raw.id : undefined,
  };
}

function toIsoDate(value: unknown): string | undefined {
  if (typeof value === "string" && value) return value;
  if (typeof value === "number" && Number.isFinite(value)) {
    // Tenable a veces manda epoch seconds
    const ms = value > 1e12 ? value : value * 1000;
    return new Date(ms).toISOString();
  }
  return undefined;
}

function normalizeFinding(
  raw: Record<string, unknown>
): NormalizedFinding | null {
  const asset = (raw.asset as Record<string, unknown> | undefined) ?? {};
  const plugin = (raw.plugin as Record<string, unknown> | undefined) ?? {};
  const pluginId = Number(plugin.id);
  if (!Number.isFinite(pluginId)) return null;

  const hostname =
    (typeof asset.fqdn === "string" && asset.fqdn) ||
    (typeof asset.hostname === "string" && asset.hostname) ||
    (typeof asset.netbios_name === "string" && asset.netbios_name) ||
    (typeof asset.ipv4 === "string" && asset.ipv4) ||
    (typeof asset.uuid === "string" ? `tenable-${asset.uuid}` : null);

  if (!hostname) return null;

  const cve = asStringArray(plugin.cve);
  const cvss =
    (typeof plugin.cvss3_base_score === "number"
      ? plugin.cvss3_base_score
      : undefined) ??
    (typeof plugin.cvss_base_score === "number"
      ? plugin.cvss_base_score
      : undefined) ??
    (typeof raw.score === "number" ? raw.score : undefined);

  return {
    asset: {
      hostname: hostname.toLowerCase(),
      ipv4: typeof asset.ipv4 === "string" ? asset.ipv4 : undefined,
      uuid: typeof asset.uuid === "string" ? asset.uuid : undefined,
    },
    plugin: {
      id: pluginId,
      name: String(plugin.name ?? `Plugin ${pluginId}`),
      cve: cve.length ? cve : undefined,
      risk_factor:
        typeof plugin.risk_factor === "string"
          ? plugin.risk_factor
          : typeof raw.severity === "string"
            ? raw.severity
            : undefined,
      cvss_base_score: cvss,
    },
    severity: typeof raw.severity === "string" ? raw.severity : undefined,
    state: typeof raw.state === "string" ? raw.state : undefined,
    first_found: toIsoDate(raw.first_found),
    last_found: toIsoDate(raw.last_found),
    last_fixed: toIsoDate(raw.last_fixed),
  };
}

/** Assets export v1 (campos planos hostnames/ipv4s). */
export async function exportAssets(): Promise<NormalizedAsset[]> {
  const lookbackDays = envNumber("TENABLE_ASSET_LOOKBACK_DAYS", 90);
  const body: Record<string, unknown> = {
    chunk_size: envNumber("TENABLE_ASSET_CHUNK_SIZE", 2000),
  };

  if (process.env.TENABLE_ASSET_NO_FILTER !== "true") {
    body.filters = {
      last_assessed: Math.floor(Date.now() / 1000) - lookbackDays * 86400,
    };
  }

  const export_uuid = await startExport("assets", body);
  console.info(`[tenable] assets export started ${export_uuid}`);
  const raw = await collectExportChunks<Record<string, unknown>>(
    "assets",
    export_uuid
  );
  return raw.map(normalizeAsset).filter((a): a is NormalizedAsset => !!a);
}

export async function exportVulnerabilities(opts?: {
  pluginIds?: number[];
  severities?: string[];
  states?: string[];
  numAssets?: number;
}): Promise<NormalizedFinding[]> {
  const severities = (
    opts?.severities ??
    (process.env.TENABLE_SEVERITIES ?? "critical,high").split(",")
  )
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const states = (opts?.states ?? ["OPEN", "REOPENED"]).map((s) =>
    s.toUpperCase()
  );

  const filters: Record<string, unknown> = {
    severity: severities,
    state: states,
  };

  // Si opts.pluginIds está definido (aunque sea []), no leas el env
  const pluginIds =
    opts?.pluginIds !== undefined
      ? opts.pluginIds
      : (process.env.TENABLE_PLUGIN_IDS ?? "")
          .split(",")
          .map((s) => Number(s.trim()))
          .filter((n) => Number.isFinite(n) && n > 0);

  if (pluginIds.length) {
    filters.plugin_id = pluginIds;
  }

  const sinceDays = envNumber("TENABLE_VULN_SINCE_DAYS", 365);
  filters.since = Math.floor(Date.now() / 1000) - sinceDays * 86400;

  const export_uuid = await startExport("vulns", {
    num_assets:
      opts?.numAssets ?? envNumber("TENABLE_VULN_NUM_ASSETS", 2000),
    include_unlicensed: process.env.TENABLE_INCLUDE_UNLICENSED === "true",
    filters,
  });
  console.info(
    `[tenable] vulns export started ${export_uuid} · sev=${severities.join(",")} · state=${states.join(",")} · plugins=${pluginIds.length ? pluginIds.join(",") : "all"}`
  );
  const raw = await collectExportChunks<Record<string, unknown>>(
    "vulns",
    export_uuid
  );
  return raw.map(normalizeFinding).filter((f): f is NormalizedFinding => !!f);
}

async function discoverTopCriticalPluginId(): Promise<number | null> {
  const dateRange = envNumber("TENABLE_TEST_DATE_RANGE", 90);
  const qs = new URLSearchParams({
    date_range: String(dateRange),
    "filter.0.filter": "severity",
    "filter.0.quality": "eq",
    "filter.0.value": "Critical",
  });
  const listRes = await tenableFetch(
    `/workbenches/vulnerabilities?${qs.toString()}`
  );
  const listJson = (await listRes.json()) as {
    vulnerabilities?: {
      plugin_id: number;
      plugin_name: string;
      count: number;
    }[];
  };
  const top = [...(listJson.vulnerabilities ?? [])].sort(
    (a, b) => b.count - a.count
  )[0];
  if (!top) return null;
  console.info(
    `[tenable] plugin para mini-export: ${top.plugin_id} — ${top.plugin_name} (count=${top.count})`
  );
  return top.plugin_id;
}

/** Solo assets vía /assets/export (prueba mínima API real). */
export async function fetchTenableAssetsOnly() {
  await clearStaleExports("assets");
  console.info("[tenable] modo ASSETS-ONLY (export API real)");
  const assetList = await exportAssets();
  console.info(`[tenable] assets exportados: ${assetList.length}`);
  return {
    assets: assetList,
    findings: [] as NormalizedFinding[],
    source: "tenable-assets" as const,
  };
}

/**
 * Prueba real acotada:
 * 1) /assets/export
 * 2) /vulns/export filtrado a 1 plugin_id
 */
export async function fetchTenableMiniExport() {
  await clearStaleExports("vulns");
  await clearStaleExports("assets");

  console.info("[tenable] modo EXPORT-MINI (API real /assets/export + /vulns/export)");

  const assetList = await exportAssets();
  console.info(`[tenable] assets exportados: ${assetList.length}`);

  let pluginIds = (process.env.TENABLE_PLUGIN_IDS ?? "")
    .split(",")
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isFinite(n) && n > 0);

  if (!pluginIds.length) {
    const discovered = await discoverTopCriticalPluginId();
    if (discovered) pluginIds = [discovered];
  }

  if (!pluginIds.length) {
    throw new Error(
      "Sin plugin_id. Pon TENABLE_PLUGIN_IDS=320656 en .env.local"
    );
  }

  const findings = await exportVulnerabilities({
    pluginIds,
    severities: ["critical", "high", "medium", "low"],
    numAssets: envNumber("TENABLE_VULN_NUM_ASSETS", 100),
  });

  const maxFindings = envNumber("TENABLE_TEST_MAX_ASSETS", 50);
  const capped = findings.slice(0, maxFindings);
  console.info(
    `[tenable] findings del export: ${findings.length} (guardando ${capped.length})`
  );

  const byHost = new Map(assetList.map((a) => [a.hostname, a]));
  for (const f of capped) {
    if (!byHost.has(f.asset.hostname)) {
      byHost.set(f.asset.hostname, {
        hostname: f.asset.hostname,
        ipv4: f.asset.ipv4,
      });
    }
  }

  return {
    assets: Array.from(byHost.values()),
    findings: capped,
    source: "tenable-mini" as const,
  };
}

export async function fetchTenableLiveData() {
  const mode = (process.env.TENABLE_SYNC_MODE ?? "export-mini").toLowerCase();

  if (mode === "assets" || mode === "assets-only") {
    return fetchTenableAssetsOnly();
  }
  if (mode === "export-mini" || mode === "mini") {
    return fetchTenableMiniExport();
  }
  if (mode === "phased" || mode === "export-phased") {
    // El sync action orquesta las fases y persiste cada una
    throw new Error("INTERNAL: usar runPhasedExport desde syncTenableData");
  }

  await clearStaleExports("vulns");
  await clearStaleExports("assets");
  const assetList = await exportAssets();
  const findings = await exportVulnerabilities({ pluginIds: [] });
  const byHost = new Map(assetList.map((a) => [a.hostname, a]));
  for (const f of findings) {
    if (!byHost.has(f.asset.hostname)) {
      byHost.set(f.asset.hostname, {
        hostname: f.asset.hostname,
        ipv4: f.asset.ipv4,
      });
    }
  }
  return {
    assets: Array.from(byHost.values()),
    findings,
    source: "tenable" as const,
  };
}

export type PhasedBatch = {
  phase: string;
  assets: NormalizedAsset[];
  findings: NormalizedFinding[];
};

/**
 * Estrategia a escala: assets → critical → high → medium → fixed (secuencial).
 * Cada fase se puede persistir por separado (el caller hace el upsert).
 */
export async function* runPhasedExport(): AsyncGenerator<PhasedBatch> {
  await clearStaleExports("vulns");
  await clearStaleExports("assets");

  const phases = (process.env.TENABLE_PHASE_SEVERITIES ?? "critical,high,medium")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

  const syncFixed = process.env.TENABLE_SYNC_FIXED !== "false";

  console.info(
    `[tenable] modo PHASED · fases: assets → ${phases.join(" → ")}${syncFixed ? " → fixed" : ""}`
  );

  const assetList = await exportAssets();
  console.info(`[tenable] fase assets OK · ${assetList.length}`);
  yield { phase: "assets", assets: assetList, findings: [] };

  const numAssets = envNumber("TENABLE_VULN_NUM_ASSETS", 500);
  const known = new Set(assetList.map((a) => a.hostname));

  for (const severity of phases) {
    console.info(`[tenable] fase vulns:${severity}…`);
    const findings = await exportVulnerabilities({
      pluginIds: [],
      severities: [severity],
      states: ["OPEN", "REOPENED"],
      numAssets,
    });
    console.info(
      `[tenable] fase vulns:${severity} OK · ${findings.length} findings`
    );

    const extraAssets: NormalizedAsset[] = [];
    for (const f of findings) {
      if (!known.has(f.asset.hostname)) {
        known.add(f.asset.hostname);
        extraAssets.push({
          hostname: f.asset.hostname,
          ipv4: f.asset.ipv4,
        });
      }
    }

    yield {
      phase: `vulns:${severity}`,
      assets: extraAssets,
      findings,
    };
  }

  if (syncFixed) {
    console.info("[tenable] fase vulns:FIXED…");
    const fixedFindings = await exportVulnerabilities({
      pluginIds: [],
      severities: phases.length ? phases : ["critical", "high", "medium"],
      states: ["FIXED"],
      numAssets,
    });
    console.info(
      `[tenable] fase vulns:FIXED OK · ${fixedFindings.length} findings`
    );

    const extraAssets: NormalizedAsset[] = [];
    for (const f of fixedFindings) {
      if (!known.has(f.asset.hostname)) {
        known.add(f.asset.hostname);
        extraAssets.push({
          hostname: f.asset.hostname,
          ipv4: f.asset.ipv4,
        });
      }
    }

    yield {
      phase: "vulns:fixed",
      assets: extraAssets,
      findings: fixedFindings,
    };
  }
}
