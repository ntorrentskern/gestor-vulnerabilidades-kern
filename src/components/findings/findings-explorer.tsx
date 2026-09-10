"use client";

import { useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { createRemediationCampaign } from "@/actions/campaigns";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input, Label, Select, Textarea } from "@/components/ui/input";
import { formatDate, severityLabel } from "@/lib/utils";
import type { FindingRow } from "@/lib/analytics";

type Mode = "browse" | "campaign";

export function FindingsExplorer({
  findings,
  mode = "browse",
  initialFilters,
}: {
  findings: FindingRow[];
  mode?: Mode;
  initialFilters?: {
    severity?: string;
    status?: string;
    hostname?: string;
    name?: string;
    cve?: string;
  };
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const [severity, setSeverity] = useState(initialFilters?.severity ?? "");
  const [status, setStatus] = useState(
    initialFilters?.status ?? (mode === "campaign" ? "open" : "")
  );
  const [cve, setCve] = useState(initialFilters?.cve ?? "");
  const [hostname, setHostname] = useState(initialFilters?.hostname ?? "");
  const [name, setName] = useState(initialFilters?.name ?? "");
  const [environment, setEnvironment] = useState("");
  const [pluginId, setPluginId] = useState("");
  const [lastSeenFrom, setLastSeenFrom] = useState("");
  const [lastSeenTo, setLastSeenTo] = useState("");
  const [resolvedFrom, setResolvedFrom] = useState("");
  const [resolvedTo, setResolvedTo] = useState("");

  const [campaignName, setCampaignName] = useState("");
  const [description, setDescription] = useState("");
  const [assignedTo, setAssignedTo] = useState("Sistemas");
  const [error, setError] = useState<string | null>(null);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severity && f.severity !== severity) return false;
      if (status && f.status !== status) return false;
      if (cve && !(f.cve ?? "").toLowerCase().includes(cve.toLowerCase())) {
        return false;
      }
      if (
        hostname &&
        !f.hostname.toLowerCase().includes(hostname.toLowerCase())
      ) {
        return false;
      }
      if (name && !f.name.toLowerCase().includes(name.toLowerCase())) {
        return false;
      }
      if (
        environment &&
        !(f.environment ?? "").toLowerCase().includes(environment.toLowerCase())
      ) {
        return false;
      }
      if (pluginId && String(f.pluginId) !== pluginId.trim()) return false;

      const lastSeen = f.lastSeen ? new Date(f.lastSeen) : null;
      if (lastSeenFrom && (!lastSeen || lastSeen < new Date(lastSeenFrom))) {
        return false;
      }
      if (lastSeenTo && (!lastSeen || lastSeen > new Date(lastSeenTo))) {
        return false;
      }
      const resolved = f.resolvedAt ? new Date(f.resolvedAt) : null;
      if (resolvedFrom && (!resolved || resolved < new Date(resolvedFrom))) {
        return false;
      }
      if (resolvedTo && (!resolved || resolved > new Date(resolvedTo))) {
        return false;
      }
      return true;
    });
  }, [
    findings,
    severity,
    status,
    cve,
    hostname,
    name,
    environment,
    pluginId,
    lastSeenFrom,
    lastSeenTo,
    resolvedFrom,
    resolvedTo,
  ]);

  const allFilteredSelected =
    filtered.length > 0 && filtered.every((f) => selected.has(f.id));

  function toggleAll() {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allFilteredSelected) filtered.forEach((f) => next.delete(f.id));
      else filtered.forEach((f) => next.add(f.id));
      return next;
    });
  }

  function toggleOne(id: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function onCreate() {
    setError(null);
    startTransition(async () => {
      const result = await createRemediationCampaign({
        name: campaignName,
        description,
        assignedTo,
        assetVulnIds: Array.from(selected),
      });
      if (!result.ok) {
        setError(result.error);
        return;
      }
      router.push("/campaigns");
      router.refresh();
    });
  }

  function clearFilters() {
    setSeverity("");
    setStatus(mode === "campaign" ? "open" : "");
    setCve("");
    setHostname("");
    setName("");
    setEnvironment("");
    setPluginId("");
    setLastSeenFrom("");
    setLastSeenTo("");
    setResolvedFrom("");
    setResolvedTo("");
  }

  const statusTone = (s: FindingRow["status"]) =>
    s === "patched" ? "success" : s === "in_progress" ? "medium" : "neutral";

  const statusLabel = (s: FindingRow["status"]) =>
    s === "patched" ? "Resuelta" : s === "in_progress" ? "En curso" : "Abierta";

  return (
    <div
      className={
        mode === "campaign"
          ? "grid gap-6 xl:grid-cols-[1fr_320px]"
          : "space-y-4"
      }
    >
      <Card>
        <CardHeader>
          <CardTitle>
            {mode === "campaign" ? "Hallazgos para campaña" : "Vulnerabilidades"}
          </CardTitle>
          <CardDescription>
            {filtered.length} de {findings.length} hallazgos · filtra y agrupa a
            tu criterio
          </CardDescription>
          <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            <div>
              <Label>Criticidad</Label>
              <Select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="">Todas</option>
                <option value="critical">Crítica</option>
                <option value="high">Alta</option>
                <option value="medium">Media</option>
                <option value="low">Baja</option>
              </Select>
            </div>
            <div>
              <Label>Estado</Label>
              <Select value={status} onChange={(e) => setStatus(e.target.value)}>
                <option value="">Todos</option>
                <option value="open">Abierta</option>
                <option value="in_progress">En curso</option>
                <option value="patched">Resuelta</option>
              </Select>
            </div>
            <div>
              <Label>CVE</Label>
              <Input
                placeholder="CVE-2024-…"
                value={cve}
                onChange={(e) => setCve(e.target.value)}
              />
            </div>
            <div>
              <Label>Activo / hostname</Label>
              <Input
                placeholder="srv-…"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
              />
            </div>
            <div>
              <Label>Nombre plugin</Label>
              <Input
                placeholder="Chrome, OpenSSL…"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div>
              <Label>Entorno</Label>
              <Input
                placeholder="production"
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
              />
            </div>
            <div>
              <Label>Plugin ID</Label>
              <Input
                placeholder="320656"
                value={pluginId}
                onChange={(e) => setPluginId(e.target.value)}
              />
            </div>
            <div>
              <Label>Último visto desde</Label>
              <Input
                type="date"
                value={lastSeenFrom}
                onChange={(e) => setLastSeenFrom(e.target.value)}
              />
            </div>
            <div>
              <Label>Último visto hasta</Label>
              <Input
                type="date"
                value={lastSeenTo}
                onChange={(e) => setLastSeenTo(e.target.value)}
              />
            </div>
            <div>
              <Label>Resuelta desde</Label>
              <Input
                type="date"
                value={resolvedFrom}
                onChange={(e) => setResolvedFrom(e.target.value)}
              />
            </div>
            <div>
              <Label>Resuelta hasta</Label>
              <Input
                type="date"
                value={resolvedTo}
                onChange={(e) => setResolvedTo(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <Button type="button" variant="outline" onClick={clearFilters}>
                Limpiar filtros
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="overflow-x-auto p-0">
          <table className="w-full min-w-[1100px] text-left text-sm">
            <thead className="border-y border-slate-200 bg-slate-50 text-xs uppercase text-slate-500">
              <tr>
                {mode === "campaign" && (
                  <th className="px-4 py-3">
                    <input
                      type="checkbox"
                      checked={allFilteredSelected}
                      onChange={toggleAll}
                      aria-label="Seleccionar todas"
                    />
                  </th>
                )}
                <th className="px-4 py-3">Severidad</th>
                <th className="px-4 py-3">Estado</th>
                <th className="px-4 py-3">Activo</th>
                <th className="px-4 py-3">CVE</th>
                <th className="px-4 py-3">Vulnerabilidad</th>
                <th className="px-4 py-3">CVSS</th>
                <th className="px-4 py-3">Último visto</th>
                <th className="px-4 py-3">Resuelta</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr
                  key={f.id}
                  className="border-b border-slate-100 hover:bg-slate-50"
                >
                  {mode === "campaign" && (
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selected.has(f.id)}
                        onChange={() => toggleOne(f.id)}
                        disabled={f.status === "patched"}
                        aria-label={`Seleccionar ${f.name}`}
                      />
                    </td>
                  )}
                  <td className="px-4 py-3">
                    <Badge tone={f.severity}>{severityLabel(f.severity)}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <Badge tone={statusTone(f.status)}>
                      {statusLabel(f.status)}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="font-medium text-slate-900">{f.hostname}</div>
                    <div className="text-xs text-slate-500">
                      {f.ipAddress ?? "—"} · {f.environment ?? "—"}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{f.cve ?? "—"}</td>
                  <td className="max-w-xs px-4 py-3">
                    <div className="truncate" title={f.name}>
                      {f.name}
                    </div>
                    <div className="text-xs text-slate-500">
                      Plugin {f.pluginId}
                    </div>
                  </td>
                  <td className="px-4 py-3">{f.cvssScore ?? "—"}</td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {formatDate(f.lastSeen ?? f.firstSeen)}
                  </td>
                  <td className="px-4 py-3 text-xs text-slate-500">
                    {f.resolvedAt ? formatDate(f.resolvedAt) : "—"}
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td
                    colSpan={mode === "campaign" ? 9 : 8}
                    className="px-4 py-10 text-center text-sm text-slate-500"
                  >
                    Sin resultados con estos filtros.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </CardContent>
      </Card>

      {mode === "campaign" && (
        <Card className="h-fit xl:sticky xl:top-20">
          <CardHeader>
            <CardTitle>Nuevo paquete</CardTitle>
            <CardDescription>
              {selected.size} hallazgo(s) seleccionado(s)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Label htmlFor="name">Nombre</Label>
              <Input
                id="name"
                placeholder="Patch Chrome marzo"
                value={campaignName}
                onChange={(e) => setCampaignName(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="assigned">Asignado a</Label>
              <Input
                id="assigned"
                value={assignedTo}
                onChange={(e) => setAssignedTo(e.target.value)}
              />
            </div>
            <div>
              <Label htmlFor="desc">Descripción</Label>
              <Textarea
                id="desc"
                placeholder="Alcance, ventana de cambio…"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            {error && (
              <p className="rounded-md bg-red-50 px-3 py-2 text-xs text-red-700">
                {error}
              </p>
            )}
            <Button
              className="w-full"
              disabled={
                pending || selected.size === 0 || campaignName.trim().length < 3
              }
              onClick={onCreate}
            >
              {pending ? "Creando…" : "Crear campaña"}
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
