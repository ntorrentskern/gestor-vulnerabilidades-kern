"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  PackagePlus,
  ListChecks,
  Shield,
  Bug,
  Server,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { logout } from "@/actions/auth";
import { Button } from "@/components/ui/button";

const links = [
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/vulnerabilities", label: "Vulnerabilidades", icon: Bug },
  { href: "/campaigns/new", label: "Campaign Builder", icon: PackagePlus },
  { href: "/campaigns", label: "Campañas", icon: ListChecks },
];

export function AppShell({
  children,
  username,
  role,
}: {
  children: React.ReactNode;
  username?: string;
  role?: string;
}) {
  const pathname = usePathname();

  return (
    <div className="flex min-h-screen w-full bg-slate-100 text-slate-900">
      <aside className="hidden w-60 shrink-0 border-r border-slate-200 bg-slate-950 text-slate-100 lg:flex lg:flex-col">
        <div className="flex items-center gap-2 border-b border-slate-800 px-5 py-5">
          <Shield className="h-5 w-5 text-teal-400" />
          <div>
            <p className="text-sm font-semibold tracking-wide">VulnTracker</p>
            <p className="text-[11px] text-slate-400">Kern Pharma · Tenable</p>
          </div>
        </div>
        <nav className="flex flex-1 flex-col gap-1 p-3">
          {links.map(({ href, label, icon: Icon }) => {
            const active =
              pathname === href ||
              (href !== "/dashboard" && pathname.startsWith(href));
            return (
              <Link
                key={href}
                href={href}
                className={cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-slate-800 text-white"
                    : "text-slate-300 hover:bg-slate-900 hover:text-white"
                )}
              >
                <Icon className="h-4 w-4" />
                {label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-slate-800 p-4">
          <p className="truncate text-sm font-medium" title={username}>
            {username}
          </p>
          <p className="mb-3 text-xs uppercase tracking-wide text-slate-400">
            {role}
          </p>
          <form action={logout}>
            <Button
              type="submit"
              variant="outline"
              size="sm"
              className="w-full border-slate-600 bg-transparent text-slate-200 hover:bg-slate-800 hover:text-white"
            >
              Cerrar sesión
            </Button>
          </form>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b border-slate-200 bg-white/95 px-4 py-3 backdrop-blur md:px-6">
          <div className="flex items-center gap-2 lg:hidden">
            <Server className="h-4 w-4 text-teal-700" />
            <p className="text-sm font-semibold">VulnTracker</p>
          </div>
          <div className="hidden text-sm text-slate-500 lg:block">
            Priorización y remediación corporativa
          </div>
          <nav className="flex flex-wrap gap-1 lg:hidden">
            {links.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className="rounded border border-slate-200 px-2 py-1 text-[11px]"
              >
                {label}
              </Link>
            ))}
          </nav>
        </header>
        <main className="w-full flex-1 px-4 py-5 md:px-6 lg:px-8">
          {children}
        </main>
      </div>
    </div>
  );
}
