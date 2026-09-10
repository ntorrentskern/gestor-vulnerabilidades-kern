"use client";

import { useActionState } from "react";
import { authenticate } from "@/actions/auth";
import { Button } from "@/components/ui/button";
import { Input, Label } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

export function LoginForm() {
  const [state, formAction, pending] = useActionState(authenticate, undefined);

  return (
    <Card className="w-full max-w-md border-slate-200 shadow-md">
      <CardHeader>
        <CardTitle className="text-lg">Acceso VulnTracker</CardTitle>
        <CardDescription>
          Autenticación con usuario y contraseña (Auth.js + Neon).
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form action={formAction} className="space-y-4" suppressHydrationWarning>
          <div suppressHydrationWarning>
            <Label htmlFor="username">Usuario</Label>
            <Input
              id="username"
              name="username"
              autoComplete="username"
              required
              placeholder="tu@correo.com"
              suppressHydrationWarning
            />
          </div>
          <div suppressHydrationWarning>
            <Label htmlFor="password">Contraseña</Label>
            <Input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              required
              placeholder="••••••••"
              suppressHydrationWarning
            />
          </div>
          {state?.error && (
            <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-red-700">
              {state.error}
            </p>
          )}
          <Button type="submit" className="w-full" disabled={pending}>
            {pending ? "Entrando…" : "Iniciar sesión"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
