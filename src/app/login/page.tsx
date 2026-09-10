import { LoginForm } from "@/components/auth/login-form";
import { Shield } from "lucide-react";

export default function LoginPage() {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-4">
      <div
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            "radial-gradient(circle at 20% 20%, #0f766e 0%, transparent 40%), radial-gradient(circle at 80% 0%, #1e293b 0%, transparent 35%), linear-gradient(135deg, #020617 0%, #0f172a 100%)",
        }}
      />
      <div className="relative z-10 flex w-full max-w-md flex-col items-center gap-6">
        <div className="flex items-center gap-2 text-slate-100">
          <Shield className="h-6 w-6 text-teal-400" />
          <span className="text-xl font-semibold tracking-tight">
            VulnTracker
          </span>
        </div>
        <LoginForm />
        <p className="text-center text-xs text-slate-500">
          Acceso restringido · Kern Pharma
        </p>
      </div>
    </div>
  );
}
