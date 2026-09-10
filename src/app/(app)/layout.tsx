import { auth } from "@/lib/auth";
import { AppShell } from "@/components/layout/app-shell";

export default async function ProtectedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await auth();

  return (
    <AppShell
      username={session?.user?.username ?? session?.user?.name ?? undefined}
      role={session?.user?.role}
    >
      {children}
    </AppShell>
  );
}
