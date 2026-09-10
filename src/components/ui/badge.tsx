import { cn } from "@/lib/utils";

export function Badge({
  className,
  tone = "neutral",
  ...props
}: React.HTMLAttributes<HTMLSpanElement> & {
  tone?: "neutral" | "critical" | "high" | "medium" | "low" | "success";
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide",
        tone === "neutral" && "bg-slate-100 text-slate-700",
        tone === "critical" && "bg-red-100 text-red-800",
        tone === "high" && "bg-orange-100 text-orange-800",
        tone === "medium" && "bg-amber-100 text-amber-800",
        tone === "low" && "bg-emerald-100 text-emerald-800",
        tone === "success" && "bg-teal-100 text-teal-800",
        className
      )}
      {...props}
    />
  );
}
