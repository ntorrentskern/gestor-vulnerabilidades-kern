import { forwardRef } from "react";
import { cn } from "@/lib/utils";

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "secondary" | "outline" | "ghost" | "danger";
  size?: "sm" | "md" | "lg";
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "md", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:pointer-events-none disabled:opacity-50",
          variant === "default" &&
            "bg-slate-900 text-white hover:bg-slate-800",
          variant === "secondary" &&
            "bg-slate-100 text-slate-900 hover:bg-slate-200",
          variant === "outline" &&
            "border border-slate-300 bg-white text-slate-800 hover:bg-slate-50",
          variant === "ghost" && "text-slate-700 hover:bg-slate-100",
          variant === "danger" && "bg-red-700 text-white hover:bg-red-800",
          size === "sm" && "h-8 px-3 text-xs",
          size === "md" && "h-9 px-4 text-sm",
          size === "lg" && "h-11 px-5 text-sm",
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";
