import React from "react";

export type SOCSeverity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "info"
  | "normal"
  | "unknown";

interface SOCBadgeProps {
  severity?: string | null;
  variant?: string | null;
  children?: React.ReactNode;
  size?: "sm" | "md" | "lg";
  className?: string;
  pulse?: boolean;
}

export const SOCBadge: React.FC<SOCBadgeProps> = ({
  severity,
  variant,
  children,
  size = "md",
  className = "",
  pulse = false,
}) => {
  const rawType = variant || severity || "info";
  let normSev: string = rawType.toLowerCase().trim();
  if (normSev === "primary") normSev = "info";
  if (normSev === "secondary") normSev = "normal";
  if (normSev === "success") normSev = "low";
  if (normSev === "warning") normSev = "medium";
  if (normSev === "danger") normSev = "critical";
  if (normSev === "neutral" || normSev === "default") normSev = "unknown";

  const colorStyles: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/40 shadow-cyber-glow-red",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/40",
    medium: "bg-amber-500/15 text-amber-400 border-amber-500/40 shadow-cyber-glow-amber",
    low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-cyber-glow-emerald",
    info: "bg-cyan-500/15 text-cyan-400 border-cyan-500/40 shadow-cyber-glow-sm",
    normal: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    unknown: "bg-slate-700/20 text-slate-400 border-slate-700/40",
  };

  const badgeStyle = colorStyles[normSev] || colorStyles.unknown;

  const sizeStyles = {
    sm: "text-[9px] px-1.5 py-0.5",
    md: "text-[10px] px-2 py-0.5 font-semibold",
    lg: "text-xs px-2.5 py-1 font-bold",
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border uppercase tracking-wider font-mono ${badgeStyle} ${sizeStyles[size]} ${className}`}
    >
      {pulse && (
        <span
          className={`w-1.5 h-1.5 rounded-full animate-pulse ${
            normSev === "critical"
              ? "bg-red-500"
              : normSev === "high"
              ? "bg-orange-500"
              : normSev === "medium"
              ? "bg-amber-500"
              : normSev === "low"
              ? "bg-emerald-500"
              : "bg-cyan-400"
          }`}
        />
      )}
      {children || severity?.toUpperCase()}
    </span>
  );
};
