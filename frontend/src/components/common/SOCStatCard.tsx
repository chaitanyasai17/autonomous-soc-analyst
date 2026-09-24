import React from "react";
import { GlassCard } from "./GlassCard";

interface SOCStatCardProps {
  label: string;
  value: string | number;
  subvalue?: string;
  subtitle?: string;
  icon: React.ReactNode | React.ComponentType<{ className?: string }>;
  variant?: "cyan" | "danger" | "warning" | "success" | "purple" | "blue" | "default" | "emerald" | "amber";
  trend?: {
    direction: "up" | "down" | "neutral";
    value: string;
    isPositive?: boolean;
  };
  sparkline?: React.ReactNode;
  iconBg?: string;
  className?: string;
}

export const SOCStatCard: React.FC<SOCStatCardProps> = ({
  label,
  value,
  subvalue,
  subtitle,
  icon,
  variant = "cyan",
  trend,
  sparkline,
  iconBg,
  className = "",
}) => {
  const variantStyles = {
    cyan: "bg-cyan-500/15 border border-cyan-500/30 text-cyan-400 shadow-cyber-glow-sm",
    danger: "bg-red-500/15 border border-red-500/30 text-red-400 shadow-cyber-glow-red",
    warning: "bg-amber-500/15 border border-amber-500/30 text-amber-400",
    amber: "bg-amber-500/15 border border-amber-500/30 text-amber-400",
    success: "bg-emerald-500/15 border border-emerald-500/30 text-emerald-400",
    emerald: "bg-emerald-500/15 border border-emerald-500/30 text-emerald-400",
    purple: "bg-purple-500/15 border border-purple-500/30 text-purple-400",
    blue: "bg-blue-500/15 border border-blue-500/30 text-blue-400",
    default: "bg-slate-800/60 border border-slate-700/60 text-slate-300",
  };

  const resolvedIconBg = iconBg || variantStyles[variant] || variantStyles.cyan;

  const renderIcon = () => {
    if (typeof icon === "function" || (typeof icon === "object" && icon !== null && "$$typeof" in icon && !React.isValidElement(icon))) {
      const IconComponent = icon as React.ComponentType<{ className?: string }>;
      return <IconComponent className="w-5 h-5" />;
    }
    if (React.isValidElement(icon)) {
      return icon;
    }
    if (typeof icon === "object" && icon !== null) {
      // ForwardRef exotic component from Lucide
      const IconComponent = icon as any;
      return <IconComponent className="w-5 h-5" />;
    }
    return icon as React.ReactNode;
  };

  const displaySubtitle = subtitle || subvalue;

  return (
    <GlassCard className={`flex flex-col justify-between ${className}`}>
      <div className="flex items-center gap-3">
        <div className={`p-2.5 rounded-xl shrink-0 ${resolvedIconBg}`}>
          {renderIcon()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs text-slate-400 font-medium truncate">{label}</div>
          <div className="flex items-baseline gap-2 mt-0.5">
            <span className="text-2xl font-extrabold text-white font-mono">{value}</span>
            {trend && (
              <span
                className={`text-xs font-semibold flex items-center ${
                  trend.isPositive ?? trend.direction === "up"
                    ? "text-emerald-400"
                    : "text-red-400"
                }`}
              >
                {trend.direction === "up" ? "▲" : trend.direction === "down" ? "▼" : "•"}{" "}
                {trend.value}
              </span>
            )}
          </div>
        </div>
      </div>

      {(displaySubtitle || sparkline) && (
        <div className="flex items-end justify-between mt-3 pt-2 border-t border-[rgba(21,34,56,0.6)]">
          <span className="text-[10px] text-slate-400">{displaySubtitle}</span>
          {sparkline && <div className="shrink-0">{sparkline}</div>}
        </div>
      )}
    </GlassCard>
  );
};
