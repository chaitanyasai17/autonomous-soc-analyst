import React from "react";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: LucideIcon;
  variant?: "cyan" | "red" | "orange" | "yellow" | "emerald" | "purple";
  badge?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  title,
  value,
  subtitle,
  icon: Icon,
  variant = "cyan",
  badge,
}) => {
  const variantStyles = {
    cyan: "text-cyan-400 border-cyan-500/20 bg-cyan-500/10",
    red: "text-red-400 border-red-500/20 bg-red-500/10",
    orange: "text-orange-400 border-orange-500/20 bg-orange-500/10",
    yellow: "text-yellow-400 border-yellow-500/20 bg-yellow-500/10",
    emerald: "text-emerald-400 border-emerald-500/20 bg-emerald-500/10",
    purple: "text-purple-400 border-purple-500/20 bg-purple-500/10",
  };

  return (
    <div className="bg-slate-900/80 border border-slate-800/80 rounded-xl p-5 hover:border-slate-700/80 transition-all duration-200">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
          {title}
        </span>
        <div className={`p-2.5 rounded-lg border ${variantStyles[variant]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="mt-3 flex items-baseline justify-between">
        <span className="text-3xl font-bold tracking-tight text-white">{value}</span>
        {badge && (
          <span className="text-xs font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
            {badge}
          </span>
        )}
      </div>
      {subtitle && <p className="mt-1 text-xs text-slate-400">{subtitle}</p>}
    </div>
  );
};
