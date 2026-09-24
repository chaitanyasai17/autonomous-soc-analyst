import React from "react";
import { AlertStatus, IncidentStatus, ProcessingStatus, RiskLevel } from "../../types";

export const SeverityBadge: React.FC<{ severity: RiskLevel | string }> = ({ severity }) => {
  const sev = String(severity).toLowerCase();

  const styles: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };

  const style = styles[sev] || "bg-slate-700/20 text-slate-400 border-slate-700";

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${style}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${sev === 'critical' ? 'bg-red-400 animate-pulse' : sev === 'high' ? 'bg-orange-400' : sev === 'medium' ? 'bg-yellow-400' : 'bg-emerald-400'}`} />
      {sev}
    </span>
  );
};

export const StatusBadge: React.FC<{ status: AlertStatus | IncidentStatus | ProcessingStatus | string }> = ({ status }) => {
  const st = String(status).toLowerCase();

  const styles: Record<string, string> = {
    open: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
    investigating: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    in_progress: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    contained: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    resolved: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    closed: "bg-slate-600/20 text-slate-400 border-slate-600/40",
    false_positive: "bg-zinc-500/15 text-zinc-400 border-zinc-600/40",
    completed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    failed: "bg-red-500/15 text-red-400 border-red-500/30",
    processing: "bg-cyan-500/15 text-cyan-400 border-cyan-500/30 animate-pulse",
    pending: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  };

  const style = styles[st] || "bg-slate-700/20 text-slate-300 border-slate-700";

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize border ${style}`}
    >
      {st.replace("_", " ")}
    </span>
  );
};
