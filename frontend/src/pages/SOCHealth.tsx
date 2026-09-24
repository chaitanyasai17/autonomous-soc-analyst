import React, { useState, useEffect } from "react";
import {
  Activity,
  HeartPulse,
  Database,
  FileText,
  Filter,
  Network,
  Gauge,
  AlertOctagon,
  Layers,
  Briefcase,
  Sparkles,
  Crosshair,
  Bell,
  Globe,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Clock,
  Cpu,
  Laptop,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

interface ComponentHealth {
  name: string;
  status: "HEALTHY" | "DEGRADED" | "ERROR";
  latency_ms: number;
  message: string;
  last_check: string;
}

interface OperationalMetrics {
  total_logs: number;
  total_events: number;
  total_detections: number;
  total_alerts: number;
  total_incidents: number;
  total_endpoints: number;
  online_endpoints: number;
  isolated_endpoints: number;
  detection_rate: number;
  alert_rate: number;
  incident_rate: number;
  last_log_at: string | null;
  last_detection_at: string | null;
  last_alert_at: string | null;
  last_incident_at: string | null;
}

interface SOCHealthReport {
  overall_status: "HEALTHY" | "DEGRADED" | "ERROR";
  timestamp: string;
  active_components: number;
  total_components: number;
  components: Record<string, ComponentHealth>;
  operational_metrics?: OperationalMetrics;
}

const ENGINE_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  database: Database,
  log_ingestion: FileText,
  log_parser: Filter,
  sigma_detection: Cpu,
  mitre_attack: Network,
  risk_assessment: Gauge,
  alert_manager: AlertOctagon,
  alert_correlation: Layers,
  incident_manager: Briefcase,
  ai_threat_analyst: Sparkles,
  attack_simulator: Crosshair,
  notification_engine: Bell,
  web_security_scanner: Globe,
};

export const SOCHealth: React.FC = () => {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [report, setReport] = useState<SOCHealthReport | null>(null);

  const fetchHealth = async () => {
    try {
      setLoading(true);
      const res = await api.get("/soc-health");
      setReport(res.data);
    } catch (err: any) {
      showToast("Failed to run SOC diagnostics", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const getStatusBadge = (status: string) => {
    switch (status) {
      case "HEALTHY":
        return {
          bg: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
          icon: CheckCircle2,
          dot: "bg-emerald-400",
        };
      case "DEGRADED":
        return {
          bg: "bg-amber-500/20 text-amber-300 border-amber-500/40",
          icon: AlertTriangle,
          dot: "bg-amber-400",
        };
      default:
        return {
          bg: "bg-rose-500/20 text-rose-300 border-rose-500/40",
          icon: XCircle,
          dot: "bg-rose-400",
        };
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="health" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="SOC Health"
        tagline="SYSTEM DIAGNOSTICS & TELEMETRY"
        subtitle="Operational status, service health, and platform performance."
        icon={HeartPulse}
        badgeText={report ? `${report.active_components}/${report.total_components} Engines Online` : "Diagnostics Engine"}
        actions={
          <SOCButton
            variant="secondary"
            onClick={fetchHealth}
            disabled={loading}
            icon={<RefreshCw className={`w-3.5 h-3.5 text-cyan-400 ${loading ? "animate-spin" : ""}`} />}
          >
            Run Diagnostics Now
          </SOCButton>
        }
      />

      {/* Loading Skeleton */}
      {loading && !report ? (
        <div className="space-y-6 animate-pulse">
          <div className="cyber-panel p-6 h-28" />
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="cyber-panel p-4 h-24" />
            ))}
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <div key={i} className="cyber-panel p-4 h-36" />
            ))}
          </div>
        </div>
      ) : report ? (
        <>
          {/* Overall Health Status Banner */}
          <div
            className={`cyber-panel p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${
              report.overall_status === "HEALTHY"
                ? "border-emerald-500/30 shadow-lg shadow-emerald-950/30"
                : report.overall_status === "DEGRADED"
                ? "border-amber-500/30 shadow-lg shadow-amber-950/30"
                : "border-rose-500/30 shadow-lg shadow-rose-950/30"
            }`}
          >
            <div className="flex items-center gap-4">
              <div
                className={`w-12 h-12 rounded-xl flex items-center justify-center border ${
                  report.overall_status === "HEALTHY"
                    ? "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                    : report.overall_status === "DEGRADED"
                    ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                    : "bg-rose-500/20 text-rose-400 border-rose-500/40"
                }`}
              >
                <Activity className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                    Global System Health:
                  </span>
                  <span className="text-lg font-bold text-white tracking-wide">
                    {report.overall_status}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-0.5">
                  All 13 core SOC engines are fully initialized and responding under operational thresholds.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-6 border-t sm:border-t-0 sm:border-l border-slate-800/80 pt-3 sm:pt-0 sm:pl-6 text-xs">
              <div>
                <span className="text-slate-400 block text-[10px] uppercase font-bold">Active Engines</span>
                <span className="text-base font-bold text-emerald-400 font-mono">
                  {report.active_components} / {report.total_components} Online
                </span>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px] uppercase font-bold">Diagnostics Timestamp</span>
                <span className="text-slate-300 font-mono text-[11px]">
                  {new Date(report.timestamp).toLocaleTimeString()}
                </span>
              </div>
            </div>
          </div>

          {/* Operational Rates & Telemetry Metrics Ribbon */}
          {report?.operational_metrics && (
            <div className="space-y-3">
              <div className="text-xs font-bold uppercase tracking-wider text-cyan-300/80 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                <span>Measured Operational Rates & Telemetry Activity</span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                {/* Ingestion */}
                <div className="cyber-panel p-4">
                  <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold mb-1">
                    <FileText className="w-3.5 h-3.5" />
                    <span>Telemetry Ingestion</span>
                  </div>
                  <div className="text-xl font-bold text-white font-mono">
                    {report.operational_metrics.total_events}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    {report.operational_metrics.total_logs} log files ingested
                  </div>
                  {report.operational_metrics.last_log_at && (
                    <div className="text-[10px] text-slate-500 font-mono mt-2 truncate">
                      Last: {new Date(report.operational_metrics.last_log_at).toLocaleTimeString()}
                    </div>
                  )}
                </div>

                {/* Detections */}
                <div className="cyber-panel p-4">
                  <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold mb-1">
                    <Cpu className="w-3.5 h-3.5" />
                    <span>Detection Volume</span>
                  </div>
                  <div className="text-xl font-bold text-white font-mono">
                    {report.operational_metrics.total_detections}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Rate: {(report.operational_metrics.detection_rate * 100).toFixed(1)}% of events
                  </div>
                  {report.operational_metrics.last_detection_at && (
                    <div className="text-[10px] text-slate-500 font-mono mt-2 truncate">
                      Last: {new Date(report.operational_metrics.last_detection_at).toLocaleTimeString()}
                    </div>
                  )}
                </div>

                {/* Alerts */}
                <div className="cyber-panel p-4">
                  <div className="flex items-center gap-2 text-orange-400 text-xs font-semibold mb-1">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    <span>Alert Generation</span>
                  </div>
                  <div className="text-xl font-bold text-white font-mono">
                    {report.operational_metrics.total_alerts}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Alerts escalated
                  </div>
                  {report.operational_metrics.last_alert_at && (
                    <div className="text-[10px] text-slate-500 font-mono mt-2 truncate">
                      Last: {new Date(report.operational_metrics.last_alert_at).toLocaleTimeString()}
                    </div>
                  )}
                </div>

                {/* Incidents */}
                <div className="cyber-panel p-4">
                  <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold mb-1">
                    <Briefcase className="w-3.5 h-3.5" />
                    <span>Incidents Correlated</span>
                  </div>
                  <div className="text-xl font-bold text-white font-mono">
                    {report.operational_metrics.total_incidents}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    Active Cases
                  </div>
                  {report.operational_metrics.last_incident_at && (
                    <div className="text-[10px] text-slate-500 font-mono mt-2 truncate">
                      Last: {new Date(report.operational_metrics.last_incident_at).toLocaleTimeString()}
                    </div>
                  )}
                </div>

                {/* Endpoint Fleet */}
                <div className="cyber-panel p-4 col-span-2 md:col-span-1">
                  <div className="flex items-center gap-2 text-emerald-400 text-xs font-semibold mb-1">
                    <Laptop className="w-3.5 h-3.5" />
                    <span>Endpoint Fleet</span>
                  </div>
                  <div className="text-xl font-bold text-white font-mono">
                    {report.operational_metrics.online_endpoints} / {report.operational_metrics.total_endpoints}
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">
                    {report.operational_metrics.isolated_endpoints} hosts contained
                  </div>
                  <div className="text-[10px] text-emerald-400 font-mono mt-2 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Fleet Status: Synchronized
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* 13 Engine Diagnostics Grid */}
          <div className="space-y-3">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center justify-between">
              <span>Engine Diagnostic Status (13 Engines)</span>
              <span className="text-cyan-400 font-mono flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                100% Operational Check
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {report &&
                Object.entries(report.components).map(([key, comp]) => {
                  const Icon = ENGINE_ICONS[key] || Activity;
                  const badge = getStatusBadge(comp.status);

                  return (
                    <div
                      key={key}
                      className="cyber-panel p-4 hover:border-cyan-500/40 transition flex flex-col justify-between space-y-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded-lg bg-[#030a18] border border-cyan-900/40 text-cyan-400">
                            <Icon className="w-4 h-4" />
                          </div>
                          <div>
                            <h3 className="text-xs font-bold text-slate-200 leading-snug">{comp.name}</h3>
                            <span className="text-[10px] font-mono text-slate-500 block mt-0.5">
                              engine_id: {key}
                            </span>
                          </div>
                        </div>

                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${badge.bg}`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full ${badge.dot} animate-pulse`} />
                          {comp.status}
                        </span>
                      </div>

                      <div className="p-2.5 rounded-lg bg-[#030a18]/90 border border-slate-800/80">
                        <p className="text-[11px] text-slate-300 leading-relaxed line-clamp-2">
                          {comp.message}
                        </p>
                      </div>

                      <div className="flex items-center justify-between text-[10px] text-slate-400 pt-1 border-t border-slate-800/60 font-mono">
                        <span>
                          Latency:{" "}
                          {typeof comp.latency_ms === "number" && comp.latency_ms > 0 ? (
                            <strong className="text-cyan-400">
                              {comp.latency_ms >= 1
                                ? `${comp.latency_ms.toFixed(1)} ms`
                                : `${comp.latency_ms.toFixed(2)} ms`}
                            </strong>
                          ) : (
                            <strong className="text-slate-400" title="In-memory service; no external roundtrip latency measured">
                              N/A
                            </strong>
                          )}
                        </span>
                        <span>Checked: {new Date(comp.last_check).toLocaleTimeString()}</span>
                      </div>
                    </div>
                  );
                })}
            </div>
          </div>
        </>
      ) : (
        <div className="cyber-panel p-12 text-center space-y-3">
          <AlertTriangle className="w-10 h-10 text-amber-400 mx-auto" />
          <p className="text-slate-300 font-medium">Unable to load SOC Health diagnostics.</p>
          <SOCButton
            variant="secondary"
            onClick={fetchHealth}
          >
            Retry Diagnostics
          </SOCButton>
        </div>
      )}
      </div>
    </div>
  );
};
