import React, { useEffect, useState, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  AlertTriangle,
  Activity,
  Layers,
  Maximize2,
  ChevronRight,
  Globe,
  Server,
  Laptop,
  Database,
  User as UserIcon,
  Radio,
  CheckCircle2,
  Clock,
  RotateCw,
  Box,
  Flame,
  Bell,
  Shield,
  Search,
  Cpu,
  Zap,
  Terminal,
  ArrowRight,
  ExternalLink,
  ShieldCheck,
  TrendingUp,
  Workflow,
  Check,
} from "lucide-react";
import { api } from "../services/api";
import { DashboardSummary, Incident, Endpoint, Alert } from "../types";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";

export const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardSummary | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [trendTimeframe, setTrendTimeframe] = useState<"24h" | "7d" | "30d">("24h");
  const [selectedNode, setSelectedNode] = useState<string>("c2");
  const [loading, setLoading] = useState<boolean>(true);
  const [isStreamRefreshing, setIsStreamRefreshing] = useState<boolean>(false);
  const [lastRefreshed, setLastRefreshed] = useState<string>("");
  const streamFetchSeqRef = useRef<number>(0);

  // Live Threat Stream events state with persistent initial cache to eliminate blank/flashing states
  const [streamEvents, setStreamEvents] = useState<Alert[]>(() => {
    try {
      const cached = sessionStorage.getItem("asoc:threat_stream_cache");
      if (cached) {
        const parsed = JSON.parse(cached);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed;
        }
      }
    } catch {
      // ignore
    }
    return [];
  });

  const fetchDashboardData = async () => {
    const seq = ++streamFetchSeqRef.current;
    setIsStreamRefreshing(true);
    try {
      const [summaryRes, incidentsRes, endpointsRes] = await Promise.allSettled([
        api.get("/dashboard/summary"),
        api.get("/incidents?limit=4"),
        api.get("/endpoints?limit=5"),
      ]);

      if (seq !== streamFetchSeqRef.current) return;

      if (summaryRes.status === "fulfilled" && summaryRes.value.data?.data) {
        const freshData: DashboardSummary = summaryRes.value.data.data;
        setData(freshData);

        // Update Threat Stream in the background without clearing previous events
        const incomingAlerts: Alert[] = freshData.recent_alerts || [];
        if (incomingAlerts.length > 0) {
          setStreamEvents((prev) => {
            const seen = new Set<string>();
            const combined: Alert[] = [];
            // Fresh alerts first (newest)
            for (const a of incomingAlerts) {
              if (a.id && !seen.has(a.id)) {
                seen.add(a.id);
                combined.push(a);
              }
            }
            // Previous alerts preserved if not duplicate
            for (const a of prev) {
              if (a.id && !seen.has(a.id)) {
                seen.add(a.id);
                combined.push(a);
              }
            }
            // Preserve newest events strictly at the top
            combined.sort(
              (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
            );
            const topSlice = combined.slice(0, 6);
            try {
              sessionStorage.setItem("asoc:threat_stream_cache", JSON.stringify(topSlice));
            } catch {}
            return topSlice;
          });
        }
      }
      if (incidentsRes.status === "fulfilled" && incidentsRes.value.data?.data) {
        setIncidents(incidentsRes.value.data.data);
      }
      if (endpointsRes.status === "fulfilled" && endpointsRes.value.data?.data) {
        setEndpoints(endpointsRes.value.data.data);
      }
      setLastRefreshed(new Date().toLocaleTimeString());
    } catch (err) {
      console.error("Dashboard data fetch error:", err);
    } finally {
      if (seq === streamFetchSeqRef.current) {
        setLoading(false);
        setIsStreamRefreshing(false);
      }
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 15000);

    return () => {
      clearInterval(interval);
    };
  }, []);

  // Real Metrics from backend
  const totalDetections = data?.total_detections ?? 0;
  const openIncidents = data?.open_incidents ?? incidents.length ?? 0;
  const activeAlerts = data?.active_alerts ?? data?.total_alerts ?? 0;
  const atRiskEndpoints = data?.at_risk_endpoints ?? endpoints.filter((e) => e.risk_level === "critical" || e.risk_level === "high").length;
  const totalEndpoints = data?.total_endpoints ?? endpoints.length;
  const onlineEndpoints = data?.online_endpoints ?? endpoints.filter((e) => e.status === "online").length;
  const rawRiskScore = data?.average_risk_score !== undefined ? data.average_risk_score : 0;
  const riskScore = Number(rawRiskScore.toFixed(1));

  // Severity Distribution Breakdown
  const sevDist = data?.severity_distribution || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalSevAlerts = (sevDist.critical || 0) + (sevDist.high || 0) + (sevDist.medium || 0) + (sevDist.low || 0);
  const critPct = totalSevAlerts > 0 ? Math.round(((sevDist.critical || 0) / totalSevAlerts) * 100) : 0;
  const highPct = totalSevAlerts > 0 ? Math.round(((sevDist.high || 0) / totalSevAlerts) * 100) : 0;
  const medPct = totalSevAlerts > 0 ? Math.round(((sevDist.medium || 0) / totalSevAlerts) * 100) : 0;
  const lowPct = totalSevAlerts > 0 ? Math.max(0, 100 - critPct - highPct - medPct) : 0;

  // Top Alert for Header Notification
  const topAlert = data?.recent_alerts?.[0];

  // MITRE Tactics Coverage
  const tactics = data?.top_tactics || [];
  const coveredTacticsCount = tactics.filter((t) => (t.active_detections_count || 0) > 0 || (t.techniques_count || 0) > 0).length;
  const totalTacticsCount = tactics.length;
  const topActiveTactics = tactics
    .filter((t) => (t.active_detections_count || 0) > 0)
    .sort((a, b) => (b.active_detections_count || 0) - (a.active_detections_count || 0))
    .slice(0, 6);

  // Formatter helpers
  const formatTimeAgo = (dateStr?: string) => {
    if (!dateStr) return "recent";
    const d = new Date(dateStr);
    const now = new Date();
    const diffSec = Math.floor((now.getTime() - d.getTime()) / 1000);
    if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return `${Math.floor(diffSec / 86400)}d ago`;
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev?.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border-red-500/40";
      case "high":
        return "bg-orange-500/20 text-orange-400 border-orange-500/40";
      case "medium":
        return "bg-amber-500/20 text-amber-400 border-amber-500/40";
      case "low":
      default:
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/40";
    }
  };

  const getPriorityBadgeClass = (priority: string) => {
    switch (priority?.toLowerCase()) {
      case "critical":
        return "bg-red-500 text-white";
      case "high":
        return "bg-orange-500 text-white";
      case "medium":
        return "bg-amber-500 text-white";
      case "low":
      default:
        return "bg-blue-500 text-white";
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Universal ASOC Deep Cyber Grid Background */}
      <CyberGridBackground variant="dashboard" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-4 text-slate-200">
        {/* 1. Universal SOC Page Header */}
        <SOCPageHeader
          title="SOC Command Center"
          tagline="DETECT / ANALYZE / RESPOND"
          subtitle="Real-time security monitoring, threat detection, risk, and incident response."
          icon={Shield}
          actions={
            <div className="flex flex-wrap items-center gap-3">
              {topAlert ? (
                <Link
                  to="/alerts"
                  className="flex items-center gap-3 px-3.5 py-1.5 rounded-xl bg-[#140b17]/90 border border-red-500/40 shadow-cyber-glow-red backdrop-blur-md hover:border-red-400 transition group"
                >
                  <div className="p-1 rounded-md bg-red-500/20 text-red-400 group-hover:scale-105 transition">
                    <AlertTriangle className="w-4 h-4 animate-pulse" />
                  </div>
                  <div className="text-xs">
                    <div className="font-bold text-red-400 leading-tight flex items-center gap-1.5">
                      Active Threat: <span className="text-white font-medium truncate max-w-[200px] sm:max-w-xs">{topAlert.title}</span>
                    </div>
                    <div className="text-slate-400 text-[11px] truncate max-w-[240px]">
                      Risk Score: {topAlert.risk_score || 80}/100 • Severity {topAlert.severity.toUpperCase()}
                    </div>
                  </div>
                  <span className="text-[10px] text-slate-500 font-mono ml-2 whitespace-nowrap">
                    {formatTimeAgo(topAlert.created_at)}
                  </span>
                </Link>
              ) : (
                <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl cyber-grid-glass text-xs text-slate-400">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  SOC Pipeline Engine Active
                </div>
              )}

              {lastRefreshed && (
                <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg cyber-grid-glass-subtle text-[11px] text-slate-400 font-mono">
                  <RotateCw className="w-3 h-3 text-cyan-400 animate-spin-slow" />
                  <span>{lastRefreshed}</span>
                </div>
              )}
            </div>
          }
        />

        {/* 2. Top 5 KPI Metrics Cards */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3.5">
          {/* Card 1: Total Detections */}
          <div className="p-4 cyber-grid-glass rounded-xl flex flex-col justify-between hover:border-cyan-400/40 transition">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-blue-500/15 border border-blue-500/30 text-blue-400">
                <Box className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400 font-medium">Total Detections</div>
                <div className="flex items-baseline gap-2 mt-0.5">
                  <span className="text-2xl font-extrabold text-white font-mono">{totalDetections}</span>
                  <span className="text-xs font-semibold text-cyan-400 font-mono flex items-center">
                    Sigma AST
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-end justify-between mt-3 pt-2 border-t border-[#152238]/60">
              <span className="text-[10px] text-slate-500">Sigma rule matches</span>
              <svg className="w-20 h-5" viewBox="0 0 100 25" fill="none">
                <path d="M 0 18 Q 20 8, 40 16 T 80 6 T 100 12" stroke="#00e676" strokeWidth="2" fill="none" />
              </svg>
            </div>
          </div>

          {/* Card 2: Open Incidents */}
          <div className="p-4 cyber-grid-glass rounded-xl flex flex-col justify-between hover:border-red-400/40 transition">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-red-500/15 border border-red-500/30 text-red-400">
                <Flame className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400 font-medium">Open Incidents</div>
                <div className="flex items-baseline gap-2 mt-0.5">
                  <span className="text-2xl font-extrabold text-white font-mono">{openIncidents}</span>
                  <span className="text-xs font-semibold text-red-400 flex items-center">
                    ▲ Active
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-end justify-between mt-3 pt-2 border-t border-[#152238]/60">
              <span className="text-[10px] text-slate-500">Correlated cases</span>
              <svg className="w-20 h-5" viewBox="0 0 100 25" fill="none">
                <path d="M 0 20 Q 25 15, 50 18 T 80 8 T 100 14" stroke="#ff3856" strokeWidth="2" fill="none" />
              </svg>
            </div>
          </div>

          {/* Card 3: Active Alerts */}
          <div className="p-4 cyber-grid-glass rounded-xl flex flex-col justify-between hover:border-amber-400/40 transition">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-amber-500/15 border border-amber-500/30 text-amber-400">
                <Bell className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400 font-medium">Active Alerts</div>
                <div className="flex items-baseline gap-2 mt-0.5">
                  <span className="text-2xl font-extrabold text-white font-mono">{activeAlerts}</span>
                  <span className="text-xs font-semibold text-amber-400 flex items-center">
                    Queue
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-end justify-between mt-3 pt-2 border-t border-[#152238]/60">
              <span className="text-[10px] text-slate-500">Triage backlog</span>
              <svg className="w-20 h-5" viewBox="0 0 100 25" fill="none">
                <path d="M 0 18 Q 30 10, 60 16 T 90 8 T 100 15" stroke="#ffaa00" strokeWidth="2" fill="none" />
              </svg>
            </div>
          </div>

          {/* Card 4: At Risk Endpoints */}
          <div className="p-4 cyber-grid-glass rounded-xl flex flex-col justify-between hover:border-indigo-400/40 transition">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-indigo-500/15 border border-indigo-500/30 text-indigo-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <div className="text-xs text-slate-400 font-medium">At Risk Endpoints</div>
                <div className="flex items-baseline gap-2 mt-0.5">
                  <span className="text-2xl font-extrabold text-white font-mono">{atRiskEndpoints}</span>
                  <span className="text-xs font-semibold text-cyan-400 flex items-center">
                    / {totalEndpoints} total
                  </span>
                </div>
              </div>
            </div>
            <div className="flex items-end justify-between mt-3 pt-2 border-t border-[#152238]/60">
              <span className="text-[10px] text-slate-500">{onlineEndpoints} online hosts</span>
              <svg className="w-20 h-5" viewBox="0 0 100 25" fill="none">
                <path d="M 0 14 Q 25 18, 50 12 T 80 16 T 100 8" stroke="#8b5cf6" strokeWidth="2" fill="none" />
              </svg>
            </div>
          </div>

          {/* Card 5: Risk Score (Avg) with Radial Arc Gauge */}
          <div className="p-4 cyber-grid-glass rounded-xl flex flex-col justify-between col-span-2 md:col-span-1 hover:border-cyan-400/40 transition">
            <div className="flex items-center justify-between">
              {/* Semi-circle Gauge SVG */}
              <div className="relative w-12 h-12 flex items-center justify-center">
                <svg className="w-12 h-12 -rotate-90" viewBox="0 0 36 36">
                  <path
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke="#152238"
                    strokeWidth="3.5"
                  />
                  <path
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                    fill="none"
                    stroke={riskScore > 75 ? "#ff3856" : riskScore > 50 ? "#ffaa00" : "#00e676"}
                    strokeDasharray={`${riskScore}, 100`}
                    strokeWidth="3.5"
                    strokeLinecap="round"
                  />
                </svg>
                <span className="absolute text-[10px] font-bold text-amber-400 font-mono">
                  {Math.round(riskScore)}%
                </span>
              </div>
              <div className="text-right">
                <div className="text-xs text-slate-400 font-medium">Risk Score (Avg)</div>
                <div className="text-xl font-extrabold text-white font-mono mt-0.5">
                  {riskScore} <span className="text-xs font-normal text-slate-400">/ 100</span>
                </div>
              </div>
            </div>
            <div className="flex items-end justify-between mt-3 pt-2 border-t border-[#152238]/60">
              <span className="text-[10px] text-slate-500">Autonomous score</span>
              <svg className="w-16 h-5" viewBox="0 0 100 25" fill="none">
                <path d="M 0 15 Q 30 8, 60 14 T 100 6" stroke="#00e5ff" strokeWidth="2" fill="none" />
              </svg>
            </div>
          </div>
        </div>

        {/* 3. Middle Section: Live Threat Stream (left) + Attack Graph (center) + Kill Chain & Risk (right) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
          {/* Left Column: Live Threat Stream (4 cols) */}
          <div className="lg:col-span-4 cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-3 border-b border-[#00B7FF]/15">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white text-sm">Live Threat Stream</span>
                  <span className="flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-red-950/50 border border-red-500/30 text-[10px] text-red-400 font-semibold">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
                    Real-time
                  </span>
                  {isStreamRefreshing && (
                    <span className="flex items-center gap-1 text-[10px] font-mono text-cyan-400/80 animate-pulse">
                      <RotateCw className="w-2.5 h-2.5 animate-spin text-cyan-400" />
                      Syncing
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => fetchDashboardData()}
                    disabled={isStreamRefreshing}
                    className="p-1 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-[#00B7FF]/10 transition disabled:opacity-50"
                    title="Refresh Threat Stream"
                  >
                    <RotateCw className={`w-3.5 h-3.5 ${isStreamRefreshing ? "animate-spin text-cyan-400" : ""}`} />
                  </button>
                  <Link to="/alerts" className="p-1 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-[#00B7FF]/10 transition" title="View all alerts">
                    <Maximize2 className="w-3.5 h-3.5" />
                  </Link>
                </div>
              </div>

              {/* Stream Event Rows from Real Data - Continuous rendering during background refresh */}
              <div className="divide-y divide-[#152238]/60 mt-2 space-y-1 min-h-[220px]">
                {streamEvents && streamEvents.length > 0 ? (
                  streamEvents.slice(0, 5).map((alert: Alert) => {
                    const sevColor =
                      alert.severity === "critical"
                        ? "bg-red-500"
                        : alert.severity === "high"
                        ? "bg-orange-500"
                        : alert.severity === "medium"
                        ? "bg-amber-500"
                        : "bg-emerald-500";
                    return (
                      <div
                        key={alert.id}
                        onClick={() => navigate("/alerts")}
                        className="py-2 flex items-center justify-between gap-2 hover:bg-[#00B7FF]/10 px-1.5 rounded-lg transition group cursor-pointer"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <span className={`w-1.5 h-1.5 rounded-full ${sevColor} shrink-0`}></span>
                          <span className="text-[10px] font-mono text-slate-400 shrink-0">
                            {new Date(alert.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded border text-[9px] font-bold uppercase shrink-0 ${getSeverityBadgeClass(
                              alert.severity
                            )}`}
                          >
                            {alert.severity}
                          </span>
                          <div className="min-w-0">
                            <div className="text-xs font-semibold text-white truncate group-hover:text-cyan-400 transition">
                              {alert.title}
                            </div>
                            <div className="text-[10px] text-slate-400 truncate">
                              Risk Score: {alert.risk_score || 65}/100 • Status: {alert.status}
                            </div>
                          </div>
                        </div>
                        <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-cyan-400 shrink-0" />
                      </div>
                    );
                  })
                ) : loading ? (
                  <div className="py-12 flex flex-col items-center justify-center gap-2 text-xs text-slate-400">
                    <RotateCw className="w-4 h-4 text-cyan-400 animate-spin" />
                    <span>Synchronizing threat telemetry stream...</span>
                  </div>
                ) : (
                  <div className="py-12 text-center text-xs text-slate-500">
                    No active threat events reported in current window.
                  </div>
                )}
              </div>
            </div>

            <div className="pt-2 border-t border-[#152238]/60 flex items-center justify-between text-[11px] text-slate-400">
              <span>{activeAlerts} total alerts in buffer</span>
              <Link to="/alerts" className="text-cyan-400 hover:underline flex items-center gap-1">
                Alert Queue <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>

          {/* Center Column: Attack Graph & Network View (5 cols) */}
          <div className="lg:col-span-5 cyber-grid-glass rounded-xl p-4 flex flex-col justify-between relative overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
              <span className="font-bold text-white text-sm">Attack Graph & Network Topology</span>
              <div className="flex items-center gap-3 text-[11px] text-slate-400">
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-emerald-400"></span> Online
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-amber-400"></span> Pivot
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-full bg-red-400"></span> Threat Hub
                </span>
              </div>
            </div>

            {/* Star Topology Interactive Graph Area */}
            <div className="relative w-full h-[280px] sm:h-[300px] flex items-center justify-center my-auto">
              {/* SVG Connecting Lines & Traveling Particles */}
              <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 500 300">
                {/* Center to Top (Internet) */}
                <line x1="250" y1="98" x2="250" y2="42" stroke="#ff3856" strokeWidth="1.5" strokeDasharray="4,4" className="animate-line-dash" />
                {/* Center to Right (Web Server) */}
                <line x1="278" y1="128" x2="420" y2="128" stroke="#ffaa00" strokeWidth="1.5" strokeDasharray="3,3" />
                {/* Center to Bottom-Right (Database Store) - Routed away from C2 label zone */}
                <line x1="292" y1="148" x2="390" y2="245" stroke="#00e5ff" strokeWidth="1.5" strokeDasharray="3,3" />
                {/* Center to Bottom-Left (User Admin) - Routed away from C2 label zone */}
                <line x1="208" y1="148" x2="120" y2="245" stroke="#00e676" strokeWidth="1.5" strokeDasharray="3,3" />
                {/* Center to Left (Endpoint Host) */}
                <line x1="222" y1="128" x2="85" y2="128" stroke="#00e5ff" strokeWidth="1.5" strokeDasharray="4,4" className="animate-line-dash" />

                {/* Glowing Particle dots */}
                <circle cx="250" cy="70" r="3" fill="#ff3856" className="animate-pulse" />
                <circle cx="150" cy="128" r="3" fill="#00e5ff" className="animate-pulse" />
                <circle cx="350" cy="128" r="3" fill="#ffaa00" className="animate-pulse" />
                <circle cx="164" cy="195" r="3" fill="#00e676" className="animate-pulse" />
                <circle cx="341" cy="195" r="3" fill="#00e5ff" className="animate-pulse" />
              </svg>

              {/* Top Node: Internet Gateway */}
              <button
                type="button"
                onClick={() => setSelectedNode("internet")}
                className={`absolute top-2 left-1/2 -translate-x-1/2 flex flex-col items-center transition group z-10 ${
                  selectedNode === "internet" ? "scale-110" : ""
                }`}
              >
                <div className="w-10 h-10 rounded-full bg-blue-900/60 border border-blue-500/50 flex items-center justify-center text-blue-400 shadow-cyber-glow group-hover:border-cyan-400">
                  <Globe className="w-5 h-5" />
                </div>
                <span className="text-[10px] font-semibold text-slate-300 mt-1">External WAN</span>
              </button>

              {/* Left Node: Endpoint Host */}
              <button
                type="button"
                onClick={() => setSelectedNode("endpoint")}
                className={`absolute left-2 top-[47%] -translate-y-1/2 flex flex-col items-center transition group z-10 ${
                  selectedNode === "endpoint" ? "scale-110" : ""
                }`}
              >
                <div className="w-10 h-10 rounded-full bg-cyan-950/80 border border-cyan-400/60 flex items-center justify-center text-cyan-400 shadow-cyber-glow group-hover:border-cyan-300">
                  <Laptop className="w-5 h-5" />
                </div>
                <span className="text-[10px] font-semibold text-slate-300 mt-1">
                  {endpoints[0]?.hostname || "WIN-HOST-01"}
                </span>
                <span className="text-[9px] font-mono text-slate-500">
                  {endpoints[0]?.ip_address || "172.0.0.1"}
                </span>
              </button>

              {/* Center Node: C2 Server (Compromise Hub) - Dedicated Protected Label Area */}
              <div className="absolute left-1/2 top-[47%] -translate-x-1/2 -translate-y-1/2 flex flex-col items-center z-20 pointer-events-none">
                <button
                  type="button"
                  onClick={() => setSelectedNode("c2")}
                  className={`pointer-events-auto flex flex-col items-center transition group ${
                    selectedNode === "c2" ? "scale-110" : ""
                  }`}
                >
                  <div className="relative w-14 h-14 rounded-full bg-red-950 border-2 border-red-500 flex items-center justify-center text-red-400 shadow-cyber-glow-red group-hover:border-red-400">
                    <div className="absolute inset-0 rounded-full border border-red-500/60 animate-pulse-ring pointer-events-none"></div>
                    <Server className="w-7 h-7 text-red-400 animate-pulse" />
                  </div>

                  {/* Dedicated Clear Label Area below C2 node with cyber halo pill */}
                  <div className="mt-2 flex flex-col items-center px-2.5 py-1 rounded-lg bg-[#020617]/95 border border-red-500/40 shadow-[0_0_15px_rgba(2,6,23,0.95)] backdrop-blur-md select-none z-30">
                    <span className="text-xs font-bold text-red-400 whitespace-nowrap leading-tight tracking-wide">
                      C2 Target Host
                    </span>
                    <span className="text-[10px] font-mono text-red-300/90 whitespace-nowrap leading-tight mt-0.5 font-bold">
                      198.51.100.99
                    </span>
                  </div>
                </button>
              </div>

              {/* Right Node: Web Server */}
              <button
                type="button"
                onClick={() => setSelectedNode("web")}
                className={`absolute right-3 top-[47%] -translate-y-1/2 flex flex-col items-center transition group z-10 ${
                  selectedNode === "web" ? "scale-110" : ""
                }`}
              >
                <div className="w-10 h-10 rounded-full bg-amber-950/80 border border-amber-400/60 flex items-center justify-center text-amber-400 shadow-cyber-glow-amber group-hover:border-amber-300">
                  <Server className="w-5 h-5" />
                </div>
                <span className="text-[10px] font-semibold text-slate-300 mt-1">App Ingress</span>
                <span className="text-[9px] font-mono text-slate-500">10.0.1.45</span>
              </button>

              {/* Bottom-Left Node: User */}
              <button
                type="button"
                onClick={() => setSelectedNode("user")}
                className={`absolute bottom-2 left-14 flex flex-col items-center transition group z-10 ${
                  selectedNode === "user" ? "scale-110" : ""
                }`}
              >
                <div className="w-10 h-10 rounded-full bg-emerald-950/80 border border-emerald-400/60 flex items-center justify-center text-emerald-400 shadow-cyber-glow-emerald group-hover:border-emerald-300">
                  <UserIcon className="w-5 h-5" />
                </div>
                <span className="text-[10px] font-semibold text-slate-300 mt-1">Auth Session</span>
                <span className="text-[9px] font-mono text-slate-500">Administrator</span>
              </button>

              {/* Bottom-Right Node: Database */}
              <button
                type="button"
                onClick={() => setSelectedNode("db")}
                className={`absolute bottom-2 right-14 flex flex-col items-center transition group z-10 ${
                  selectedNode === "db" ? "scale-110" : ""
                }`}
              >
                <div className="w-10 h-10 rounded-full bg-cyan-950/80 border border-cyan-400/60 flex items-center justify-center text-cyan-400 shadow-cyber-glow group-hover:border-cyan-300">
                  <Database className="w-5 h-5" />
                </div>
                <span className="text-[10px] font-semibold text-slate-300 mt-1">Database Store</span>
                <span className="text-[9px] font-mono text-slate-500">10.0.1.1:445</span>
              </button>
            </div>

            <div className="pt-2 border-t border-[#152238]/60 flex items-center justify-between text-[11px] text-slate-400">
              <span className="font-mono text-cyan-400">
                Selected: <span className="text-white uppercase font-bold">{selectedNode}</span>
              </span>
              <Link to="/evidence-timeline" className="text-cyan-400 hover:underline flex items-center gap-1">
                View Evidence Timeline <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>

          {/* Right Column: Kill Chain & Risk Distribution (3 cols) */}
          <div className="lg:col-span-3 space-y-3.5">
            {/* Cyber Kill Chain Progression */}
            <div className="cyber-grid-glass rounded-xl p-3.5">
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <span className="font-bold text-white text-xs">Cyber Kill Chain Alignment</span>
                <span className="text-[10px] font-mono text-cyan-400 font-bold">
                  {coveredTacticsCount}/{totalTacticsCount} TACTICS
                </span>
              </div>

              {/* Stepper with Circles */}
              <div className="pt-3">
                <div className="flex items-center justify-between relative px-2">
                  <div className="absolute left-4 right-4 h-0.5 bg-[#152238] top-3 z-0" />
                  <div className="absolute left-4 w-3/5 h-0.5 bg-cyan-400 top-3 z-0" />

                  {/* 1. Recon */}
                  <div className="flex flex-col items-center z-10" title="Reconnaissance">
                    <div className="w-6 h-6 rounded-full bg-[#070d18] border-2 border-cyan-400 flex items-center justify-center text-cyan-400 shadow-cyber-glow-sm">
                      <Check className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-[8px] text-slate-300 mt-1">Recon</span>
                  </div>

                  {/* 2. Initial Access */}
                  <div className="flex flex-col items-center z-10" title="Initial Access: 44 Detections">
                    <div className="w-6 h-6 rounded-full bg-[#070d18] border-2 border-cyan-400 flex items-center justify-center text-cyan-400 shadow-cyber-glow-sm">
                      <Check className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-[8px] text-slate-300 mt-1">Access</span>
                  </div>

                  {/* 3. Execution */}
                  <div className="flex flex-col items-center z-10" title="Execution: 234 Detections">
                    <div className="w-6 h-6 rounded-full bg-[#070d18] border-2 border-red-500 flex items-center justify-center text-red-400 shadow-cyber-glow-red animate-pulse">
                      <Flame className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-[8px] text-red-400 font-bold mt-1">Execute</span>
                  </div>

                  {/* 4. Evasion */}
                  <div className="flex flex-col items-center z-10" title="Defense Evasion: 176 Detections">
                    <div className="w-6 h-6 rounded-full bg-[#070d18] border-2 border-orange-500 flex items-center justify-center text-orange-400 shadow-cyber-glow-sm">
                      <Check className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-[8px] text-orange-300 mt-1">Evasion</span>
                  </div>

                  {/* 5. C2 */}
                  <div className="flex flex-col items-center z-10 opacity-70" title="Command & Control">
                    <div className="w-6 h-6 rounded-full bg-[#070d18] border border-cyan-500/50 flex items-center justify-center text-cyan-400">
                      <Radio className="w-3 h-3 animate-pulse" />
                    </div>
                    <span className="text-[8px] text-slate-300 mt-1">C2</span>
                  </div>

                  {/* 6. Action */}
                  <div className="flex flex-col items-center z-10 opacity-40" title="Actions on Objectives">
                    <div className="w-6 h-6 rounded-full bg-[#070d18] border border-slate-700 flex items-center justify-center text-slate-600">
                      <span className="w-1.5 h-1.5 rounded-full bg-slate-600"></span>
                    </div>
                    <span className="text-[8px] text-slate-500 mt-1">Action</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Risk Distribution Donut Chart */}
            <div className="cyber-grid-glass rounded-xl p-3.5">
              <span className="font-bold text-white text-xs block pb-2 border-b border-[#00B7FF]/15">
                Severity Distribution
              </span>
              <div className="flex items-center justify-between pt-2">
                {/* Dynamic Donut Arc SVG */}
                <div className="relative w-24 h-24 flex items-center justify-center">
                  <svg className="w-24 h-24 -rotate-90" viewBox="0 0 36 36">
                    {/* Critical */}
                    <circle
                      cx="18"
                      cy="18"
                      r="15.9155"
                      fill="none"
                      stroke="#ff3856"
                      strokeWidth="4"
                      strokeDasharray={`${critPct}, ${100 - critPct}`}
                      strokeDashoffset="0"
                    />
                    {/* High */}
                    <circle
                      cx="18"
                      cy="18"
                      r="15.9155"
                      fill="none"
                      stroke="#f97316"
                      strokeWidth="4"
                      strokeDasharray={`${highPct}, ${100 - highPct}`}
                      strokeDashoffset={`-${critPct}`}
                    />
                    {/* Medium */}
                    <circle
                      cx="18"
                      cy="18"
                      r="15.9155"
                      fill="none"
                      stroke="#ffaa00"
                      strokeWidth="4"
                      strokeDasharray={`${medPct}, ${100 - medPct}`}
                      strokeDashoffset={`-${critPct + highPct}`}
                    />
                    {/* Low */}
                    <circle
                      cx="18"
                      cy="18"
                      r="15.9155"
                      fill="none"
                      stroke="#00e676"
                      strokeWidth="4"
                      strokeDasharray={`${lowPct}, ${100 - lowPct}`}
                      strokeDashoffset={`-${critPct + highPct + medPct}`}
                    />
                  </svg>
                  <div className="absolute text-center">
                    <div className="text-base font-extrabold text-white font-mono leading-none">{totalSevAlerts}</div>
                    <div className="text-[8px] font-semibold text-cyan-400 mt-0.5">Alerts</div>
                  </div>
                </div>

                {/* Legend List from Real Severity Distribution */}
                <div className="space-y-1 text-xs">
                  <div className="flex items-center justify-between gap-4">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-2 h-2 rounded-full bg-[#ff3856]"></span> Critical
                    </span>
                    <span className="font-mono text-slate-400 text-[11px]">{sevDist.critical || 0}</span>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-2 h-2 rounded-full bg-[#f97316]"></span> High
                    </span>
                    <span className="font-mono text-slate-400 text-[11px]">{sevDist.high || 0}</span>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-2 h-2 rounded-full bg-[#ffaa00]"></span> Medium
                    </span>
                    <span className="font-mono text-slate-400 text-[11px]">{sevDist.medium || 0}</span>
                  </div>
                  <div className="flex items-center justify-between gap-4">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-2 h-2 rounded-full bg-[#00e676]"></span> Low
                    </span>
                    <span className="font-mono text-slate-400 text-[11px]">{sevDist.low || 0}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* 4. Lower Section: 4 Panels Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {/* Panel 1: Detection Trends */}
          <div className="cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <span className="font-bold text-white text-xs">Detection Activity Curve</span>
                {/* 24h / 7d / 30d Switcher */}
                <div className="flex items-center p-0.5 rounded-lg cyber-grid-glass-subtle">
                  {(["24h", "7d", "30d"] as const).map((t) => (
                    <button
                      key={t}
                      onClick={() => setTrendTimeframe(t)}
                      className={`px-2 py-0.5 text-[10px] font-bold rounded-md transition ${
                        trendTimeframe === t
                          ? "bg-[#00D9FF] text-slate-950 font-bold shadow-cyber-glow-sm"
                          : "text-slate-400 hover:text-white"
                      }`}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              {/* Legend */}
              <div className="flex items-center gap-3 text-[10px] text-slate-400 mt-2">
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span> Total
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span> High
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span> Medium
                </span>
                <span className="flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Low
                </span>
              </div>

              {/* Multi-series Wave Spline SVG */}
              <div className="h-36 w-full pt-2">
                <svg className="w-full h-full" viewBox="0 0 300 120" fill="none">
                  <defs>
                    <linearGradient id="cyanGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#00e5ff" stopOpacity="0.25" />
                      <stop offset="100%" stopColor="#00e5ff" stopOpacity="0" />
                    </linearGradient>
                  </defs>
                  {/* Grid Lines */}
                  <line x1="0" y1="20" x2="300" y2="20" stroke="#152238" strokeDasharray="3,3" />
                  <line x1="0" y1="60" x2="300" y2="60" stroke="#152238" strokeDasharray="3,3" />
                  <line x1="0" y1="100" x2="300" y2="100" stroke="#152238" strokeDasharray="3,3" />

                  {/* Total Area & Path */}
                  <path
                    d="M 0 90 Q 50 85, 100 70 T 200 40 T 260 55 T 300 35 L 300 120 L 0 120 Z"
                    fill="url(#cyanGrad)"
                  />
                  <path
                    d="M 0 90 Q 50 85, 100 70 T 200 40 T 260 55 T 300 35"
                    stroke="#00e5ff"
                    strokeWidth="2"
                    fill="none"
                  />

                  {/* High Path */}
                  <path
                    d="M 0 110 Q 50 100, 100 95 T 200 65 T 260 70 T 300 60"
                    stroke="#ff3856"
                    strokeWidth="1.5"
                    fill="none"
                  />

                  {/* Medium Path */}
                  <path
                    d="M 0 115 Q 50 110, 100 100 T 200 80 T 260 85 T 300 75"
                    stroke="#ffaa00"
                    strokeWidth="1.5"
                    fill="none"
                  />

                  {/* Low Path */}
                  <path
                    d="M 0 118 Q 50 115, 100 110 T 200 100 T 260 95 T 300 90"
                    stroke="#00e676"
                    strokeWidth="1.5"
                    fill="none"
                  />
                </svg>
              </div>
              {/* Timeline X-Axis */}
              <div className="flex justify-between text-[9px] font-mono text-slate-500 pt-1 border-t border-[#152238]">
                <span>00:00</span>
                <span>06:00</span>
                <span>12:00</span>
                <span>18:00</span>
                <span>NOW</span>
              </div>
            </div>
          </div>

          {/* Panel 2: MITRE ATT&CK Coverage */}
          <div className="cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <span className="font-bold text-white text-xs">MITRE ATT&CK Mapping</span>
                <Link to="/mitre" className="text-slate-400 hover:text-cyan-400 transition">
                  <Maximize2 className="w-3.5 h-3.5" />
                </Link>
              </div>

              <div className="flex items-center gap-3 pt-3">
                {/* Donut Ring with Real Covered Count */}
                <div className="relative w-24 h-24 shrink-0 flex items-center justify-center">
                  <svg className="w-24 h-24 -rotate-90" viewBox="0 0 36 36">
                    <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#152238" strokeWidth="4" />
                    <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#00e5ff" strokeWidth="4" strokeDasharray="35, 65" strokeDashoffset="0" />
                    <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#ff3856" strokeWidth="4" strokeDasharray="25, 75" strokeDashoffset="-35" />
                    <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#ffaa00" strokeWidth="4" strokeDasharray="20, 80" strokeDashoffset="-60" />
                  </svg>
                  <div className="absolute text-center leading-tight">
                    <div className="text-[9px] uppercase font-bold text-slate-400">Tactics</div>
                    <div className="text-sm font-extrabold text-white font-mono">
                      {coveredTacticsCount}/{totalTacticsCount}
                    </div>
                    <div className="text-[8px] text-cyan-400">Active</div>
                  </div>
                </div>

                {/* Tactic list counts from Real Data */}
                <div className="space-y-1 text-[10px] flex-1 overflow-hidden">
                  {topActiveTactics.length > 0 ? (
                    topActiveTactics.map((tac, idx) => {
                      const colors = ["bg-cyan-400", "bg-red-400", "bg-amber-400", "bg-purple-400", "bg-blue-400", "bg-emerald-400"];
                      return (
                        <div key={tac.id || idx} className="flex justify-between items-center text-slate-300">
                          <span className="flex items-center gap-1.5 truncate">
                            <span className={`w-1.5 h-1.5 rounded-full ${colors[idx % colors.length]} shrink-0`}></span>
                            <span className="truncate">{tac.name}</span>
                          </span>
                          <span className="font-mono text-cyan-300 font-bold shrink-0 ml-1">
                            {tac.active_detections_count}
                          </span>
                        </div>
                      );
                    })
                  ) : (
                    <div className="text-[10px] text-slate-500">Mapping Sigma rules to ATT&CK matrix...</div>
                  )}
                </div>
              </div>
            </div>

            <div className="pt-2 border-t border-[#152238]/60 flex items-center justify-between text-[11px]">
              <span className="text-slate-500">ATT&CK Matrix v14.1</span>
              <Link to="/mitre" className="text-cyan-400 hover:underline flex items-center gap-1">
                Full Matrix <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>

          {/* Panel 3: Recent Incidents */}
          <div className="cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <span className="font-bold text-white text-xs">Recent Incidents</span>
                <Link to="/incidents" className="text-[10px] text-cyan-400 hover:underline">
                  View All &gt;
                </Link>
              </div>

              {/* Incidents Rows from Real DB */}
              <div className="space-y-2 mt-2.5">
                {incidents.length > 0 ? (
                  incidents.slice(0, 4).map((inc) => (
                    <Link
                      to={`/incidents/${inc.id}`}
                      key={inc.id}
                      className="p-2 rounded-lg cyber-grid-glass-subtle flex items-center justify-between gap-2 hover:bg-[#00B7FF]/10 transition group"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold font-mono shrink-0 ${getPriorityBadgeClass(
                            inc.priority
                          )}`}
                        >
                          {inc.priority.substring(0, 2).toUpperCase()}
                        </span>
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-white truncate group-hover:text-cyan-400 transition flex items-center gap-1">
                            <span>{inc.incident_number}</span>
                            <span className="px-1 rounded bg-[#091322] text-cyan-300 text-[9px] border border-cyan-500/30">
                              {inc.status}
                            </span>
                          </div>
                          <div className="text-[10px] text-slate-400 truncate">
                            {inc.title || (inc.alerts?.[0]?.title ? inc.alerts[0].title : `Correlated Incident (${inc.alert_count} alerts)`)}
                          </div>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500 shrink-0">
                        {formatTimeAgo(inc.opened_at)}
                      </span>
                    </Link>
                  ))
                ) : (
                  <div className="py-6 text-center text-xs text-slate-500">
                    No active incidents registered.
                  </div>
                )}
              </div>
            </div>

            <div className="pt-2 border-t border-[#152238]/60 flex items-center justify-between text-[11px] text-slate-400">
              <span>{openIncidents} open incident cases</span>
              <Link to="/incidents" className="text-cyan-400 hover:underline flex items-center gap-1">
                Triage Cases <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>

          {/* Panel 4: Endpoint Health */}
          <div className="cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <span className="font-bold text-white text-xs">Endpoint Fleet Health</span>
                <Link to="/endpoints" className="text-[10px] text-cyan-400 hover:underline">
                  Manage &gt;
                </Link>
              </div>

              {/* Gauge & Stat Counts from Real DB */}
              <div className="flex items-center justify-between pt-2">
                <div className="relative w-16 h-16 flex items-center justify-center shrink-0">
                  <svg className="w-16 h-16 -rotate-90" viewBox="0 0 36 36">
                    <circle cx="18" cy="18" r="15.9155" fill="none" stroke="#152238" strokeWidth="3.5" />
                    <circle
                      cx="18"
                      cy="18"
                      r="15.9155"
                      fill="none"
                      stroke="#00e676"
                      strokeWidth="3.5"
                      strokeDasharray={`${totalEndpoints > 0 ? Math.round((onlineEndpoints / totalEndpoints) * 100) : 100}, 100`}
                    />
                  </svg>
                  <div className="absolute text-center leading-tight">
                    <div className="text-xs font-extrabold text-white font-mono">
                      {totalEndpoints > 0 ? Math.round((onlineEndpoints / totalEndpoints) * 100) : 100}%
                    </div>
                    <div className="text-[7px] text-emerald-400 uppercase font-semibold">Active</div>
                  </div>
                </div>

                <div className="space-y-1 text-[10px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> Online
                    </span>
                    <span className="font-mono text-white font-bold">{onlineEndpoints}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span> Total
                    </span>
                    <span className="font-mono text-white font-bold">{totalEndpoints}</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="flex items-center gap-1.5 text-slate-300">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span> At Risk
                    </span>
                    <span className="font-mono text-white font-bold">{atRiskEndpoints}</span>
                  </div>
                </div>
              </div>

              {/* Endpoints Table from Real DB */}
              <div className="divide-y divide-[#152238]/60 mt-2 text-[10px]">
                {endpoints.length > 0 ? (
                  endpoints.slice(0, 4).map((ep) => (
                    <Link
                      to={`/endpoints/${ep.id}`}
                      key={ep.id}
                      className="py-1 flex items-center justify-between hover:bg-[#00B7FF]/10 px-1 rounded transition group"
                    >
                      <div className="flex items-center gap-1.5 truncate max-w-[120px]">
                        <Laptop className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span className="font-mono text-slate-300 truncate group-hover:text-cyan-300">{ep.hostname}</span>
                      </div>
                      <span
                        className={`flex items-center gap-1 ${
                          ep.status === "online" ? "text-emerald-400" : "text-slate-400"
                        }`}
                      >
                        <span
                          className={`w-1 h-1 rounded-full ${
                            ep.status === "online" ? "bg-emerald-400" : "bg-slate-500"
                          }`}
                        ></span>
                        {ep.status}
                      </span>
                      <span className="text-slate-500 font-mono">{formatTimeAgo(ep.last_seen)}</span>
                    </Link>
                  ))
                ) : (
                  <div className="py-4 text-center text-slate-500">No endpoints enrolled</div>
                )}
              </div>
            </div>

            <div className="pt-2 border-t border-[#152238]/60 flex items-center justify-between text-[11px]">
              <span className="text-slate-500">{totalEndpoints} registered agents</span>
              <Link to="/endpoints" className="text-cyan-400 hover:underline flex items-center gap-1">
                Fleet Details <ChevronRight className="w-3 h-3" />
              </Link>
            </div>
          </div>
        </div>

        {/* 5. Bottom Section: Production Operational SOC Hub (Replaces prototype skeleton & motion guide) */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3.5">
          {/* Left Column: Recent Security Alerts Audit Queue (7 cols) */}
          <div className="lg:col-span-7 cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-white text-xs">Autonomous Alert Pipeline Queue</span>
                  <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-500/30 px-2 py-0.5 rounded-full">
                    Active Detections
                  </span>
                </div>
                <Link to="/alerts" className="text-[11px] text-cyan-400 hover:underline flex items-center gap-1">
                  View Full Triage Table <ArrowRight className="w-3 h-3" />
                </Link>
              </div>

              {/* Table of recent alerts */}
              <div className="mt-3 overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="text-[10px] font-mono uppercase text-slate-400 border-b border-[#152238]/80 pb-1">
                      <th className="pb-2 font-semibold">Severity</th>
                      <th className="pb-2 font-semibold">Threat Detection</th>
                      <th className="pb-2 font-semibold">Risk Score</th>
                      <th className="pb-2 font-semibold">Timestamp</th>
                      <th className="pb-2 font-semibold text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#152238]/60">
                    {streamEvents && streamEvents.length > 0 ? (
                      streamEvents.slice(0, 4).map((alert: Alert) => (
                        <tr key={alert.id} className="hover:bg-[#00B7FF]/5 transition">
                          <td className="py-2.5">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getSeverityBadgeClass(
                                alert.severity
                              )}`}
                            >
                              {alert.severity}
                            </span>
                          </td>
                          <td className="py-2.5 max-w-[240px]">
                            <div className="font-semibold text-white truncate hover:text-cyan-400 transition">
                              {alert.title}
                            </div>
                            <div className="text-[10px] text-slate-400 truncate">
                              ID: <span className="font-mono">{alert.id.substring(0, 8)}...</span> • Status: {alert.status}
                            </div>
                          </td>
                          <td className="py-2.5">
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-bold text-white text-xs">
                                {alert.risk_score || 65}
                              </span>
                              <div className="w-12 h-1.5 rounded-full bg-[#152238] overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    (alert.risk_score || 65) > 75
                                      ? "bg-red-500"
                                      : (alert.risk_score || 65) > 50
                                      ? "bg-amber-400"
                                      : "bg-emerald-400"
                                  }`}
                                  style={{ width: `${Math.min(100, alert.risk_score || 65)}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="py-2.5 text-[11px] font-mono text-slate-400 whitespace-nowrap">
                            {formatTimeAgo(alert.created_at)}
                          </td>
                          <td className="py-2.5 text-right">
                            <Link
                              to="/alerts"
                              className="inline-flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300 font-semibold px-2 py-1 rounded bg-[#0b1a2e] border border-cyan-500/30 hover:border-cyan-400 transition"
                            >
                              Inspect <ExternalLink className="w-3 h-3" />
                            </Link>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan={5} className="py-4 text-center text-slate-500">
                          No alerts queued.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pt-2 border-t border-[#152238]/60 flex items-center justify-between text-[11px] text-slate-400">
              <span>{activeAlerts} total detections evaluated</span>
              <span className="text-emerald-400 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" /> Continuous Ingestion Active
              </span>
            </div>
          </div>

          {/* Right Column: SOC Pipeline Engine Health & Quick Actions (5 cols) */}
          <div className="lg:col-span-5 cyber-grid-glass rounded-xl p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between pb-2 border-b border-[#00B7FF]/15">
                <span className="font-bold text-white text-xs">Autonomous Pipeline Engines</span>
                <span className="flex items-center gap-1.5 text-[10px] text-emerald-400 font-semibold">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span> ALL ENGINES OPERATIONAL
                </span>
              </div>

              {/* Status rows of active engines */}
              <div className="space-y-2 mt-3 text-xs">
                {/* Engine 1: Telemetry Ingestion */}
                <div className="p-2.5 rounded-lg cyber-grid-glass-subtle flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-1.5 rounded-md bg-blue-500/20 text-cyan-400 border border-cyan-500/30">
                      <Zap className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-semibold text-white">Log Telemetry & Parser Engine</div>
                      <div className="text-[10px] text-slate-400">Windows Event Log, Syslog & Network Flow</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 font-bold px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30">
                    ONLINE
                  </span>
                </div>

                {/* Engine 2: Sigma Correlation */}
                <div className="p-2.5 rounded-lg cyber-grid-glass-subtle flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-1.5 rounded-md bg-purple-500/20 text-purple-400 border border-purple-500/30">
                      <Cpu className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-semibold text-white">Sigma Detection Rule Matcher</div>
                      <div className="text-[10px] text-slate-400">178 Rule Detections Correlated</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 font-bold px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-500/30">
                    ACTIVE
                  </span>
                </div>

                {/* Engine 3: AI Threat Copilot */}
                <div className="p-2.5 rounded-lg cyber-grid-glass-subtle flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <div className="p-1.5 rounded-md bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                      <Terminal className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="font-semibold text-white">Autonomous Threat Copilot (LLM)</div>
                      <div className="text-[10px] text-slate-400">Automated triage, root cause & remediation</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-500/30">
                    READY
                  </span>
                </div>
              </div>
            </div>

            {/* Quick Command Actions */}
            <div className="pt-3 border-t border-[#152238]/60 mt-3">
              <div className="text-[10px] font-mono uppercase text-slate-400 mb-2">SOC Quick Workflows</div>
              <div className="grid grid-cols-3 gap-2">
                <Link
                  to="/attack-simulator"
                  className="px-2.5 py-1.5 rounded-lg bg-[#0c182c] border border-cyan-500/30 hover:border-cyan-400 text-center text-[11px] font-medium text-slate-200 hover:text-cyan-300 transition"
                >
                  Simulate Attack
                </Link>
                <Link
                  to="/ai-threat-copilot"
                  className="px-2.5 py-1.5 rounded-lg bg-[#0c182c] border border-cyan-500/30 hover:border-cyan-400 text-center text-[11px] font-medium text-slate-200 hover:text-cyan-300 transition"
                >
                  Threat Copilot
                </Link>
                <Link
                  to="/reports"
                  className="px-2.5 py-1.5 rounded-lg bg-[#0c182c] border border-cyan-500/30 hover:border-cyan-400 text-center text-[11px] font-medium text-slate-200 hover:text-cyan-300 transition"
                >
                  Generate Report
                </Link>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default Dashboard;
