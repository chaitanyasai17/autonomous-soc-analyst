import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  BarChart3,
  Target,
  ShieldCheck,
  RefreshCw,
  TrendingUp,
  Cpu,
  Laptop,
  Network,
  CheckCircle2,
  Clock,
  FileCode,
  ShieldAlert,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { GlassCard } from "../components/common/GlassCard";
import { SOCBadge } from "../components/common/SOCBadge";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { PageSkeleton } from "../components/common/SOCSkeleton";
import { SOCEmptyState, SOCErrorState } from "../components/common/SOCEmptyState";
import { SOCButton } from "../components/common/SOCButton";

interface DetectionAnalyticsData {
  total_detections: number;
  by_severity?: Record<string, number>;
  by_category?: Record<string, number>;
  top_rules?: Array<{
    rule_id: string;
    rule_title?: string;
    title?: string;
    severity?: string;
    count: number;
    category?: string;
  }>;
  top_mitre_techniques?: Array<{
    technique_id: string;
    name?: string;
    count: number;
  }>;
  detections_by_endpoint?: Array<{
    endpoint: string;
    count: number;
  }>;
  daily_trend?: Array<{
    date: string;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
  quality_metrics?: {
    total_detections?: number;
    reviewed_detections?: number;
    true_positives?: number;
    false_positives?: number;
    benign_suspicious?: number;
    tp_rate?: number;
    fp_rate?: number;
    accuracy?: number;
  };
  average_confidence?: number;
  last_detection_at?: string | null;
}

export const DetectionAnalytics: React.FC = () => {
  const { showToast } = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<DetectionAnalyticsData | null>(null);

  const fetchAnalytics = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get("/detections/analytics");
      const payload = res.data?.data ?? res.data;
      if (payload && typeof payload === "object" && typeof payload.total_detections === "number") {
        setData(payload);
      } else if (payload && typeof payload === "object") {
        // Fallback for object without total_detections explicitly set
        setData({
          total_detections: Number(payload.total_detections || 0),
          by_severity: payload.by_severity || {},
          by_category: payload.by_category || {},
          top_rules: Array.isArray(payload.top_rules) ? payload.top_rules : [],
          top_mitre_techniques: Array.isArray(payload.top_mitre_techniques) ? payload.top_mitre_techniques : [],
          detections_by_endpoint: Array.isArray(payload.detections_by_endpoint) ? payload.detections_by_endpoint : [],
          daily_trend: Array.isArray(payload.daily_trend) ? payload.daily_trend : [],
          quality_metrics: payload.quality_metrics || {},
          average_confidence: Number(payload.average_confidence || 0),
          last_detection_at: payload.last_detection_at || null,
        });
      } else {
        throw new Error("Invalid analytics payload format received from server");
      }
    } catch (err: any) {
      const errMsg = err.response?.data?.message || err.message || "Failed to load detection analytics";
      setError(errMsg);
      showToast(errMsg, "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalytics();
  }, []);

  const formatTimestamp = (ts?: string | null) => {
    if (!ts) return "None Recorded";
    try {
      const d = new Date(ts);
      return isNaN(d.getTime()) ? String(ts) : d.toLocaleString();
    } catch {
      return String(ts);
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden text-slate-200">
      {/* Background Graphic */}
      <CyberGridBackground variant="analytics" />

      {/* Main Foreground Content */}
      <div className="relative z-10 space-y-6">
        {/* Page Header */}
        <SOCPageHeader
          title="Detection Analytics"
          tagline="SIGMA ENGINE / PRECISION / COVERAGE"
          subtitle="Real-time Sigma rule efficacy, precision ratios, MITRE coverage, and telemetry host impact metrics."
          icon={<BarChart3 className="w-5 h-5 text-[#00D9FF]" />}
          actions={
            <>
              <Link to="/detections">
                <SOCButton variant="secondary" size="sm">
                  View Detections
                </SOCButton>
              </Link>
              <SOCButton
                variant="primary"
                size="sm"
                icon={<RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />}
                onClick={fetchAnalytics}
                disabled={loading}
              >
                Refresh Data
              </SOCButton>
            </>
          }
        />

        {/* Loading State */}
        {loading && <PageSkeleton />}

        {/* Error State */}
        {!loading && error && (
          <SOCErrorState
            title="Failed to Load Detection Analytics"
            error={error}
            onRetry={fetchAnalytics}
          />
        )}

        {/* Success State */}
        {!loading && !error && data && (
          <>
            {/* Top 4 KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <SOCStatCard
                label="Total Detections"
                value={data.total_detections}
                subvalue="Sigma rules fired"
                icon={<Target className="w-5 h-5" />}
                iconBg="bg-cyan-500/15 border border-cyan-500/30 text-cyan-400"
              />

              <SOCStatCard
                label="True Positive Rate"
                value={
                  (data.quality_metrics?.reviewed_detections ?? 0) > 0
                    ? `${Math.round((data.quality_metrics?.tp_rate ?? 0) * 100)}%`
                    : "N/A"
                }
                subvalue={
                  (data.quality_metrics?.reviewed_detections ?? 0) > 0
                    ? `${data.quality_metrics?.true_positives ?? 0} of ${data.quality_metrics?.reviewed_detections} reviewed (${data.quality_metrics?.reviewed_detections} of ${data.total_detections} total)`
                    : `0 of ${data.total_detections} reviewed (Pending Triage)`
                }
                icon={<ShieldCheck className="w-5 h-5" />}
                iconBg="bg-emerald-500/15 border border-emerald-500/30 text-emerald-400"
              />

              <SOCStatCard
                label="Avg Rule Confidence"
                value={`${Math.round((data.average_confidence ?? 0) * 100)}%`}
                subvalue="Heuristic accuracy"
                icon={<Cpu className="w-5 h-5" />}
                iconBg="bg-purple-500/15 border border-purple-500/30 text-purple-400"
              />

              <SOCStatCard
                label="Latest Detection"
                value={data.total_detections > 0 ? "Active" : "None"}
                subvalue={formatTimestamp(data.last_detection_at)}
                icon={<Clock className="w-5 h-5" />}
                iconBg="bg-amber-500/15 border border-amber-500/30 text-amber-400"
              />
            </div>

            {/* Zero Detections Notice */}
            {data.total_detections === 0 && (
              <SOCEmptyState
                title="Zero Detections Recorded"
                description="No security detections have been triggered yet. Ingest telemetry logs or run a simulation attack to generate detection metrics."
                action={{
                  label: "Go to Log Management",
                  onClick: () => (window.location.href = "/logs"),
                }}
              />
            )}

            {/* Section: Severity Breakdown & Analyst Quality */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Severity Distribution */}
              <GlassCard>
                <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)] mb-4">
                  <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-400" />
                    Severity Breakdown
                  </span>
                  <span className="text-[10px] font-mono text-[#00D9FF]">4 TIERS</span>
                </div>

                <div className="space-y-3.5">
                  {["critical", "high", "medium", "low"].map((sev) => {
                    const count =
                      data.by_severity?.[sev] ||
                      data.by_severity?.[sev.toUpperCase()] ||
                      0;
                    const pct =
                      data.total_detections > 0
                        ? Math.round((count / data.total_detections) * 100)
                        : 0;
                    return (
                      <div key={sev} className="space-y-1">
                        <div className="flex justify-between text-xs">
                          <span className="capitalize font-semibold text-slate-300">
                            {sev}
                          </span>
                          <span className="font-mono text-slate-400">
                            {count} ({pct}%)
                          </span>
                        </div>
                        <div className="w-full h-2 bg-[#020617] rounded-full overflow-hidden border border-[rgba(0,183,255,0.1)]">
                          <div
                            className={`h-full transition-all duration-300 ${
                              sev === "critical"
                                ? "bg-red-500 shadow-cyber-glow-red"
                                : sev === "high"
                                ? "bg-orange-500"
                                : sev === "medium"
                                ? "bg-amber-500"
                                : "bg-emerald-500"
                            }`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </GlassCard>

              {/* Analyst Quality Feedback */}
              <GlassCard>
                <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)] mb-4">
                  <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Analyst Quality Feedback
                  </span>
                  <span className="text-[10px] font-mono text-emerald-400 font-bold">
                    {(data.quality_metrics?.reviewed_detections ?? 0) > 0
                      ? `${Math.round((data.quality_metrics?.accuracy ?? 0) * 100)}% ACCURACY`
                      : "N/A (0 REVIEWED)"}
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-3 mb-4">
                  <div className="p-3 cyber-panel-subtle rounded-xl text-center">
                    <div className="text-xl font-bold font-mono text-emerald-400">
                      {data.quality_metrics?.true_positives ?? 0}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">True Positives</div>
                  </div>

                  <div className="p-3 cyber-panel-subtle rounded-xl text-center">
                    <div className="text-xl font-bold font-mono text-red-400">
                      {data.quality_metrics?.false_positives ?? 0}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">False Positives</div>
                  </div>

                  <div className="p-3 cyber-panel-subtle rounded-xl text-center">
                    <div className="text-xl font-bold font-mono text-amber-400">
                      {data.quality_metrics?.benign_suspicious ?? 0}
                    </div>
                    <div className="text-[10px] text-slate-400 mt-0.5">Benign / Test</div>
                  </div>
                </div>

                <div className="p-3 cyber-panel-subtle rounded-xl text-xs text-slate-400 space-y-1.5 font-mono">
                  <div className="flex justify-between">
                    <span>Triage Backlog:</span>
                    <span className="font-bold text-slate-200">
                      {Math.max(
                        0,
                        (data.total_detections || 0) -
                          (data.quality_metrics?.reviewed_detections || 0)
                      )}{" "}
                      unreviewed of {data.total_detections || 0} total
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>Model Precision:</span>
                    <span className="font-bold text-[#00D9FF]">
                      {(data.quality_metrics?.reviewed_detections ?? 0) > 0
                        ? `${Math.round((data.quality_metrics?.tp_rate ?? 0) * 100)}% TP`
                        : "N/A"}
                    </span>
                  </div>
                </div>
              </GlassCard>
            </div>

            {/* Daily Detection Volume Timeline */}
            <GlassCard>
              <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)] mb-3">
                <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-[#00D9FF]" />
                  Detection Volume Timeline
                </span>
                <span className="text-[10px] font-mono text-slate-400">RECENT BUCKETS</span>
              </div>

              {(data.daily_trend || []).length === 0 ? (
                <p className="text-xs text-slate-500 py-6 text-center">
                  No detection timeline events recorded yet.
                </p>
              ) : (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
                  {(data.daily_trend || []).map((day) => (
                    <div
                      key={day.date}
                      className="p-3 cyber-panel-subtle rounded-xl flex flex-col justify-between"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono text-slate-400 truncate">
                          {day.date}
                        </span>
                        <span className="text-xs font-bold text-white font-mono">
                          {day.total}
                        </span>
                      </div>
                      <div className="mt-2 flex items-center gap-1 text-[9px] font-mono flex-wrap">
                        {day.critical > 0 && (
                          <span className="px-1 py-0.5 rounded bg-red-950 text-red-300 border border-red-800">
                            {day.critical}c
                          </span>
                        )}
                        {day.high > 0 && (
                          <span className="px-1 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-800">
                            {day.high}h
                          </span>
                        )}
                        {day.medium > 0 && (
                          <span className="px-1 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                            {day.medium}m
                          </span>
                        )}
                        {day.low > 0 && (
                          <span className="px-1 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                            {day.low}l
                          </span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </GlassCard>

            {/* Top Sigma Rules & Impacted Host Endpoints */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
              {/* Top Sigma Rules */}
              <GlassCard>
                <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)] mb-3">
                  <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-purple-400" />
                    Top Triggered Sigma Rules
                  </span>
                  <Link to="/sigma" className="text-[10px] text-[#00D9FF] hover:underline font-mono">
                    VIEW RULES &gt;
                  </Link>
                </div>

                {(data.top_rules || []).length === 0 ? (
                  <p className="text-xs text-slate-500 py-4 text-center">
                    No Sigma rule matches recorded yet.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {(data.top_rules || []).slice(0, 6).map((rule, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 cyber-panel-subtle rounded-xl flex items-center justify-between gap-3"
                      >
                        <div className="min-w-0 flex-1">
                          <div
                            className="text-xs font-semibold text-slate-200 truncate"
                            title={rule.rule_title || rule.title || rule.rule_id}
                          >
                            {rule.rule_title || rule.title || rule.rule_id}
                          </div>
                          <div className="text-[10px] text-slate-500 font-mono truncate">
                            {rule.rule_id}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <SOCBadge severity={rule.severity} size="sm" />
                          <span className="text-xs font-bold text-white font-mono px-2 py-0.5 rounded bg-[rgba(3,11,28,0.8)] border border-[rgba(0,183,255,0.2)]">
                            {rule.count}x
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </GlassCard>

              {/* Impacted Host Endpoints */}
              <GlassCard>
                <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)] mb-3">
                  <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                    <Laptop className="w-4 h-4 text-blue-400" />
                    Detections by Host Endpoint
                  </span>
                  <Link to="/endpoints" className="text-[10px] text-[#00D9FF] hover:underline font-mono">
                    ENDPOINTS &gt;
                  </Link>
                </div>

                {(data.detections_by_endpoint || []).length === 0 ? (
                  <p className="text-xs text-slate-500 py-4 text-center">
                    No host telemetry endpoints associated with detections.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {(data.detections_by_endpoint || []).map((ep, idx) => (
                      <div
                        key={idx}
                        className="p-2.5 cyber-panel-subtle rounded-xl flex items-center justify-between gap-3"
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <div className="p-1 rounded bg-[#008CFF]/15 text-[#00D9FF] border border-[#00B7FF]/30">
                            <Laptop className="w-3.5 h-3.5" />
                          </div>
                          <span className="text-xs font-semibold text-slate-200 truncate font-mono">
                            {ep.endpoint}
                          </span>
                        </div>
                        <span className="text-xs font-bold text-[#00D9FF] font-mono px-2 py-0.5 rounded bg-[rgba(0,140,255,0.12)] border border-[rgba(0,183,255,0.25)]">
                          {ep.count} hits
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </GlassCard>
            </div>

            {/* MITRE ATT&CK Techniques Triggered */}
            <GlassCard>
              <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)] mb-3">
                <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
                  <Network className="w-4 h-4 text-indigo-400" />
                  MITRE ATT&CK Techniques Triggered
                </span>
                <Link to="/mitre" className="text-[10px] text-[#00D9FF] hover:underline font-mono">
                  TACTICS MATRIX &gt;
                </Link>
              </div>

              {(data.top_mitre_techniques || []).length === 0 ? (
                <p className="text-xs text-slate-500 py-4 text-center">
                  No MITRE ATT&CK techniques associated with current detections.
                </p>
              ) : (
                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-7 gap-3">
                  {(data.top_mitre_techniques || []).map((t, idx) => (
                    <div
                      key={idx}
                      className="p-3 cyber-panel-subtle rounded-xl text-center"
                    >
                      <div className="text-xs font-bold text-[#00D9FF] font-mono">
                        {t.technique_id}
                      </div>
                      <div className="text-base font-black text-white font-mono mt-1">
                        {t.count}
                      </div>
                      <div className="text-[9px] text-slate-500 uppercase font-mono mt-0.5 truncate">
                        {t.name || "Technique"}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </GlassCard>
          </>
        )}
      </div>
    </div>
  );
};
