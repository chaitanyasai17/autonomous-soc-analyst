import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Target,
  ShieldAlert,
  Gauge,
  Sparkles,
  AlertOctagon,
  RefreshCw,
  Eye,
  SlidersHorizontal,
  Play,
  CheckCircle2,
  ExternalLink,
  Layers,
  GitCommit,
  Info,
} from "lucide-react";
import { api } from "../services/api";
import { SigmaDetection, RiskLevel } from "../types";
import { SeverityBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { PipelineTraceModal } from "../components/common/PipelineTraceModal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { GlassCard } from "../components/common/GlassCard";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";

export const Detections: React.FC = () => {
  const [detections, setDetections] = useState<SigmaDetection[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Operations State
  const [isRunningAll, setIsRunningAll] = useState<boolean>(false);
  const [isAssessing, setIsAssessing] = useState<boolean>(false);
  const [isAlerting, setIsAlerting] = useState<boolean>(false);
  const [activeDetection, setActiveDetection] = useState<SigmaDetection | null>(null);
  const [traceDetectionId, setTraceDetectionId] = useState<string | null>(null);

  // Statistics & Quality
  const [stats, setStats] = useState<any | null>(null);
  const [qualityMetrics, setQualityMetrics] = useState<any | null>(null);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const fetchStats = async () => {
    try {
      const [statsRes, qualityRes] = await Promise.all([
        api.get("/detections/statistics"),
        api.get("/detections/quality-metrics"),
      ]);
      if (statsRes.data?.data) {
        setStats(statsRes.data.data);
      }
      if (qualityRes.data?.data) {
        setQualityMetrics(qualityRes.data.data);
      }
    } catch {
      // statistics endpoint fallback
    }
  };

  const fetchDetections = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        skip: (page - 1) * 10,
        limit: 10,
      };
      if (severityFilter) params.severity = severityFilter;
      if (searchQuery) params.matched_rule = searchQuery;

      const res = await api.get("/detections", { params });
      if (res.data) {
        setDetections(res.data.data || []);
        setTotal(res.data.total || 0);
      }
    } catch (err: any) {
      toastError("Failed to fetch Sigma detections.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    fetchDetections();
  }, [page, severityFilter, searchQuery]);

  const handleRunSigmaOnAll = async () => {
    setIsRunningAll(true);
    try {
      const res = await api.post("/detections/run-all");
      const summary = res.data?.data;
      success(
        `Sigma scan complete: ${summary.detections_created} new detection(s) created from ${summary.events_scanned} event(s). Historical total: ${total} persisted detections.`
      );
      fetchStats();
      fetchDetections();
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed running Sigma detections across all logs.");
    } finally {
      setIsRunningAll(false);
    }
  };

  const handleAssessAllRisk = async () => {
    setIsAssessing(true);
    try {
      const res = await api.post("/risk/assess-batch");
      success(`Risk engine assessed ${res.data?.data?.assessed_count || 0} detection(s).`);
      navigate("/risk");
    } catch (err: any) {
      toastError("Failed to run batch risk scoring.");
    } finally {
      setIsAssessing(false);
    }
  };

  const handleGenerateAlerts = async () => {
    setIsAlerting(true);
    try {
      const res = await api.post("/alerts/auto-generate");
      success(res.data?.data?.message || "Alerts generated successfully.");
      navigate("/alerts");
    } catch (err: any) {
      toastError("Failed to auto-generate alerts.");
    } finally {
      setIsAlerting(false);
    }
  };

  const handleRecordFeedback = async (detectionId: string, verdict: string) => {
    try {
      await api.post(`/detections/${detectionId}/feedback`, { verdict });
      success(`Analyst verdict '${verdict}' recorded.`);
      fetchStats();
      fetchDetections();
      if (activeDetection && (activeDetection as any).id === detectionId) {
        setActiveDetection({ ...activeDetection, analyst_verdict: verdict } as any);
      }
    } catch (err: any) {
      toastError("Failed to record analyst verdict.");
    }
  };

  const columns: Column<SigmaDetection>[] = [
    {
      header: "Severity",
      accessor: "severity",
      render: (item) => <SeverityBadge severity={item.severity} />,
    },
    {
      header: "Verdict",
      accessor: "id",
      render: (item: any) => {
        if (!item.analyst_verdict) {
          return <span className="text-[10px] text-slate-500 italic">Unreviewed</span>;
        }
        if (item.analyst_verdict === "TRUE_POSITIVE") {
          return (
            <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[10px] font-bold">
              TRUE POSITIVE
            </span>
          );
        }
        if (item.analyst_verdict === "FALSE_POSITIVE") {
          return (
            <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 text-[10px] font-bold">
              FALSE POSITIVE
            </span>
          );
        }
        return (
          <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[10px] font-bold">
            BENIGN
          </span>
        );
      },
    },
    {
      header: "Matched Rule Title",
      accessor: "rule_title",
      render: (item) => (
        <div>
          <div className="font-bold text-white">{item.rule_title}</div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5 flex items-center gap-2">
            <span>Rule: <strong className="text-cyan-400">{item.matched_rule}</strong></span>
            <span>•</span>
            <span>Category: {item.rule_category || "execution"}</span>
          </div>
        </div>
      ),
    },
    {
      header: "MITRE ATT&CK Mapping",
      accessor: "rule_tags",
      render: (item) => (
        <div className="flex flex-wrap gap-1 max-w-xs">
          {(item.rule_tags || []).slice(0, 3).map((tag, idx) => (
            <span
              key={idx}
              className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-cyan-300"
            >
              {tag.replace("attack.", "")}
            </span>
          ))}
          {(item.rule_tags || []).length > 3 && (
            <span className="text-[10px] text-slate-500">
              +{item.rule_tags!.length - 3} more
            </span>
          )}
        </div>
      ),
    },
    {
      header: "Confidence",
      accessor: "confidence",
      render: (item) => (
        <span className="font-mono text-xs font-bold text-slate-200">
          {(item.confidence * 100).toFixed(0)}%
        </span>
      ),
    },
    {
      header: "Detection Timestamp",
      accessor: "detection_timestamp",
      render: (item) => (
        <span className="font-mono text-xs text-slate-400">
          {new Date(item.detection_timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Actions",
      className: "text-right",
      render: (item) => (
        <div className="flex items-center justify-end gap-1.5">
          <button
            onClick={() => setTraceDetectionId(item.id)}
            className="p-1.5 rounded-lg bg-slate-900 border border-slate-700/80 hover:bg-slate-800 text-cyan-400 transition-colors"
            title="Trace End-to-End Pipeline Provenance"
          >
            <GitCommit className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setActiveDetection(item)}
            className="px-2.5 py-1 rounded-lg bg-cyan-950 border border-cyan-800/40 text-cyan-300 hover:bg-cyan-900 text-xs font-semibold flex items-center gap-1 transition-colors"
            title="Inspect Detection Evidence & Explain Why"
          >
            <Info className="w-3.5 h-3.5 text-cyan-400" />
            Explain Why
          </button>

          <button
            onClick={async () => {
              try {
                await api.post(`/risk/assess/${item.id}`);
                success("Risk evaluated for this detection.");
                navigate("/risk");
              } catch (e: any) {
                toastError("Risk assessment failed.");
              }
            }}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-yellow-400 transition-colors"
            title="Calculate deterministic risk score"
          >
            <Gauge className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => navigate("/ai")}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-400 transition-colors"
            title="Investigate with AI Copilot"
          >
            <Sparkles className="w-3.5 h-3.5" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with threat radar and nodes */}
      <CyberGridBackground variant="detections" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header Controls */}
        <SOCPageHeader
        title="Security Detections"
        tagline="REAL-TIME THREAT DETECTIONS"
        subtitle="Sigma-powered detection events and matched security telemetry."
        icon={Target}
        badge={{ label: "SIGMA ENGINE ACTIVE", variant: "success", pulse: true }}
        actions={
          <div className="flex flex-wrap items-center gap-2.5">
            <SOCButton
              variant="primary"
              size="sm"
              icon={Play}
              loading={isRunningAll}
              onClick={handleRunSigmaOnAll}
            >
              {isRunningAll ? "Scanning Events..." : "Run Detection Scan"}
            </SOCButton>

            <SOCButton
              variant="secondary"
              size="sm"
              icon={Gauge}
              loading={isAssessing}
              disabled={isAssessing || total === 0}
              onClick={handleAssessAllRisk}
            >
              {isAssessing ? "Scoring..." : "Assess Risk"}
            </SOCButton>

            <SOCButton
              variant="danger"
              size="sm"
              icon={AlertOctagon}
              loading={isAlerting}
              disabled={isAlerting || total === 0}
              onClick={handleGenerateAlerts}
            >
              {isAlerting ? "Generating..." : "Generate Alerts"}
            </SOCButton>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <SOCStatCard
          label="Total Detections"
          value={stats?.total_detections ?? total}
          icon={Target}
          variant="cyan"
          subtitle="Indexed AST signature matches"
        />

        <SOCStatCard
          label="Critical Hits"
          value={stats?.by_severity?.critical ?? 0}
          icon={ShieldAlert}
          variant="danger"
          subtitle="Immediate containment required"
        />

        <SOCStatCard
          label="Avg Confidence"
          value={stats?.average_confidence ? `${(stats.average_confidence * 100).toFixed(0)}%` : "95%"}
          icon={Gauge}
          variant="blue"
          subtitle="Heuristic and exact matches"
        />
      </div>

      {/* Quality Metrics Banner */}
      {qualityMetrics && (
        <div className="p-4 rounded-xl cyber-panel-subtle flex flex-wrap items-center justify-between gap-4 border border-[#1E3A8A]/50 bg-[#040D21]/80 backdrop-blur-md">
          <div className="flex items-center gap-2 text-xs">
            <span className="font-bold uppercase tracking-wider text-slate-200 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-cyan-400" />
              Detection Quality & Feedback:
            </span>
            <span className="text-cyan-300 font-mono">
              {qualityMetrics.reviewed_detections} of {qualityMetrics.total_detections} Reviewed by Analysts
            </span>
          </div>
          <div className="flex items-center gap-6 text-xs font-mono">
            <div>
              <span className="text-slate-400 text-[10px] block uppercase font-sans">True Positive Rate</span>
              <span className="text-emerald-400 font-bold">{(qualityMetrics.tp_rate * 100).toFixed(1)}%</span>
            </div>
            <div>
              <span className="text-slate-400 text-[10px] block uppercase font-sans">False Positive Rate</span>
              <span className="text-rose-400 font-bold">{(qualityMetrics.fp_rate * 100).toFixed(1)}%</span>
            </div>
            <div>
              <span className="text-slate-400 text-[10px] block uppercase font-sans">Detection Precision</span>
              <span className="text-cyan-400 font-bold">{(qualityMetrics.accuracy * 100).toFixed(1)}%</span>
            </div>
          </div>
        </div>
      )}


      {/* Detections Table */}
      <DataTable
        columns={columns}
        data={detections}
        isLoading={isLoading}
        total={total}
        page={page}
        pageSize={10}
        onPageChange={setPage}
        searchValue={searchQuery}
        onSearchChange={setSearchQuery}
        searchPlaceholder="Search matched rules..."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <button
              onClick={fetchDetections}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-400 hover:text-white"
              title="Refresh Detections"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        }
        emptyMessage="No threat detections recorded yet. Run a detection scan across ingested logs."
      />

      {/* Matched Fields & Evidence Modal */}
      <Modal
        isOpen={!!activeDetection}
        onClose={() => setActiveDetection(null)}
        title="WHY WAS THIS DETECTED? — Evidence Dossier"
        maxWidth="2xl"
      >
        {activeDetection && (
          <div className="space-y-4">
            {/* Explain Why Core Banner */}
            <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 space-y-3">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <span className="text-[11px] font-mono text-cyan-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                  <Info className="w-3.5 h-3.5" />
                  Detection Trigger Rationale
                </span>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={activeDetection.severity} />
                  <span className="text-xs font-mono text-cyan-400 font-bold px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-700/50">
                    {(activeDetection.confidence * 100).toFixed(0)}% Confidence
                  </span>
                </div>
              </div>

              <div>
                <span className="text-[10px] font-mono text-slate-400 uppercase">Detection Rule:</span>
                <h4 className="text-base font-bold text-white mt-0.5">
                  {activeDetection.rule_title}
                </h4>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Sigma Rule ID: <span className="text-cyan-300">{activeDetection.matched_rule}</span> • Category: <span className="text-slate-300 uppercase">{activeDetection.rule_category || "execution"}</span>
                </p>
              </div>

              <div className="grid grid-cols-2 gap-3 pt-2 border-t border-slate-900 text-xs">
                <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-400 font-mono uppercase block">Source Event Reference</span>
                  <span className="font-mono text-cyan-400 font-semibold truncate block mt-0.5" title={activeDetection.parsed_log_id}>
                    EVT-{activeDetection.parsed_log_id.substring(0, 8).toUpperCase()}
                  </span>
                  <span className="text-[9px] text-slate-500 font-mono truncate block">
                    {activeDetection.parsed_log_id}
                  </span>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800">
                  <span className="text-[10px] text-slate-400 font-mono uppercase block">Detection Timestamp</span>
                  <span className="font-mono text-slate-200 block mt-0.5">
                    {new Date(activeDetection.detection_timestamp).toLocaleString()}
                  </span>
                  <span className="text-[9px] text-emerald-400 font-mono block">
                    Telemetry Correlated
                  </span>
                </div>
              </div>
            </div>

            {/* MITRE Tags */}
            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                MITRE ATT&CK Framework Mapping
              </label>
              <div className="flex flex-wrap gap-1.5">
                {(activeDetection.rule_tags || []).map((tag, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-1 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-300 text-xs font-mono"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </div>

            {/* Matched Fields */}
            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-2">
                Matched Signature Evidence Fields
              </label>
              <div className="space-y-2">
                {(activeDetection.matched_fields || []).map((m, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between text-slate-400 mb-1">
                      <span>Field Key: <strong className="text-cyan-400">{m.field}</strong></span>
                      <span className="text-[10px] text-slate-500">Selection: {m.selection}</span>
                    </div>
                    <div className="text-slate-200 bg-slate-900/60 p-2.5 rounded-lg border border-slate-800/60 break-all">
                      {m.value}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Analyst Ground Truth Feedback */}
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block">
                Analyst Ground Truth Feedback (Continuous Tuning)
              </label>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleRecordFeedback((activeDetection as any).id, "TRUE_POSITIVE")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 border transition ${
                    (activeDetection as any).analyst_verdict === "TRUE_POSITIVE"
                      ? "bg-emerald-500/20 text-emerald-300 border-emerald-500/50 shadow-sm"
                      : "bg-slate-900 border-slate-800 text-slate-400 hover:text-emerald-400"
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  True Positive
                </button>
                <button
                  onClick={() => handleRecordFeedback((activeDetection as any).id, "FALSE_POSITIVE")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 border transition ${
                    (activeDetection as any).analyst_verdict === "FALSE_POSITIVE"
                      ? "bg-rose-500/20 text-rose-300 border-rose-500/50 shadow-sm"
                      : "bg-slate-900 border-slate-800 text-slate-400 hover:text-rose-400"
                  }`}
                >
                  <AlertOctagon className="w-3.5 h-3.5" />
                  False Positive
                </button>
                <button
                  onClick={() => handleRecordFeedback((activeDetection as any).id, "BENIGN_SUSPICIOUS")}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold flex items-center gap-1.5 border transition ${
                    (activeDetection as any).analyst_verdict === "BENIGN_SUSPICIOUS"
                      ? "bg-amber-500/20 text-amber-300 border-amber-500/50 shadow-sm"
                      : "bg-slate-900 border-slate-800 text-slate-400 hover:text-amber-400"
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Benign Suspicious
                </button>
              </div>
            </div>

            {/* Action Bar */}
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    const id = (activeDetection as any).id;
                    setActiveDetection(null);
                    setTraceDetectionId(id);
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-cyan-400 hover:bg-slate-800 text-xs font-semibold transition"
                >
                  <GitCommit className="w-3.5 h-3.5" />
                  View Provenance Trace
                </button>

                <button
                  onClick={() => {
                    setActiveDetection(null);
                    navigate("/ai");
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950 border border-cyan-800/50 text-cyan-300 hover:bg-cyan-900 text-xs font-bold transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                  Analyze with AI Copilot
                </button>
              </div>

              <button
                onClick={() => setActiveDetection(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* Pipeline Provenance Trace Modal */}
      <PipelineTraceModal
        isOpen={!!traceDetectionId}
        onClose={() => setTraceDetectionId(null)}
        objectType="detection"
        objectId={traceDetectionId}
      />
      </div>
    </div>
  );
};
