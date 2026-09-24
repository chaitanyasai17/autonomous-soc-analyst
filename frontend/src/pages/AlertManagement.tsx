import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  AlertOctagon,
  Eye,
  UserCheck,
  Sparkles,
  ShieldCheck,
  CheckCircle2,
  Filter,
  Plus,
  Flame,
  Layers,
  RefreshCw,
  ArrowRight,
  GitCommit,
} from "lucide-react";
import { api } from "../services/api";
import { Alert, AlertStatus, RiskLevel } from "../types";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { PipelineTraceModal } from "../components/common/PipelineTraceModal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";
import { notifyBadgeRefresh } from "../hooks/useNotificationBadges";

export const AlertManagement: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [statusFilter, setStatusFilter] = useState<string>(searchParams.get("status") || "");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [activeAlert, setActiveAlert] = useState<Alert | null>(null);
  const [traceAlertId, setTraceAlertId] = useState<string | null>(null);

  // Operations State
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [isCorrelating, setIsCorrelating] = useState<boolean>(false);
  const [isPromoting, setIsPromoting] = useState<boolean>(false);

  // AI Enrichment Drawer
  const [aiAnalysis, setAiAnalysis] = useState<any | null>(null);
  const [isAiLoading, setIsAiLoading] = useState<boolean>(false);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const fetchAlerts = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        skip: (page - 1) * 10,
        limit: 10,
      };
      if (statusFilter) params.status = statusFilter;
      if (severityFilter) params.severity = severityFilter;

      const res = await api.get("/alerts", { params });
      if (res.data) {
        setAlerts(res.data.data || []);
        setTotal(res.data.total || 0);
      }
    } catch (err: any) {
      toastError("Failed to fetch alerts.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, statusFilter, severityFilter]);

  const handleUpdateStatus = async (alertId: string, newStatus: AlertStatus) => {
    try {
      await api.patch(`/alerts/${alertId}/status`, { status: newStatus });
      success(`Alert status updated to '${newStatus.toUpperCase()}'.`);
      if (activeAlert && activeAlert.id === alertId) {
        setActiveAlert({ ...activeAlert, status: newStatus });
      }
      fetchAlerts();
      notifyBadgeRefresh();
    } catch (err: any) {
      toastError(err.response?.data?.message || "Status transition failed.");
    }
  };

  const handleAutoGenerateAlerts = async () => {
    setIsGenerating(true);
    try {
      const res = await api.post("/alerts/auto-generate");
      success(res.data?.data?.message || "Alerts generated from high-risk detections.");
      fetchAlerts();
      notifyBadgeRefresh();
    } catch (err: any) {
      toastError("Failed generating alerts.");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleAutoCorrelate = async () => {
    setIsCorrelating(true);
    try {
      const res = await api.post("/incidents/auto-correlate");
      success(res.data?.message || "Alerts correlated into security incidents.");
      fetchAlerts();
      notifyBadgeRefresh();
      navigate("/incidents");
    } catch (err: any) {
      toastError("Auto-correlation failed.");
    } finally {
      setIsCorrelating(false);
    }
  };

  const handlePromoteToIncident = async (alert: Alert) => {
    setIsPromoting(true);
    try {
      const res = await api.post("/incidents", {
        priority: alert.severity || "high",
        alert_ids: [alert.id],
      });
      if (res.data?.data) {
        success(`Incident ${res.data.data.incident_number} declared from alert.`);
        setActiveAlert(null);
        notifyBadgeRefresh();
        navigate(`/incidents/${res.data.data.id}`);
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed declaring incident.");
    } finally {
      setIsPromoting(false);
    }
  };

  const handleRunAiAnalysis = async () => {
    if (!activeAlert) {
      toastError("No alert selected for AI analysis.");
      return;
    }
    setIsAiLoading(true);
    try {
      const res = await api.post(`/ai/analyze/alert/${activeAlert.id}`);
      setAiAnalysis(res.data?.data || null);
      success("AI Threat Copilot analysis generated for alert.");
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed running AI Threat Copilot.");
    } finally {
      setIsAiLoading(false);
    }
  };

  const columns: Column<Alert>[] = [
    {
      header: "Severity",
      accessor: "severity",
      render: (item) => <SeverityBadge severity={item.severity} />,
    },
    {
      header: "Security Alert Title",
      accessor: "title",
      render: (item) => (
        <div>
          <div className="font-bold text-white">{item.title}</div>
          <div className="text-xs text-slate-400 line-clamp-1 max-w-sm mt-0.5">
            {item.description}
          </div>
        </div>
      ),
    },
    {
      header: "Triage Status",
      accessor: "status",
      render: (item) => <StatusBadge status={item.status} />,
    },
    {
      header: "Risk Score",
      accessor: "risk_score",
      render: (item) => (
        <span className="font-mono text-xs font-bold text-cyan-400">
          {item.risk_score ? `${item.risk_score} / 100` : "Assessed"}
        </span>
      ),
    },
    {
      header: "Investigator",
      accessor: "assigned_username",
      render: (item) => (
        <span className="text-xs text-slate-300 font-mono">
          {item.assigned_username || "Unassigned"}
        </span>
      ),
    },
    {
      header: "Timestamp",
      accessor: "created_at",
      render: (item) => (
        <span className="font-mono text-xs text-slate-400">
          {new Date(item.created_at).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Actions",
      className: "text-right",
      render: (item) => (
        <div className="flex items-center justify-end gap-1.5">
          <button
            onClick={() => setTraceAlertId(item.id)}
            className="p-1 rounded-lg bg-slate-900 border border-slate-700/80 hover:bg-slate-800 text-cyan-400 text-xs transition"
            title="Trace End-to-End Pipeline Provenance"
          >
            <GitCommit className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => {
              setActiveAlert(item);
              setAiAnalysis(null);
            }}
            className="px-2.5 py-1 rounded-lg bg-cyan-950 border border-cyan-800/50 text-xs font-semibold text-cyan-300 hover:bg-cyan-900 transition-colors"
          >
            Triage
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background */}
      <CyberGridBackground variant="alerts" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header Controls */}
        <SOCPageHeader
        title="Security Alerts"
        tagline="TRIAGE & ESCALATION QUEUE"
        subtitle="Prioritized security alerts generated from confirmed detections."
        icon={AlertOctagon}
        badge={{ label: `${total} QUEUED ALERTS`, variant: total > 0 ? "danger" : "default", pulse: total > 0 }}
        actions={
          <div className="flex items-center gap-2.5">
            <SOCButton
              variant="secondary"
              size="sm"
              icon={ShieldCheck}
              loading={isGenerating}
              onClick={handleAutoGenerateAlerts}
            >
              Generate From Risk
            </SOCButton>

            <SOCButton
              variant="danger"
              size="sm"
              icon={Flame}
              loading={isCorrelating}
              disabled={isCorrelating || total === 0}
              onClick={handleAutoCorrelate}
            >
              Auto-Correlate Incidents
            </SOCButton>
          </div>
        }
      />

      {/* Table & Filters */}
      <DataTable
        columns={columns}
        data={alerts}
        isLoading={isLoading}
        total={total}
        page={page}
        pageSize={10}
        onPageChange={setPage}
        searchPlaceholder="Filter alerts..."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="in_progress">In Progress</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
              <option value="false_positive">False Positive</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <button
              onClick={fetchAlerts}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-400 hover:text-white"
              title="Refresh Alerts"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        }
        emptyMessage="No security alerts found in queue. Evaluate detections or click 'Generate From Risk'."
      />

      {/* Alert Triage Drawer Modal */}
      <Modal
        isOpen={!!activeAlert}
        onClose={() => setActiveAlert(null)}
        title="Alert Investigation & Case Promotion"
        maxWidth="2xl"
      >
        {activeAlert && (
          <div className="space-y-5">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={activeAlert.severity} />
                  <StatusBadge status={activeAlert.status} />
                </div>
                <span className="font-mono text-xs text-cyan-400 font-bold">
                  Risk Score: {activeAlert.risk_score ? `${activeAlert.risk_score}/100` : "Assessed"}
                </span>
              </div>
              <h3 className="text-base font-bold text-white mb-1">{activeAlert.title}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">{activeAlert.description}</p>
            </div>

            {/* Lifecycle Status Triage Controls */}
            <div>
              <label className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
                Transition Alert Triage State
              </label>
              <div className="flex flex-wrap gap-2">
                {(["open", "in_progress", "resolved", "closed", "false_positive"] as AlertStatus[]).map(
                  (st) => (
                    <button
                      key={st}
                      onClick={() => handleUpdateStatus(activeAlert.id, st)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-bold border capitalize transition-all ${
                        activeAlert.status === st
                          ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50 ring-1 ring-cyan-500/40"
                          : "bg-slate-950 border-slate-800 text-slate-400 hover:text-white hover:border-slate-700"
                      }`}
                    >
                      {st.replace("_", " ")}
                    </button>
                  )
                )}
              </div>
            </div>

            {/* Promote to Incident Button */}
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between">
              <div>
                <p className="text-xs font-bold text-white flex items-center gap-1.5">
                  <Flame className="w-4 h-4 text-red-500" />
                  Declare Official Incident Investigation
                </p>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Promote this alert into a dedicated case with an assigned incident sequence (<span className="font-mono text-cyan-400">INC-YYYY-XXXX</span>).
                </p>
              </div>

              <button
                onClick={() => handlePromoteToIncident(activeAlert)}
                disabled={isPromoting}
                className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white font-bold text-xs shadow-md shadow-red-950/30 transition-all disabled:opacity-50 flex items-center gap-1.5"
              >
                <span>{isPromoting ? "Promoting..." : "Create Incident"}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* AI Copilot Threat Analysis Section */}
            <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/20 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    AI Threat Copilot Intelligence
                  </span>
                </div>
                {!aiAnalysis && (
                  <button
                    onClick={handleRunAiAnalysis}
                    disabled={isAiLoading}
                    className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black transition-colors disabled:opacity-50"
                  >
                    {isAiLoading ? "Analyzing..." : "Synthesize with AI"}
                  </button>
                )}
              </div>

              {aiAnalysis && (
                <div className="space-y-3 pt-2 text-xs">
                  <div>
                    <span className="text-slate-400 font-bold block mb-1">Executive Threat Summary:</span>
                    <p className="text-slate-200 leading-relaxed bg-slate-950/70 p-3 rounded-lg border border-slate-800 font-sans">
                      {aiAnalysis.threat_summary}
                    </p>
                  </div>

                  <div>
                    <span className="text-slate-400 font-bold block mb-1">Prescribed Containment Actions:</span>
                    <ul className="list-disc pl-4 space-y-1 text-slate-300">
                      {(aiAnalysis.recommended_actions || []).map((act: string, idx: number) => (
                        <li key={idx}>{act}</li>
                      ))}
                    </ul>
                  </div>

                  <div className="pt-2 text-[10px] text-slate-500 flex items-center justify-between font-mono">
                    <span>Engine: {aiAnalysis.provider_used}</span>
                    <span>Confidence: {(aiAnalysis.confidence * 100).toFixed(0)}%</span>
                  </div>
                </div>
              )}
            </div>

            <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between">
              <button
                onClick={() => setTraceAlertId(activeAlert.id)}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-cyan-400 hover:bg-slate-800 text-xs font-semibold transition"
              >
                <GitCommit className="w-3.5 h-3.5" />
                View Provenance Trace
              </button>

              <button
                onClick={() => setActiveAlert(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </Modal>

      {/* End-to-End Pipeline Provenance Trace Modal */}
      <PipelineTraceModal
        isOpen={!!traceAlertId}
        onClose={() => setTraceAlertId(null)}
        objectType="alert"
        objectId={traceAlertId}
      />
      </div>
    </div>
  );
};
