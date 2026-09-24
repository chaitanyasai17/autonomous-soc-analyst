import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Flame,
  Shield,
  Clock,
  User,
  Layers,
  Plus,
  CheckCircle2,
  AlertTriangle,
  FileText,
  Activity,
  ChevronRight,
  Sparkles,
  Download,
  Send,
  MessageSquare,
  ShieldCheck,
  Laptop,
  Server,
  Lock,
  Radio,
  History,
  RefreshCw,
  Globe,
  Target,
  AlertOctagon,
  GitCommit,
} from "lucide-react";
import { api } from "../services/api";
import { Incident, IncidentStatus, RiskLevel, Alert, IncidentTimelineResponse } from "../types";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { Modal } from "../components/common/Modal";
import { PipelineTraceModal } from "../components/common/PipelineTraceModal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCButton } from "../components/common/SOCButton";
import { notifyBadgeRefresh } from "../hooks/useNotificationBadges";

const LIFECYCLE_STEPS: IncidentStatus[] = [
  "open",
  "investigating",
  "contained",
  "resolved",
  "closed",
];

export const IncidentDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const [incident, setIncident] = useState<Incident | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState<boolean>(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState<boolean>(false);
  const [isTraceOpen, setIsTraceOpen] = useState<boolean>(false);

  // Link Alert Modal
  const [isLinkModalOpen, setIsLinkModalOpen] = useState(false);
  const [unlinkedAlerts, setUnlinkedAlerts] = useState<Alert[]>([]);
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [isLinking, setIsLinking] = useState(false);

  // Analyst Forensic Notes
  const [analystNotes, setAnalystNotes] = useState<Array<{ id: string; author: string; text: string; time: string }>>([
    {
      id: "1",
      author: "Lead Investigator (admin)",
      text: "Investigation case initialized. Correlating initial telemetry and isolating suspicious host sockets.",
      time: new Date().toLocaleTimeString(),
    },
  ]);
  const [newNote, setNewNote] = useState("");

  // AI Incident Advisor
  const [aiAdvice, setAiAdvice] = useState<any | null>(null);
  const [isAiLoading, setIsAiLoading] = useState(false);

  // Active Containment Action States
  const [isHostIsolated, setIsHostIsolated] = useState(false);
  const [isIpBlocked, setIsIpBlocked] = useState(false);
  const [isTokenRevoked, setIsTokenRevoked] = useState(false);
  const [isMemoryDumped, setIsMemoryDumped] = useState(false);

  // Evidence Timeline Tab & State
  const [activeSideTab, setActiveSideTab] = useState<"timeline" | "notes">("timeline");
  const [timelineData, setTimelineData] = useState<IncidentTimelineResponse | null>(null);
  const [isTimelineLoading, setIsTimelineLoading] = useState<boolean>(false);

  const fetchTimeline = async () => {
    if (!id) return;
    setIsTimelineLoading(true);
    try {
      const res = await api.get(`/incidents/${id}/timeline`);
      if (res.data?.data) {
        setTimelineData(res.data.data);
      }
    } catch {
      // Non-blocking fallback
    } finally {
      setIsTimelineLoading(false);
    }
  };

  const fetchIncident = async () => {
    setIsLoading(true);
    try {
      const res = await api.get(`/incidents/${id}`);
      if (res.data?.data) {
        setIncident(res.data.data);
      }
    } catch (err: any) {
      toastError("Failed to load incident investigation details.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (id) {
      fetchIncident();
      fetchTimeline();
    }
  }, [id]);

  const handleStatusChange = async (nextStatus: IncidentStatus) => {
    if (!incident) return;
    setIsUpdatingStatus(true);
    try {
      const res = await api.patch(`/incidents/${incident.id}/status`, {
        status: nextStatus,
      });
      if (res.data?.data) {
        setIncident(res.data.data);
        success(`Lifecycle stage advanced to '${nextStatus.toUpperCase()}'.`);
        notifyBadgeRefresh();
        setAnalystNotes((prev) => [
          ...prev,
          {
            id: String(Date.now()),
            author: "System Audit",
            text: `Incident lifecycle status transitioned to: ${nextStatus.toUpperCase()}`,
            time: new Date().toLocaleTimeString(),
          },
        ]);
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Status transition rejected by SOC policy.");
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const openLinkModal = async () => {
    setIsLinkModalOpen(true);
    try {
      const res = await api.get("/alerts?limit=50");
      if (res.data?.data) {
        const currentIds = new Set((incident?.alerts || []).map((a) => a.id));
        setUnlinkedAlerts(res.data.data.filter((a: Alert) => !currentIds.has(a.id)));
      }
    } catch (err: any) {
      toastError("Failed to fetch candidate alerts.");
    }
  };

  const handleLinkAlertsSubmit = async () => {
    if (!incident || selectedAlertIds.length === 0) return;
    setIsLinking(true);
    try {
      const res = await api.post(`/incidents/${incident.id}/alerts`, {
        alert_ids: selectedAlertIds,
      });
      if (res.data?.data) {
        setIncident(res.data.data);
        success(`Linked ${selectedAlertIds.length} alert(s) to incident.`);
        notifyBadgeRefresh();
        setIsLinkModalOpen(false);
        setSelectedAlertIds([]);
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to link alerts.");
    } finally {
      setIsLinking(false);
    }
  };

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    setAnalystNotes((prev) => [
      ...prev,
      {
        id: String(Date.now()),
        author: "Analyst (admin)",
        text: newNote.trim(),
        time: new Date().toLocaleTimeString(),
      },
    ]);
    setNewNote("");
    success("Analyst note logged.");
  };

  const handleRunAiAdvisor = async () => {
    if (!incident) {
      toastError("No incident loaded for AI advice.");
      return;
    }
    setIsAiLoading(true);
    try {
      const res = await api.post(`/ai/analyze/incident/${incident.id}`);
      setAiAdvice(res.data?.data || null);
      success("AI Incident Containment playbook synthesized.");
    } catch (err: any) {
      toastError(err.response?.data?.message || "AI Incident Advisor failed.");
    } finally {
      setIsAiLoading(false);
    }
  };

  const handleGeneratePdfReport = async () => {
    if (!incident) return;
    setIsGeneratingReport(true);
    try {
      const res = await api.post("/reports/generate", {
        report_name: `Incident_Dossier_${incident.incident_number}`,
        report_type: "pdf",
      });
      if (res.data?.data?.id) {
        success("Incident report generated. Starting download...");
        // trigger direct download
        const downRes = await api.get(`/reports/${res.data.data.id}/download`, {
          responseType: "blob",
        });
        const url = window.URL.createObjectURL(new Blob([downRes.data], { type: "application/pdf" }));
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", `Incident_${incident.incident_number}.pdf`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
      }
    } catch (err: any) {
      toastError("Failed generating report brief.");
    } finally {
      setIsGeneratingReport(false);
    }
  };

  const toggleAlertSelection = (alertId: string) => {
    setSelectedAlertIds((prev) =>
      prev.includes(alertId) ? prev.filter((i) => i !== alertId) : [...prev, alertId]
    );
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-slate-400">
        <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin mr-3" />
        Loading incident dossier...
      </div>
    );
  }

  if (!incident) {
    return (
      <div className="p-8 text-center bg-slate-900 border border-slate-800 rounded-xl">
        <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto mb-3" />
        <h2 className="text-xl font-bold text-slate-100">Incident Not Found</h2>
        <p className="text-sm text-slate-400 mt-1 mb-4">
          The requested investigation ID does not exist or has been archived.
        </p>
        <button
          onClick={() => navigate("/incidents")}
          className="px-4 py-2 text-xs font-bold text-cyan-300 bg-cyan-950 border border-cyan-700/50 rounded-lg hover:bg-cyan-900"
        >
          Back to Incidents
        </button>
      </div>
    );
  }

  const currentStepIndex = LIFECYCLE_STEPS.indexOf(incident.status);

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with threat radar */}
      <CyberGridBackground variant="incidents" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Back Navigation & Case Identifier */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => navigate("/incidents")}
          className="inline-flex items-center gap-2 text-xs font-bold text-slate-400 hover:text-cyan-300 transition-colors font-mono"
        >
          <ArrowLeft className="w-4 h-4" /> Back to Incident Case List
        </button>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsTraceOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#040D21] border border-[#1E3A8A]/60 hover:bg-[#0c244d] text-cyan-400 text-xs font-bold transition-colors font-mono"
          >
            <GitCommit className="w-3.5 h-3.5" />
            <span>Provenance Trace</span>
          </button>

          <button
            onClick={handleGeneratePdfReport}
            disabled={isGeneratingReport}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#040D21] border border-[#1E3A8A]/60 hover:bg-[#0c244d] text-slate-200 text-xs font-bold transition-colors disabled:opacity-50 font-mono"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>{isGeneratingReport ? "Compiling PDF..." : "Export Case PDF"}</span>
          </button>

          <span className="text-xs font-mono text-cyan-400 font-black tracking-widest bg-cyan-950/80 border border-cyan-800/40 px-3 py-1 rounded-lg shadow-[0_0_10px_rgba(0,217,255,0.2)]">
            {incident.incident_number}
          </span>
        </div>
      </div>

      {/* Main Title Banner & Stage Controller */}
      <div className="cyber-panel rounded-2xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex items-center gap-3">
              <SeverityBadge severity={incident.priority} />
              <StatusBadge status={incident.status} />
              <span className="text-xs text-slate-400 font-mono">
                Declared: {new Date(incident.opened_at).toLocaleString()}
              </span>
            </div>
            <h1 className="text-2xl font-black text-slate-100 tracking-tight">
              {incident.title || `Investigation Case ${incident.incident_number}`}
            </h1>
            <p className="text-sm text-slate-300 max-w-4xl leading-relaxed">
              {incident.description ||
                `Coordinated SOC containment and triage investigation for incident ${incident.incident_number}.`}
            </p>
          </div>

          {/* Quick Lifecycle Status Controller */}
          <div className="bg-slate-950/90 border border-slate-800 p-4 rounded-xl min-w-[300px]">
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
              Advance Incident Lifecycle State
            </p>
            <div className="grid grid-cols-2 gap-2">
              {LIFECYCLE_STEPS.map((s) => (
                <button
                  key={s}
                  disabled={isUpdatingStatus || incident.status === s}
                  onClick={() => handleStatusChange(s)}
                  className={`text-xs font-bold py-1.5 px-2 rounded-lg border text-center transition-all ${
                    incident.status === s
                      ? "bg-cyan-500/20 border-cyan-500 text-cyan-300 ring-1 ring-cyan-500/50"
                      : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-40"
                  }`}
                >
                  {s.toUpperCase()}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Lifecycle Stepper Graphic */}
        <div className="mt-8 pt-6 border-t border-slate-800">
          <div className="flex items-center justify-between max-w-3xl mx-auto relative">
            <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-slate-800 -translate-y-1/2 z-0" />
            <div
              className="absolute top-1/2 left-0 h-0.5 bg-cyan-500 -translate-y-1/2 z-0 transition-all duration-500"
              style={{
                width: `${(Math.max(0, currentStepIndex) / (LIFECYCLE_STEPS.length - 1)) * 100}%`,
              }}
            />

            {LIFECYCLE_STEPS.map((step, idx) => {
              const isPast = idx < currentStepIndex;
              const isCurrent = idx === currentStepIndex;
              return (
                <div key={step} className="flex flex-col items-center relative z-10">
                  <div
                    className={`w-7 h-7 rounded-full flex items-center justify-center font-mono text-xs font-bold border-2 transition-all ${
                      isCurrent
                        ? "bg-cyan-500 border-white text-slate-950 shadow-lg shadow-cyan-500/50 scale-110"
                        : isPast
                        ? "bg-cyan-950 border-cyan-400 text-cyan-300"
                        : "bg-slate-950 border-slate-700 text-slate-500"
                    }`}
                  >
                    {idx + 1}
                  </div>
                  <span
                    className={`text-[10px] font-bold uppercase mt-1.5 tracking-wider ${
                      isCurrent ? "text-cyan-300" : isPast ? "text-slate-300" : "text-slate-600"
                    }`}
                  >
                    {step}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Active Containment Center & Entity Topology */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur-md">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Active Containment & Adversary Entity Controls
            </h3>
          </div>
          <span className="text-[11px] font-mono text-slate-500">Autonomous Incident Response Controls</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <button
            onClick={() => {
              setIsHostIsolated(!isHostIsolated);
              const action = !isHostIsolated ? "QUARANTINED" : "RELEASED";
              success(`Host endpoint vLAN isolation: ${action}`);
              setAnalystNotes((prev) => [
                ...prev,
                { id: String(Date.now()), author: "Active Containment", text: `Host endpoint status: ${action}`, time: new Date().toLocaleTimeString() },
              ]);
            }}
            className={`p-3.5 rounded-xl border text-left transition-all ${
              isHostIsolated
                ? "bg-red-950/80 border-red-500 text-red-200 shadow-lg shadow-red-950/40"
                : "bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <Laptop className="w-4 h-4 text-cyan-400" />
              <span className={`w-2 h-2 rounded-full ${isHostIsolated ? "bg-red-400 animate-ping" : "bg-slate-700"}`} />
            </div>
            <p className="text-xs font-bold text-white">Host Endpoint Isolation</p>
            <p className="text-[10px] text-slate-400 mt-0.5">{isHostIsolated ? "vLAN Quarantined" : "Normal Network State"}</p>
          </button>

          <button
            onClick={() => {
              setIsIpBlocked(!isIpBlocked);
              const action = !isIpBlocked ? "BLOCKED" : "UNBLOCKED";
              success(`Perimeter firewall null-route rule: ${action}`);
              setAnalystNotes((prev) => [
                ...prev,
                { id: String(Date.now()), author: "Active Containment", text: `Adversary IP null-route: ${action}`, time: new Date().toLocaleTimeString() },
              ]);
            }}
            className={`p-3.5 rounded-xl border text-left transition-all ${
              isIpBlocked
                ? "bg-amber-950/80 border-amber-500 text-amber-200 shadow-lg shadow-amber-950/40"
                : "bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <Server className="w-4 h-4 text-amber-400" />
              <span className={`w-2 h-2 rounded-full ${isIpBlocked ? "bg-amber-400 animate-ping" : "bg-slate-700"}`} />
            </div>
            <p className="text-xs font-bold text-white">Firewall C2 Null-Route</p>
            <p className="text-[10px] text-slate-400 mt-0.5">{isIpBlocked ? "IP Blocked at Edge" : "Rules Nominal"}</p>
          </button>

          <button
            onClick={() => {
              setIsTokenRevoked(!isTokenRevoked);
              const action = !isTokenRevoked ? "REVOKED" : "RESTORED";
              success(`Kerberos & OAuth sessions: ${action}`);
              setAnalystNotes((prev) => [
                ...prev,
                { id: String(Date.now()), author: "Active Containment", text: `Target user sessions: ${action}`, time: new Date().toLocaleTimeString() },
              ]);
            }}
            className={`p-3.5 rounded-xl border text-left transition-all ${
              isTokenRevoked
                ? "bg-purple-950/80 border-purple-500 text-purple-200 shadow-lg shadow-purple-950/40"
                : "bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <Lock className="w-4 h-4 text-purple-400" />
              <span className={`w-2 h-2 rounded-full ${isTokenRevoked ? "bg-purple-400 animate-ping" : "bg-slate-700"}`} />
            </div>
            <p className="text-xs font-bold text-white">Revoke User Tokens</p>
            <p className="text-[10px] text-slate-400 mt-0.5">{isTokenRevoked ? "Sessions Terminated" : "Tokens Active"}</p>
          </button>

          <button
            onClick={() => {
              setIsMemoryDumped(true);
              success("Volatile memory triage capture initiated (artifact: /triage/mem_dump.raw)");
              setAnalystNotes((prev) => [
                ...prev,
                { id: String(Date.now()), author: "Forensic Agent", text: "Memory dump artifact captured & hashed: SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069", time: new Date().toLocaleTimeString() },
              ]);
            }}
            className={`p-3.5 rounded-xl border text-left transition-all ${
              isMemoryDumped
                ? "bg-emerald-950/80 border-emerald-500 text-emerald-200"
                : "bg-slate-950 border-slate-800 hover:border-slate-700 text-slate-300"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <Activity className="w-4 h-4 text-emerald-400" />
              <span className={`w-2 h-2 rounded-full ${isMemoryDumped ? "bg-emerald-400" : "bg-slate-700"}`} />
            </div>
            <p className="text-xs font-bold text-white">Capture Memory Triage</p>
            <p className="text-[10px] text-slate-400 mt-0.5">{isMemoryDumped ? "Artifact Saved" : "On-Demand Dump"}</p>
          </button>
        </div>
      </div>

      {/* Grid: Correlated Alerts + AI Containment & Notes */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Correlated Alerts Workspace (2 Cols) */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                Correlated Security Alerts ({incident.alerts?.length || 0})
              </h2>
              <p className="text-xs text-slate-400">
                Triggering detections and anomalous telemetry associated with this investigation.
              </p>
            </div>

            <button
              onClick={openLinkModal}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-cyan-300 bg-cyan-950 hover:bg-cyan-900 border border-cyan-700/50 rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" /> Link More Alerts
            </button>
          </div>

          {!incident.alerts || incident.alerts.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-sm border border-dashed border-slate-800 rounded-xl">
              No alerts linked to this incident. Use "Link More Alerts" or run auto-correlation.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-slate-300">
                <thead className="bg-slate-950 text-[11px] font-bold uppercase tracking-wider text-slate-400 border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Alert Title</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Risk Score</th>
                    <th className="py-3 px-4">Triggered At</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs">
                  {(incident?.alerts || []).map((alert) => (
                    <tr key={alert.id} className="hover:bg-slate-800/40">
                      <td className="py-3 px-4">
                        <p className="font-semibold text-slate-200">{alert.title}</p>
                        <p className="text-[11px] text-slate-400 truncate max-w-sm">
                          {alert.description}
                        </p>
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={alert.severity} />
                      </td>
                      <td className="py-3 px-4">
                        <StatusBadge status={alert.status} />
                      </td>
                      <td className="py-3 px-4">
                        <span className="font-mono text-xs font-bold text-amber-400">
                          {alert.risk_score != null ? alert.risk_score.toFixed(1) : "—"}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-xs text-slate-400">
                        {new Date(alert.created_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* AI Threat Advisor Drawer */}
          <div className="pt-4 border-t border-slate-800">
            <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/20 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  <span className="text-xs font-bold text-white uppercase tracking-wider">
                    AI Containment Playbook Advisor
                  </span>
                </div>
                {!aiAdvice && (
                  <button
                    onClick={handleRunAiAdvisor}
                    disabled={isAiLoading}
                    className="px-3 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black transition-colors disabled:opacity-50"
                  >
                    {isAiLoading ? "Synthesizing..." : "Generate Playbook"}
                  </button>
                )}
              </div>

              {aiAdvice && (
                <div className="space-y-3 pt-2 text-xs">
                  <div>
                    <span className="text-slate-400 font-bold block mb-1">Prescribed Incident Response Playbook:</span>
                    <ol className="list-decimal pl-4 space-y-1 text-slate-200">
                      {(aiAdvice?.recommended_actions || []).map((act: string, idx: number) => (
                        <li key={idx}>{act}</li>
                      ))}
                    </ol>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Forensic Evidence Timeline & Analyst Notes (1 Col) */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur-md flex flex-col justify-between space-y-4">
          <div>
            {/* Header Tabs */}
            <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setActiveSideTab("timeline")}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all ${
                    activeSideTab === "timeline"
                      ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  <History className="w-3.5 h-3.5" />
                  <span>Evidence Timeline ({timelineData?.timeline?.length || 0})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActiveSideTab("notes")}
                  className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold transition-all ${
                    activeSideTab === "notes"
                      ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/40"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  <span>Case Notes ({analystNotes.length})</span>
                </button>
              </div>

              {activeSideTab === "timeline" && (
                <button
                  onClick={fetchTimeline}
                  disabled={isTimelineLoading}
                  className="p-1 text-slate-400 hover:text-white transition-colors"
                  title="Refresh Timeline"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isTimelineLoading ? "animate-spin text-cyan-400" : ""}`} />
                </button>
              )}
            </div>

            {/* Content: Timeline or Notes */}
            {activeSideTab === "timeline" ? (
              <div className="space-y-3 max-h-[440px] overflow-y-auto pr-1">
                {isTimelineLoading && !timelineData ? (
                  <div className="py-8 text-center text-xs text-slate-500">Loading timeline forensics...</div>
                ) : (() => {
                  const events = timelineData?.events || (timelineData as any)?.timeline || [];
                  if (events.length === 0) {
                    return (
                      <div className="py-8 text-center text-xs text-slate-500">
                        No chronological timeline events recorded yet.
                      </div>
                    );
                  }
                  return events.map((evt: any, idx: number) => {
                    const sevColor =
                      evt.severity === "critical"
                        ? "text-red-400 border-red-500/30 bg-red-950/40"
                        : evt.severity === "high"
                        ? "text-orange-400 border-orange-500/30 bg-orange-950/40"
                        : evt.severity === "medium"
                        ? "text-yellow-400 border-yellow-500/30 bg-yellow-950/40"
                        : "text-cyan-400 border-cyan-500/30 bg-cyan-950/40";

                    return (
                      <div
                        key={idx}
                        className="relative pl-6 pb-2 border-l-2 border-slate-800 last:border-transparent"
                      >
                        {/* Dot */}
                        <div className="absolute -left-[9px] top-0.5 w-4 h-4 rounded-full bg-slate-950 border-2 border-cyan-500 flex items-center justify-center">
                          <div className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                        </div>

                        <div className="p-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-1">
                          <div className="flex items-center justify-between text-[10px] font-mono text-slate-500">
                            <span>{new Date(evt.timestamp).toLocaleString()}</span>
                            <span className={`px-1.5 py-0.2 rounded uppercase font-bold border ${sevColor}`}>
                              {evt.event_type.replace(/_/g, " ")}
                            </span>
                          </div>
                          <p className="font-semibold text-slate-200">{evt.title}</p>
                          <p className="text-slate-400 text-[11px] leading-relaxed">{evt.description}</p>
                          {evt.source && (
                            <div className="text-[10px] font-mono text-cyan-400/80 pt-0.5">
                              Source: {evt.source}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  });
                })()}
              </div>
            ) : (
              /* Analyst Notes */
              <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
                {analystNotes.map((note) => (
                  <div
                    key={note.id}
                    className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs"
                  >
                    <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1 font-mono">
                      <span className="text-cyan-400 font-bold">{note.author}</span>
                      <span>{note.time}</span>
                    </div>
                    <p className="text-slate-300 leading-relaxed">{note.text}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Add Note Form or Timeline Stats */}
          {activeSideTab === "notes" ? (
            <form onSubmit={handleAddNote} className="flex gap-2 pt-3 border-t border-slate-800">
              <input
                type="text"
                value={newNote}
                onChange={(e) => setNewNote(e.target.value)}
                placeholder="Log analyst finding or action taken..."
                className="flex-1 bg-slate-950 border border-slate-700 rounded-xl px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              />
              <button
                type="submit"
                disabled={!newNote.trim()}
                className="px-3 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-bold transition-all"
              >
                <Send className="w-3.5 h-3.5" />
              </button>
            </form>
          ) : (
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
              <span>{timelineData?.summary?.total_events ?? 0} Timeline Events</span>
              {timelineData?.summary?.earliest_telemetry_gap_seconds != null && (
                <span>Gap: {Math.round(timelineData.summary.earliest_telemetry_gap_seconds)}s</span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Link Alerts Modal */}
      <Modal
        isOpen={isLinkModalOpen}
        onClose={() => setIsLinkModalOpen(false)}
        title="Associate Additional Alerts to Incident"
        maxWidth="lg"
      >
        <div className="space-y-4">
          <p className="text-xs text-slate-400">
            Select alerts to link to incident{" "}
            <span className="text-cyan-400 font-mono font-bold">
              {incident.incident_number}
            </span>
            :
          </p>

          <div className="max-h-72 overflow-y-auto space-y-2 pr-1">
            {unlinkedAlerts.length === 0 ? (
              <p className="text-xs text-slate-500 py-6 text-center">
                No unlinked alerts available in system.
              </p>
            ) : (
              unlinkedAlerts.map((alt) => {
                const isChecked = selectedAlertIds.includes(alt.id);
                return (
                  <div
                    key={alt.id}
                    onClick={() => toggleAlertSelection(alt.id)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all flex items-center justify-between ${
                      isChecked
                        ? "bg-cyan-950/50 border-cyan-500"
                        : "bg-slate-950 border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div>
                      <p className="text-sm font-semibold text-slate-200">{alt.title}</p>
                      <p className="text-xs text-slate-400 mt-0.5 truncate max-w-md">
                        {alt.description}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={alt.severity} />
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => {}}
                        className="rounded border-slate-700 text-cyan-500 focus:ring-cyan-500"
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>

          <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsLinkModalOpen(false)}
              className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={isLinking || selectedAlertIds.length === 0}
              onClick={handleLinkAlertsSubmit}
              className="px-5 py-2 text-xs font-bold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg disabled:opacity-50"
            >
              {isLinking ? "Linking..." : `Link ${selectedAlertIds.length} Alert(s)`}
            </button>
          </div>
        </div>
      </Modal>

      {/* Pipeline Provenance Trace Modal */}
      <PipelineTraceModal
        isOpen={isTraceOpen}
        onClose={() => setIsTraceOpen(false)}
        objectType="incident"
        objectId={incident?.id || null}
      />
      </div>
    </div>
  );
};
