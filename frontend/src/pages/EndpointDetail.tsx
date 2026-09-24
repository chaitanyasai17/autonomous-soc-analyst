import React, { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import {
  Laptop,
  Server,
  ArrowLeft,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  Activity,
  AlertTriangle,
  Clock,
  User,
  Radio,
  FileText,
  Target,
  AlertOctagon,
  Briefcase,
  ExternalLink,
  Tag,
  Hash,
  Terminal,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { GlassCard } from "../components/common/GlassCard";

interface EndpointData {
  id: string;
  hostname: string;
  ip_address?: string;
  mac_address?: string;
  operating_system: string;
  os_version?: string;
  agent_version: string;
  status: string;
  risk_level: "low" | "medium" | "high" | "critical";
  owner_id: string;
  owner_username?: string;
  is_isolated: boolean;
  isolation_reason?: string;
  last_seen: string;
  registered_at: string;
  tags?: string[];
  event_count: number;
  detection_count: number;
  alert_count: number;
}

interface TelemetryEvent {
  id: string;
  timestamp: string;
  event_type: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  severity: string;
  message?: string;
}

interface DetectionSummary {
  id: string;
  rule_title: string;
  severity: string;
  detection_timestamp: string;
  verdict?: string;
}

interface AlertSummary {
  id: string;
  title: string;
  severity: string;
  status: string;
  created_at: string;
}

interface IncidentSummary {
  id: string;
  incident_number: string;
  priority: string;
  status: string;
  opened_at: string;
}

export const EndpointDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const { showToast } = useToast();

  const [loading, setLoading] = useState(true);
  const [endpoint, setEndpoint] = useState<EndpointData | null>(null);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [detections, setDetections] = useState<DetectionSummary[]>([]);
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);

  const [activeTab, setActiveTab] = useState<"events" | "detections" | "alerts" | "incidents">("events");
  const [isolating, setIsolating] = useState(false);

  const fetchDetail = async () => {
    if (!id) return;
    try {
      setLoading(true);
      const res = await api.get(`/endpoints/${id}`);
      const data = res.data.data;
      setEndpoint(data.endpoint);
      setEvents(data.recent_events || []);
      setDetections(data.detections || []);
      setAlerts(data.alerts || []);
      setIncidents(data.incidents || []);
    } catch (err: any) {
      const msg = err.response?.data?.message || err.response?.data?.detail || "Failed to load endpoint details";
      showToast(msg, "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDetail();
  }, [id]);

  const handleToggleIsolation = async () => {
    if (!endpoint) return;
    try {
      setIsolating(true);
      const nextState = !endpoint.is_isolated;
      await api.post(`/endpoints/${endpoint.id}/isolate`, {
        is_isolated: nextState,
        reason: nextState ? "Analyst initiated forensic containment from detail workbench" : undefined,
      });

      showToast(
        nextState ? `Host '${endpoint.hostname}' isolated.` : `Host '${endpoint.hostname}' reconnected.`,
        "success"
      );
      fetchDetail();
    } catch (err: any) {
      showToast("Failed to toggle isolation state", "error");
    } finally {
      setIsolating(false);
    }
  };

  const getRiskBadge = (level: string) => {
    switch (level.toLowerCase()) {
      case "critical":
        return "bg-purple-950/80 text-purple-300 border-purple-800 animate-pulse";
      case "high":
        return "bg-rose-950/80 text-rose-300 border-rose-800";
      case "medium":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      default:
        return "bg-emerald-950/80 text-emerald-300 border-emerald-800";
    }
  };

  if (loading) {
    return (
      <div className="p-16 flex flex-col items-center justify-center gap-3">
        <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
        <p className="text-xs text-slate-400 font-mono">Loading host telemetry & correlation...</p>
      </div>
    );
  }

  if (!endpoint) {
    return (
      <div className="p-12 text-center space-y-4">
        <AlertTriangle className="w-12 h-12 text-amber-500 mx-auto" />
        <h2 className="text-lg font-bold text-white">Endpoint Not Found</h2>
        <p className="text-xs text-slate-400">The requested endpoint does not exist or access was denied.</p>
        <Link
          to="/endpoints"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
        >
          <ArrowLeft className="w-4 h-4" />
          Back to Endpoints
        </Link>
      </div>
    );
  }

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background */}
      <CyberGridBackground variant="minimal" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Top Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 cyber-panel p-5 rounded-xl">
        <div className="flex items-center gap-4">
          <Link
            to="/endpoints"
            className="p-2 rounded-lg bg-[#040d21] hover:bg-[#0c244d] text-slate-300 hover:text-cyan-300 border border-[#1E3A8A]/50 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold text-white tracking-wide flex items-center gap-2">
                <Server className="w-5 h-5 text-cyan-400" />
                {endpoint.hostname}
              </h1>
              <span
                className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getRiskBadge(
                  endpoint.risk_level
                )}`}
              >
                {endpoint.risk_level} RISK
              </span>
              {endpoint.is_isolated && (
                <span className="px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-950/80 text-rose-300 border border-rose-800 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-rose-400" />
                  CONTAINED
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Host ID: <span className="text-cyan-300">{endpoint.id}</span> • Enrolled:{" "}
              {new Date(endpoint.registered_at).toLocaleDateString()}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleToggleIsolation}
            disabled={isolating}
            className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-semibold shadow-lg transition-all ${
              endpoint.is_isolated
                ? "bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-600/20"
                : "bg-rose-600 hover:bg-rose-500 text-white shadow-rose-600/20"
            }`}
          >
            {endpoint.is_isolated ? (
              <>
                <Unlock className="w-4 h-4" />
                Reconnect Host
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                Isolate Host (Containment)
              </>
            )}
          </button>
        </div>
      </div>

      {/* Host Specification & Metadata Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Spec Card */}
        <div className="cyber-panel p-5 rounded-xl space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            Host Specifications
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between border-b border-[#1E3A8A]/30 pb-1.5">
              <span className="text-slate-400">IP Address</span>
              <span className="font-mono text-cyan-300">{endpoint.ip_address || "N/A"}</span>
            </div>
            <div className="flex justify-between border-b border-[#1E3A8A]/30 pb-1.5">
              <span className="text-slate-400">Operating System</span>
              <span className="text-slate-200">
                {endpoint.operating_system} {endpoint.os_version && `(${endpoint.os_version})`}
              </span>
            </div>
            <div className="flex justify-between border-b border-[#1E3A8A]/30 pb-1.5">
              <span className="text-slate-400">MAC Address</span>
              <span className="font-mono text-slate-300">{endpoint.mac_address || "N/A"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Owner Account</span>
              <span className="text-cyan-400 font-medium">@{endpoint.owner_username || "system"}</span>
            </div>
          </div>
        </div>

        {/* Agent Telemetry Card */}
        <div className="cyber-panel p-5 rounded-xl space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Radio className="w-4 h-4 text-emerald-400" />
            Agent Diagnostics
          </h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between border-b border-[#1E3A8A]/30 pb-1.5">
              <span className="text-slate-400">Agent Version</span>
              <span className="font-mono text-emerald-400">{endpoint.agent_version}</span>
            </div>
            <div className="flex justify-between border-b border-[#1E3A8A]/30 pb-1.5">
              <span className="text-slate-400">Heartbeat Status</span>
              <span className="text-emerald-400 font-semibold uppercase">{endpoint.status}</span>
            </div>
            <div className="flex justify-between border-b border-[#1E3A8A]/30 pb-1.5">
              <span className="text-slate-400">Last Seen</span>
              <span className="text-slate-300 font-mono">{new Date(endpoint.last_seen).toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Network State</span>
              <span className={endpoint.is_isolated ? "text-rose-400 font-bold" : "text-emerald-400 font-bold"}>
                {endpoint.is_isolated ? "ISOLATED" : "CONNECTED"}
              </span>
            </div>
          </div>
        </div>

        {/* Security Health Summary */}
        <div className="cyber-panel p-5 rounded-xl space-y-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
            <Shield className="w-4 h-4 text-cyan-400" />
            Security Correlated Counts
          </h3>
          <div className="grid grid-cols-3 gap-2 pt-1 text-center">
            <div className="bg-[#020617]/70 p-2.5 rounded-lg border border-[#1E3A8A]/40">
              <div className="text-lg font-bold text-white font-mono">{endpoint.event_count}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">Events</div>
            </div>
            <div className="bg-[#020617]/70 p-2.5 rounded-lg border border-[#1E3A8A]/40">
              <div className="text-lg font-bold text-cyan-400 font-mono">{endpoint.detection_count}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">Detections</div>
            </div>
            <div className="bg-[#020617]/70 p-2.5 rounded-lg border border-[#1E3A8A]/40">
              <div className="text-lg font-bold text-rose-400 font-mono">{endpoint.alert_count}</div>
              <div className="text-[10px] text-slate-400 uppercase mt-0.5">Alerts</div>
            </div>
          </div>
          {endpoint.isolation_reason && (
            <div className="p-2 rounded bg-rose-950/40 border border-rose-900/60 text-[11px] text-rose-300">
              <span className="font-semibold">Isolation Note:</span> {endpoint.isolation_reason}
            </div>
          )}
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="flex border-b border-[#1E3A8A]/50 gap-2">
        <button
          onClick={() => setActiveTab("events")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === "events"
              ? "border-cyan-400 text-cyan-400 shadow-[0_2px_8px_rgba(0,217,255,0.3)]"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <FileText className="w-4 h-4" />
          Security Events ({events.length})
        </button>
        <button
          onClick={() => setActiveTab("detections")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === "detections"
              ? "border-cyan-400 text-cyan-400 shadow-[0_2px_8px_rgba(0,217,255,0.3)]"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Target className="w-4 h-4" />
          Sigma Detections ({detections.length})
        </button>
        <button
          onClick={() => setActiveTab("alerts")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === "alerts"
              ? "border-cyan-400 text-cyan-400 shadow-[0_2px_8px_rgba(0,217,255,0.3)]"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <AlertOctagon className="w-4 h-4" />
          SOC Alerts ({alerts.length})
        </button>
        <button
          onClick={() => setActiveTab("incidents")}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition-all ${
            activeTab === "incidents"
              ? "border-cyan-400 text-cyan-400 shadow-[0_2px_8px_rgba(0,217,255,0.3)]"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <Briefcase className="w-4 h-4" />
          Correlated Incidents ({incidents.length})
        </button>
      </div>

      {/* Tab Panels */}
      <div className="cyber-panel rounded-xl overflow-hidden shadow-xl p-4">
        {activeTab === "events" && (
          <div>
            {events.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                No normalized events recorded for this endpoint.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3">Event Type</th>
                      <th className="py-2.5 px-3">Source IP</th>
                      <th className="py-2.5 px-3">Destination</th>
                      <th className="py-2.5 px-3">User</th>
                      <th className="py-2.5 px-3">Severity</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-slate-300">
                    {events.map((ev) => (
                      <tr key={ev.id} className="hover:bg-slate-800/40">
                        <td className="py-2.5 px-3 font-mono text-slate-400">
                          {new Date(ev.timestamp).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-white">{ev.event_type}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-300">{ev.source_ip || "N/A"}</td>
                        <td className="py-2.5 px-3 font-mono text-slate-300">{ev.destination_ip || "N/A"}</td>
                        <td className="py-2.5 px-3 text-cyan-400">{ev.username || "N/A"}</td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getRiskBadge(
                              ev.severity
                            )}`}
                          >
                            {ev.severity}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === "detections" && (
          <div>
            {detections.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                No Sigma rule detections triggered on this endpoint.
              </div>
            ) : (
              <div className="space-y-3">
                {detections.map((det) => (
                  <div
                    key={det.id}
                    className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white text-xs">{det.rule_title}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getRiskBadge(
                            det.severity
                          )}`}
                        >
                          {det.severity}
                        </span>
                        {det.verdict && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-300">
                            {det.verdict}
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Detected at {new Date(det.detection_timestamp).toLocaleString()}
                      </p>
                    </div>
                    <Link
                      to="/detections"
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs border border-slate-700"
                    >
                      Inspect Detection
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "alerts" && (
          <div>
            {alerts.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                No SOC alerts raised for this host.
              </div>
            ) : (
              <div className="space-y-3">
                {alerts.map((alt) => (
                  <div
                    key={alt.id}
                    className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-white text-xs">{alt.title}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getRiskBadge(
                            alt.severity
                          )}`}
                        >
                          {alt.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                          {alt.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Raised at {new Date(alt.created_at).toLocaleString()}
                      </p>
                    </div>
                    <Link
                      to="/alerts"
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs border border-slate-700"
                    >
                      View in Alerts
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === "incidents" && (
          <div>
            {incidents.length === 0 ? (
              <div className="p-8 text-center text-slate-500 text-xs">
                No active incidents associated with this endpoint.
              </div>
            ) : (
              <div className="space-y-3">
                {incidents.map((inc) => (
                  <div
                    key={inc.id}
                    className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-cyan-400 text-xs">{inc.incident_number}</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getRiskBadge(
                            inc.priority
                          )}`}
                        >
                          {inc.priority}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                          {inc.status}
                        </span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Opened at {new Date(inc.opened_at).toLocaleString()}
                      </p>
                    </div>
                    <Link
                      to={`/incidents/${inc.id}`}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs border border-slate-700"
                    >
                      Open Incident Dossier
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      </div>
    </div>
  );
};
