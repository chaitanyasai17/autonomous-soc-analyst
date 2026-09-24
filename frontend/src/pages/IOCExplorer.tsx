import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  Fingerprint,
  Search,
  Filter,
  Copy,
  Check,
  ExternalLink,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Layers,
  Network,
  Activity,
  RefreshCw,
  Clock,
  Target,
  AlertOctagon,
  Briefcase,
  Laptop,
  Radio,
  X,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { Modal } from "../components/common/Modal";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";

interface IOCRecord {
  id: string;
  ioc_type: string;
  value: string;
  source: string;
  confidence: number;
  first_seen: string;
  last_seen: string;
  related_alert_id?: string;
  related_incident_id?: string;
  description?: string;
  tags?: string[];
  classification: "Observed" | "Suspicious" | "Confirmed Malicious";
  occurrences: number;
  risk_level: string;
  related_detections_count: number;
  related_alerts_count: number;
  related_incidents_count: number;
}

interface IOCStats {
  total_iocs: number;
  by_type: Record<string, number>;
  by_classification?: Record<string, number>;
}

interface IOCGraphData {
  ioc: IOCRecord;
  events: Array<{
    id: string;
    timestamp: string;
    event_type: string;
    source_ip?: string;
    hostname?: string;
    raw_snippet?: string;
  }>;
  detections: Array<{
    id: string;
    rule_title: string;
    severity: string;
    timestamp: string;
    verdict?: string;
  }>;
  alerts: Array<{
    id: string;
    title: string;
    severity: string;
    status: string;
    created_at: string;
  }>;
  incidents: Array<{
    id: string;
    incident_number: string;
    priority: string;
    status: string;
    opened_at: string;
  }>;
  endpoints: Array<{
    id: string;
    hostname: string;
    ip_address?: string;
    status: string;
    risk_level: string;
  }>;
}

export const IOCExplorer: React.FC = () => {
  const { showToast } = useToast();

  const [loading, setLoading] = useState(true);
  const [iocs, setIocs] = useState<IOCRecord[]>([]);
  const [stats, setStats] = useState<IOCStats>({
    total_iocs: 0,
    by_type: {},
    by_classification: {},
  });
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedType, setSelectedType] = useState("");
  const [selectedClassification, setSelectedClassification] = useState("");

  // Graph Modal / Drawer
  const [selectedIocId, setSelectedIocId] = useState<string | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphData, setGraphData] = useState<IOCGraphData | null>(null);

  const fetchIOCs = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (searchQuery.trim()) params.append("search", searchQuery.trim());
      if (selectedType) params.append("ioc_type", selectedType);
      params.append("limit", "100");

      const [listRes, statsRes] = await Promise.all([
        api.get(`/iocs?${params.toString()}`),
        api.get("/iocs/statistics"),
      ]);

      let items: IOCRecord[] = listRes.data.items || [];
      if (selectedClassification) {
        items = items.filter((i) => i.classification === selectedClassification);
      }
      setIocs(items);
      setStats(statsRes.data);
    } catch (err: any) {
      showToast("Failed to load IOC threat intelligence", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIOCs();
  }, [selectedType, selectedClassification]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchIOCs();
  };

  const handleCopy = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedValue(val);
    setTimeout(() => setCopiedValue(null), 2000);
    showToast("Indicator copied to clipboard", "info");
  };

  const handleOpenGraph = async (iocId: string) => {
    try {
      setSelectedIocId(iocId);
      setGraphLoading(true);
      const res = await api.get(`/iocs/${iocId}/graph`);
      setGraphData(res.data);
    } catch (err: any) {
      showToast("Failed to load IOC relationship graph", "error");
      setSelectedIocId(null);
    } finally {
      setGraphLoading(false);
    }
  };

  const getClassificationBadge = (cls: string) => {
    switch (cls) {
      case "Confirmed Malicious":
        return "bg-rose-950/80 text-rose-300 border-rose-800 animate-pulse";
      case "Suspicious":
        return "bg-amber-950/80 text-amber-300 border-amber-800";
      default:
        return "bg-slate-800 text-slate-300 border-slate-700";
    }
  };

  const getTypeBadge = (type: string) => {
    switch (type.toLowerCase()) {
      case "ipv4":
      case "ipv6":
        return "bg-cyan-500/20 text-cyan-300 border-cyan-500/30";
      case "domain":
      case "url":
        return "bg-indigo-500/20 text-indigo-300 border-indigo-500/30";
      case "sha256":
      case "md5":
      case "sha1":
        return "bg-emerald-500/20 text-emerald-300 border-emerald-500/30";
      case "hostname":
        return "bg-amber-500/20 text-amber-300 border-amber-500/30";
      case "username":
        return "bg-purple-500/20 text-purple-300 border-purple-500/30";
      default:
        return "bg-slate-800 text-slate-400 border-slate-700";
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with network nodes */}
      <CyberGridBackground variant="iocs" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
        <SOCPageHeader
          title="IOC Explorer"
          tagline="THREAT INTELLIGENCE & INDICATORS"
          subtitle="Investigate indicators and relationships across security evidence."
          icon={Fingerprint}
          badge={{ label: `${stats.total_iocs} INDICATORS INDEXED`, variant: "primary", pulse: true }}
        actions={
          <button
            onClick={fetchIOCs}
            disabled={loading}
            className="p-2 rounded-xl cyber-panel-subtle hover:bg-[#0c244d] border border-[#1E3A8A]/50 text-slate-300 hover:text-cyan-300 transition-colors"
            title="Refresh"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SOCStatCard
          label="Total Indicators"
          value={stats.total_iocs}
          icon={Fingerprint}
          variant="cyan"
          subtitle="Extracted from telemetry & detections"
        />

        <SOCStatCard
          label="Confirmed Malicious"
          value={stats.by_classification?.["Confirmed Malicious"] || 0}
          icon={ShieldAlert}
          variant="danger"
          subtitle="Backed by incident or verified detection"
        />

        <SOCStatCard
          label="Suspicious"
          value={stats.by_classification?.["Suspicious"] || 0}
          icon={AlertTriangle}
          variant="amber"
          subtitle="Triggered Sigma signature"
        />

        <SOCStatCard
          label="Observed Entities"
          value={stats.by_classification?.["Observed"] || 0}
          icon={ShieldCheck}
          variant="emerald"
          subtitle="Seen in normalized telemetry"
        />
      </div>

      {/* Filters */}
      <div className="cyber-panel p-4 rounded-xl flex flex-col md:flex-row gap-3 items-center justify-between">
        <form onSubmit={handleSearch} className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400/70" />
          <input
            type="text"
            placeholder="Search indicator value, domain, hash..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-500/30 transition-all font-mono"
          />
        </form>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400 font-mono"
          >
            <option value="">All Indicator Types</option>
            <option value="ipv4">IPv4 Address</option>
            <option value="ipv6">IPv6 Address</option>
            <option value="domain">Domain</option>
            <option value="url">URL</option>
            <option value="sha256">SHA256 Hash</option>
            <option value="md5">MD5 Hash</option>
            <option value="hostname">Hostname</option>
            <option value="username">Username</option>
          </select>

          <select
            value={selectedClassification}
            onChange={(e) => setSelectedClassification(e.target.value)}
            className="bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400 font-mono"
          >
            <option value="">All Classifications</option>
            <option value="Confirmed Malicious">Confirmed Malicious</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Observed">Observed Only</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="cyber-panel rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs text-slate-400 font-mono">Querying IOC intelligence registry...</p>
          </div>
        ) : iocs.length === 0 ? (
          <div className="p-12 text-center">
            <Fingerprint className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-300">No Indicators of Compromise Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
              No IOCs match your search or filter criteria. Ingest log telemetry or execute security scans to extract indicators.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Indicator (IOC)</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4 text-center">Seen</th>
                  <th className="py-3 px-4 text-center">Detections</th>
                  <th className="py-3 px-4 text-center">Alerts</th>
                  <th className="py-3 px-4 text-center">Incidents</th>
                  <th className="py-3 px-4 text-right">Attribution Graph</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {iocs.map((ioc) => (
                  <tr key={ioc.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-mono font-medium text-white max-w-xs truncate">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleCopy(ioc.value)}
                          className="text-slate-500 hover:text-cyan-400 transition-colors shrink-0"
                          title="Copy indicator"
                        >
                          {copiedValue === ioc.value ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                        <span
                          className="truncate cursor-pointer hover:text-cyan-400 underline-offset-2 hover:underline"
                          onClick={() => handleOpenGraph(ioc.id)}
                        >
                          {ioc.value}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getTypeBadge(
                          ioc.ioc_type
                        )}`}
                      >
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getClassificationBadge(
                          ioc.classification
                        )}`}
                      >
                        {ioc.classification}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center font-mono font-medium">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[11px]">
                        {ioc.occurrences}x
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center font-mono">
                      {ioc.related_detections_count > 0 ? (
                        <span className="text-amber-400 font-bold">{ioc.related_detections_count}</span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-center font-mono">
                      {ioc.related_alerts_count > 0 ? (
                        <span className="text-rose-400 font-bold">{ioc.related_alerts_count}</span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-center font-mono">
                      {ioc.related_incidents_count > 0 ? (
                        <span className="text-purple-400 font-bold">{ioc.related_incidents_count}</span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleOpenGraph(ioc.id)}
                        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-xs transition-colors"
                      >
                        <Layers className="w-3 h-3" />
                        <span>Inspect Graph</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Relationship Graph Modal / Drawer */}
      {selectedIocId && (
        <Modal
          isOpen={true}
          onClose={() => {
            setSelectedIocId(null);
            setGraphData(null);
          }}
          title="IOC Attribution & Relationship Graph"
          maxWidth="4xl"
        >
          {graphLoading || !graphData ? (
            <div className="p-12 flex flex-col items-center justify-center gap-3">
              <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              <p className="text-xs text-slate-400 font-mono">Tracing correlated entities across SOC graph...</p>
            </div>
          ) : (
            <div className="space-y-6">
              {/* IOC Header Box */}
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div>
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getTypeBadge(
                        graphData.ioc.ioc_type
                      )}`}
                    >
                      {graphData.ioc.ioc_type}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getClassificationBadge(
                        graphData.ioc.classification
                      )}`}
                    >
                      {graphData.ioc.classification}
                    </span>
                  </div>
                  <p className="text-base font-mono font-bold text-white mt-1.5 select-all">
                    {graphData.ioc.value}
                  </p>
                  <p className="text-xs text-slate-400 mt-1">
                    First Seen: {new Date(graphData.ioc.first_seen).toLocaleString()} • Last Seen:{" "}
                    {new Date(graphData.ioc.last_seen).toLocaleString()} • Observed Occurrences:{" "}
                    <span className="text-cyan-400 font-bold">{graphData.ioc.occurrences}</span>
                  </p>
                </div>
              </div>

              {/* Visual Pipeline Flow Chart */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Intelligence Graph Traversal
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-center text-xs">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <Activity className="w-4 h-4 text-cyan-400 mx-auto mb-1" />
                    <div className="font-bold text-white text-sm">{graphData.events.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase">Events</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <Target className="w-4 h-4 text-amber-400 mx-auto mb-1" />
                    <div className="font-bold text-white text-sm">{graphData.detections.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase">Detections</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <AlertOctagon className="w-4 h-4 text-rose-400 mx-auto mb-1" />
                    <div className="font-bold text-white text-sm">{graphData.alerts.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase">Alerts</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                    <Briefcase className="w-4 h-4 text-purple-400 mx-auto mb-1" />
                    <div className="font-bold text-white text-sm">{graphData.incidents.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase">Incidents</div>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 col-span-2 sm:col-span-1">
                    <Laptop className="w-4 h-4 text-emerald-400 mx-auto mb-1" />
                    <div className="font-bold text-white text-sm">{graphData.endpoints.length}</div>
                    <div className="text-[10px] text-slate-400 uppercase">Endpoints</div>
                  </div>
                </div>
              </div>

              {/* Related Incidents & Alerts */}
              {(graphData.incidents || []).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-purple-400 mb-2 flex items-center gap-1.5">
                    <Briefcase className="w-3.5 h-3.5" />
                    Correlated Incidents
                  </h4>
                  <div className="space-y-2">
                    {(graphData.incidents || []).map((inc) => (
                      <div
                        key={inc.id}
                        className="p-2.5 rounded-lg bg-slate-950 border border-purple-900/50 flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-purple-300">{inc.incident_number}</span>
                          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase text-[10px]">
                            {inc.status}
                          </span>
                        </div>
                        <Link
                          to={`/incidents/${inc.id}`}
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          View Incident <ExternalLink className="w-3 h-3" />
                        </Link>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Related Alerts */}
              {(graphData.alerts || []).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-rose-400 mb-2 flex items-center gap-1.5">
                    <AlertOctagon className="w-3.5 h-3.5" />
                    Associated SOC Alerts
                  </h4>
                  <div className="space-y-2 max-h-36 overflow-y-auto">
                    {(graphData.alerts || []).map((a) => (
                      <div
                        key={a.id}
                        className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                      >
                        <div>
                          <div className="font-medium text-white">{a.title}</div>
                          <div className="text-[10px] text-slate-500">
                            Raised at {new Date(a.created_at).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                            {a.status}
                          </span>
                          <Link
                            to="/alerts"
                            className="text-cyan-400 hover:underline flex items-center gap-1"
                          >
                            View <ExternalLink className="w-3 h-3" />
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Correlated Detections */}
              {(graphData.detections || []).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-amber-400 mb-2 flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5" />
                    Correlated Detections
                  </h4>
                  <div className="space-y-2 max-h-36 overflow-y-auto">
                    {(graphData.detections || []).map((det) => (
                      <div
                        key={det.id}
                        className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                      >
                        <div>
                          <div className="font-medium text-white">{det.rule_title}</div>
                          <div className="text-[10px] text-slate-500">
                            Triggered at {new Date(det.timestamp).toLocaleString()}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-950/60 text-amber-300 border border-amber-800/40">
                            {det.severity}
                          </span>
                          <Link
                            to="/detections"
                            className="text-cyan-400 hover:underline flex items-center gap-1"
                          >
                            View <ExternalLink className="w-3 h-3" />
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Matching Endpoints */}
              {(graphData.endpoints || []).length > 0 && (
                <div>
                  <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-400 mb-2 flex items-center gap-1.5">
                    <Laptop className="w-3.5 h-3.5" />
                    Enrolled Endpoints
                  </h4>
                  <div className="space-y-2">
                    {(graphData.endpoints || []).map((ep) => (
                      <div
                        key={ep.id}
                        className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-white">{ep.hostname}</span>
                          <span className="font-mono text-slate-400">({ep.ip_address})</span>
                          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 text-[10px]">
                            {ep.status}
                          </span>
                        </div>
                        <Link
                          to={`/endpoints/${ep.id}`}
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          View Endpoint <ExternalLink className="w-3 h-3" />
                        </Link>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Recent Raw Events */}
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 mb-2 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Recent Telemetry Events ({(graphData.events || []).length})
                </h4>
                {(graphData.events || []).length === 0 ? (
                  <p className="text-xs text-slate-500">No raw events correlated.</p>
                ) : (
                  <div className="space-y-1.5 max-h-48 overflow-y-auto">
                    {(graphData.events || []).map((ev) => (
                      <div
                        key={ev.id}
                        className="p-2 rounded bg-slate-950 border border-slate-800/80 font-mono text-[11px] text-slate-300"
                      >
                        <div className="flex justify-between text-slate-500 text-[10px]">
                          <span>{new Date(ev.timestamp).toLocaleTimeString()}</span>
                          <span className="text-cyan-400">{ev.event_type}</span>
                        </div>
                        <p className="truncate text-slate-300 mt-0.5">{ev.raw_snippet || "Event record"}</p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </Modal>
      )}
      </div>
    </div>
  );
};
