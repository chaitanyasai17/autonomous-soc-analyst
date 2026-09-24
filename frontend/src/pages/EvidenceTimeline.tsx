import React, { useState, useEffect, useMemo } from "react";
import { Link } from "react-router-dom";
import {
  Clock,
  Filter,
  Search,
  RefreshCw,
  Layers,
  ShieldAlert,
  AlertTriangle,
  FileText,
  Activity,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Laptop,
  CheckCircle2,
  Lock,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";

interface TimelineEntry {
  id: string;
  timestamp: string;
  stage: string;
  event_type: string;
  source: string;
  object_id: string;
  severity: "low" | "medium" | "high" | "critical" | "info";
  description: string;
  related_endpoint?: string;
  related_alert?: string;
  related_detection?: string;
  related_incident?: string;
  details: Record<string, any>;
}

export const EvidenceTimeline: React.FC = () => {
  const { showToast } = useToast();

  const [loading, setLoading] = useState(true);
  const [entries, setEntries] = useState<TimelineEntry[]>([]);
  const [totalEvents, setTotalEvents] = useState(0);

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [stageFilter, setStageFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [limit, setLimit] = useState(100);

  // Expanded card state
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set());

  const fetchTimeline = async () => {
    setLoading(true);
    try {
      const params: Record<string, any> = { limit };
      const res = await api.get("/timeline", { params });
      if (res.data?.success && res.data?.data) {
        setEntries(res.data.data.timeline || []);
        setTotalEvents(res.data.data.total_events || 0);
      }
    } catch (err: any) {
      showToast(err.response?.data?.detail || "Failed to load evidence timeline", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [limit]);

  const toggleExpand = (id: string) => {
    const next = new Set(expandedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    setExpandedIds(next);
  };

  const getStageColor = (stage: string) => {
    switch (stage.toUpperCase()) {
      case "INGESTION":
        return "bg-blue-500/20 text-blue-400 border-blue-500/30";
      case "NORMALIZATION":
        return "bg-cyan-500/20 text-cyan-400 border-cyan-500/30";
      case "DETECTION":
        return "bg-purple-500/20 text-purple-400 border-purple-500/30";
      case "RISK":
        return "bg-amber-500/20 text-amber-400 border-amber-500/30";
      case "ALERT":
        return "bg-orange-500/20 text-orange-400 border-orange-500/30";
      case "INCIDENT":
        return "bg-rose-500/20 text-rose-400 border-rose-500/30";
      case "CONTAINMENT":
        return "bg-red-500/20 text-red-300 border-red-500/40";
      case "TRIAGE":
        return "bg-emerald-500/20 text-emerald-400 border-emerald-500/30";
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500/30";
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case "critical":
        return "bg-red-500/20 text-red-400 border-red-500/40";
      case "high":
        return "bg-orange-500/20 text-orange-400 border-orange-500/40";
      case "medium":
        return "bg-amber-500/20 text-amber-400 border-amber-500/40";
      case "low":
        return "bg-blue-500/20 text-blue-400 border-blue-500/40";
      default:
        return "bg-gray-500/20 text-gray-400 border-gray-500/40";
    }
  };

  const getEntityLink = (entry: TimelineEntry) => {
    switch (entry.stage.toUpperCase()) {
      case "INGESTION":
      case "NORMALIZATION":
        return entry.object_id ? `/logs/${entry.object_id}` : "/logs";
      case "DETECTION":
        return "/detections";
      case "RISK":
        return "/risk";
      case "ALERT":
        return "/alerts";
      case "INCIDENT":
        return entry.object_id ? `/incidents/${entry.object_id}` : "/incidents";
      default:
        return null;
    }
  };

  const sortedAndFilteredEntries = useMemo(() => {
    return (entries || [])
      .filter((e) => {
        if (!e) return false;
        if (stageFilter !== "all" && (e.stage || "").toUpperCase() !== stageFilter.toUpperCase()) {
          return false;
        }
        if (severityFilter !== "all" && (e.severity || "").toLowerCase() !== severityFilter.toLowerCase()) {
          return false;
        }
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchDesc = (e.description || "").toLowerCase().includes(q);
          const matchSrc = (e.source || "").toLowerCase().includes(q);
          const matchType = (e.event_type || "").toLowerCase().includes(q);
          const matchHost = (e.related_endpoint || "").toLowerCase().includes(q);
          if (!matchDesc && !matchSrc && !matchType && !matchHost) return false;
        }
        return true;
      })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [entries, stageFilter, severityFilter, searchQuery]);

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with chronological node line */}
      <CyberGridBackground variant="timeline" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
        <SOCPageHeader
          title="Evidence Timeline"
          tagline="CHRONOLOGICAL AUDIT FORENSICS"
          subtitle="Chronological investigation evidence and security activity."
          icon={Clock}
          badge={{ label: `${totalEvents} FORENSIC EVENTS`, variant: "primary", pulse: true }}
          actions={
            <button
              onClick={fetchTimeline}
              className="p-2 rounded-xl cyber-panel-subtle hover:bg-[#0c244d] border border-[#1E3A8A]/50 text-slate-300 hover:text-cyan-300 transition-colors"
              title="Refresh Timeline"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            </button>
          }
        />

      {/* Stats / Overview Ribbon */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SOCStatCard
          label="Total Events"
          value={totalEvents}
          icon={Layers}
          variant="cyan"
          subtitle="Full telemetry provenance"
        />

        <SOCStatCard
          label="Rule Matches"
          value={(entries || []).filter((e) => e?.stage === "DETECTION").length}
          icon={Activity}
          variant="purple"
          subtitle="Sigma AST hits"
        />

        <SOCStatCard
          label="Alerts & Incidents"
          value={(entries || []).filter((e) => e?.stage === "ALERT" || e?.stage === "INCIDENT").length}
          icon={ShieldAlert}
          variant="amber"
          subtitle="Triage & declared cases"
        />

        <SOCStatCard
          label="Containment Actions"
          value={(entries || []).filter((e) => e?.stage === "CONTAINMENT").length}
          icon={Lock}
          variant="danger"
          subtitle="Mitigation operations executed"
        />
      </div>

      {/* Filter Bar */}
      <div className="flex flex-col md:flex-row gap-3 bg-slate-900/80 p-4 border border-slate-800 rounded-xl">
        <div className="relative flex-1">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-3" />
          <input
            type="text"
            placeholder="Search forensic descriptions, sources, or endpoints..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-lg focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={stageFilter}
            onChange={(e) => setStageFilter(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-700 text-slate-300 text-sm rounded-lg focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Pipeline Stages</option>
            <option value="INGESTION">Ingestion</option>
            <option value="NORMALIZATION">Normalization</option>
            <option value="DETECTION">Detection</option>
            <option value="RISK">Risk Score</option>
            <option value="ALERT">Alert</option>
            <option value="INCIDENT">Incident</option>
            <option value="CONTAINMENT">Containment</option>
            <option value="TRIAGE">Triage</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 bg-slate-950 border border-slate-700 text-slate-300 text-sm rounded-lg focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={limit}
            onChange={(e) => setLimit(Number(e.target.value))}
            className="px-3 py-2 bg-slate-950 border border-slate-700 text-slate-300 text-sm rounded-lg focus:outline-none focus:border-cyan-500"
          >
            <option value="50">Last 50 events</option>
            <option value="100">Last 100 events</option>
            <option value="200">Last 200 events</option>
            <option value="500">Last 500 events</option>
          </select>
        </div>
      </div>

      {/* Timeline Stream */}
      {loading ? (
        <div className="p-12 text-center bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-slate-400 text-sm">Assembling chronological forensics from database records...</p>
        </div>
      ) : sortedAndFilteredEntries.length === 0 ? (
        <div className="p-12 text-center bg-slate-900/80 border border-slate-800 rounded-xl">
          <Clock className="w-12 h-12 text-slate-500 mx-auto mb-3" />
          <p className="text-slate-300 font-medium text-base">No timeline events matched your filters</p>
          <p className="text-slate-500 text-sm mt-1">Try resetting filters or ingesting more telemetry data.</p>
        </div>
      ) : (
        <div className="relative pl-6 md:pl-8 space-y-6 before:absolute before:left-3 md:before:left-4 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {sortedAndFilteredEntries.map((entry) => {
            const isExpanded = expandedIds.has(entry.id);
            const entityLink = getEntityLink(entry);
            return (
              <div key={entry.id} className="relative group">
                {/* Timeline node icon */}
                <div className="absolute -left-6 md:-left-8 top-3 w-6 h-6 rounded-full bg-slate-950 border-2 border-cyan-500/80 flex items-center justify-center">
                  <div className="w-2 h-2 rounded-full bg-cyan-400" />
                </div>

                {/* Entry Card */}
                <div className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all shadow-sm">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span
                        className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${getStageColor(
                          entry.stage
                        )}`}
                      >
                        {entry.stage}
                      </span>
                      <span
                        className={`text-xs px-2 py-0.5 rounded-md font-medium border uppercase ${getSeverityBadge(
                          entry.severity
                        )}`}
                      >
                        {entry.severity}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        {entry.event_type}
                      </span>
                      <span className="text-[11px] font-mono text-cyan-400/80 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-800/40">
                        {entry.id}
                      </span>
                    </div>

                    <div className="flex items-center gap-3">
                      {entityLink && (
                        <Link
                          to={entityLink}
                          className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors hover:underline"
                        >
                          View Record <ExternalLink className="w-3 h-3" />
                        </Link>
                      )}
                      <div className="text-xs text-slate-400 flex items-center gap-1 font-mono">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {new Date(entry.timestamp).toLocaleString()}
                      </div>
                    </div>
                  </div>

                  {/* Main Description */}
                  <div className="mt-2 text-sm text-slate-100 font-medium">
                    {entry.description}
                  </div>

                  {/* Contextual Badges */}
                  <div className="mt-2.5 flex items-center gap-3 flex-wrap text-xs text-slate-400">
                    <div className="flex items-center gap-1">
                      <span className="text-slate-500">Source:</span>
                      <span className="font-mono text-slate-300">{entry.source}</span>
                    </div>

                    {entry.related_endpoint && (
                      <Link
                        to="/endpoints"
                        className="flex items-center gap-1 text-slate-300 hover:text-cyan-300 hover:underline transition-colors"
                      >
                        <Laptop className="w-3 h-3 text-blue-400" />
                        <span>{entry.related_endpoint}</span>
                      </Link>
                    )}

                    {entry.related_detection && (
                      <Link
                        to="/detections"
                        className="flex items-center gap-1 text-purple-300 hover:text-purple-200 hover:underline transition-colors"
                      >
                        <ShieldAlert className="w-3 h-3 text-purple-400" />
                        <span>{entry.related_detection}</span>
                      </Link>
                    )}

                    {entry.related_alert && (
                      <Link
                        to="/alerts"
                        className="flex items-center gap-1 text-orange-300 hover:text-orange-200 hover:underline transition-colors"
                      >
                        <AlertTriangle className="w-3 h-3 text-orange-400" />
                        <span>{entry.related_alert}</span>
                      </Link>
                    )}

                    {entry.related_incident && (
                      <Link
                        to={entry.stage === "INCIDENT" && entry.object_id ? `/incidents/${entry.object_id}` : "/incidents"}
                        className="flex items-center gap-1 text-rose-300 hover:text-rose-200 hover:underline font-semibold transition-colors"
                      >
                        <FileText className="w-3 h-3 text-rose-400" />
                        <span>{entry.related_incident}</span>
                      </Link>
                    )}
                  </div>

                  {/* Expand / Details toggle */}
                  {Object.keys(entry.details || {}).length > 0 && (
                    <div className="mt-3 pt-2 border-t border-slate-800">
                      <button
                        onClick={() => toggleExpand(entry.id)}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
                      >
                        {isExpanded ? (
                          <>
                            <ChevronDown className="w-3.5 h-3.5" />
                            Hide Technical Evidence
                          </>
                        ) : (
                          <>
                            <ChevronRight className="w-3.5 h-3.5" />
                            Show Technical Evidence ({Object.keys(entry.details || {}).length} fields)
                          </>
                        )}
                      </button>

                      {isExpanded && (
                        <div className="mt-2 p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                          <pre>{JSON.stringify(entry.details, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
      </div>
    </div>
  );
};
