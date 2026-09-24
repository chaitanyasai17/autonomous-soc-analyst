import React, { useState, useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import {
  GitCommit,
  CheckCircle2,
  AlertOctagon,
  Clock,
  ArrowRight,
  Shield,
  Target,
  Gauge,
  Briefcase,
  FileText,
  Fingerprint,
  RefreshCw,
  Search,
  Layers,
  ChevronDown,
  ChevronRight,
  Activity,
  Globe,
  ExternalLink,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";

interface TraceStage {
  stage: string;
  name: string;
  status: string;
  timestamp: string | null;
  summary: string;
  entity_id: string;
  details: Record<string, any>;
}

interface PipelineTraceData {
  queried_type: string;
  queried_id: string;
  stages_count: number;
  stages: TraceStage[];
  iocs: Array<{ type: string; value: string; confidence: number }>;
  provenance: {
    has_telemetry_source: boolean;
    has_normalized_event: boolean;
    has_detection: boolean;
    has_risk_assessment: boolean;
    has_alert: boolean;
    has_incident: boolean;
  };
}

export const PipelineTrace: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const { showToast } = useToast();

  const [selectedType, setSelectedType] = useState<string>(
    searchParams.get("type") || "incident"
  );
  const [selectedId, setSelectedId] = useState<string>(
    searchParams.get("id") || ""
  );

  const [loading, setLoading] = useState<boolean>(false);
  const [traceData, setTraceData] = useState<PipelineTraceData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedStages, setExpandedStages] = useState<Set<number>>(new Set([0, 1, 2, 3, 4]));

  // Quick pick items
  const [recentItems, setRecentItems] = useState<Array<{ id: string; label: string; type: string }>>([]);
  const [loadingRecent, setLoadingRecent] = useState<boolean>(false);

  // Load recent entities for quick selection
  const loadRecentEntities = async (type: string) => {
    setLoadingRecent(true);
    try {
      let endpoint = "";
      switch (type) {
        case "incident":
          endpoint = "/incidents?limit=8";
          break;
        case "alert":
          endpoint = "/alerts?limit=8";
          break;
        case "detection":
          endpoint = "/detections?limit=8";
          break;
        case "log":
          endpoint = "/logs?limit=8";
          break;
        case "scan":
          endpoint = "/web-security/scans?limit=8";
          break;
        default:
          endpoint = "/incidents?limit=8";
      }

      const res = await api.get(endpoint);
      const raw = res.data;
      const items: any[] = Array.isArray(raw?.data)
        ? raw.data
        : Array.isArray(raw?.items)
        ? raw.items
        : Array.isArray(raw?.data?.items)
        ? raw.data.items
        : Array.isArray(raw)
        ? raw
        : [];

      const mapped = items.map((item: any) => {
        let label = item.id;
        if (type === "incident") label = `${item.incident_number || "INC"} - ${item.title}`;
        else if (type === "alert") label = `${item.title} (${item.severity})`;
        else if (type === "detection") label = `${item.rule_title || item.matched_rule}`;
        else if (type === "log") label = `${item.original_filename} (${item.event_count || 0} events)`;
        else if (type === "scan") label = `${item.target_host} - Score: ${item.posture_score}/100`;

        return { id: item.id, label, type };
      });
      setRecentItems(mapped);

      // If no ID is currently selected, pick the first recent item automatically
      if (!selectedId && mapped.length > 0) {
        setSelectedId(mapped[0].id);
        fetchTraceFor(type, mapped[0].id);
      }
    } catch (e) {
      console.warn("Could not load recent entities for picker", e);
    } finally {
      setLoadingRecent(false);
    }
  };

  const fetchTraceFor = async (type: string, id: string) => {
    if (!id.trim()) {
      showToast("Please specify or select an entity ID to trace.", "warning");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.get(`/pipeline/trace/${type}/${id.trim()}`);
      if (res.data?.data) {
        setTraceData(res.data.data);
        setSearchParams({ type, id: id.trim() });
      }
    } catch (err: any) {
      const msg = err.response?.data?.message || err.response?.data?.detail || "Failed to load pipeline trace.";
      setError(msg);
      setTraceData(null);
      showToast(msg, "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRecentEntities(selectedType);
  }, [selectedType]);

  useEffect(() => {
    const initialId = searchParams.get("id");
    const initialType = searchParams.get("type");
    if (initialId && initialType) {
      setSelectedType(initialType);
      setSelectedId(initialId);
      fetchTraceFor(initialType, initialId);
    }
  }, []);

  const toggleStageExpand = (idx: number) => {
    const next = new Set(expandedStages);
    if (next.has(idx)) {
      next.delete(idx);
    } else {
      next.add(idx);
    }
    setExpandedStages(next);
  };

  const getStageIcon = (stage: string) => {
    switch (stage) {
      case "INGESTION":
      case "ASSESSMENT":
        return FileText;
      case "PARSING":
        return GitCommit;
      case "DETECTION":
        return Target;
      case "RISK_ASSESSMENT":
        return Gauge;
      case "ALERT":
        return AlertOctagon;
      case "INCIDENT":
        return Briefcase;
      default:
        return Shield;
    }
  };

  const getStageColor = (stage: string) => {
    switch (stage) {
      case "INGESTION":
      case "ASSESSMENT":
        return "text-cyan-400 bg-cyan-950/60 border-cyan-800/60";
      case "PARSING":
        return "text-blue-400 bg-blue-950/60 border-blue-800/60";
      case "DETECTION":
        return "text-purple-400 bg-purple-950/60 border-purple-800/60";
      case "RISK_ASSESSMENT":
        return "text-amber-400 bg-amber-950/60 border-amber-800/60";
      case "ALERT":
        return "text-orange-400 bg-orange-950/60 border-orange-800/60";
      case "INCIDENT":
        return "text-rose-400 bg-rose-950/60 border-rose-800/60";
      default:
        return "text-emerald-400 bg-emerald-950/60 border-emerald-800/60";
    }
  };

  const getStageRoute = (stage: string, entityId: string) => {
    switch (stage) {
      case "INGESTION":
        return `/logs/${entityId}`;
      case "DETECTION":
        return `/detections`;
      case "RISK_ASSESSMENT":
        return `/risk`;
      case "ALERT":
        return `/alerts`;
      case "INCIDENT":
        return `/incidents/${entityId}`;
      case "ASSESSMENT":
        return `/web-security`;
      default:
        return null;
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with dataflow lines */}
      <CyberGridBackground variant="pipeline" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="SOC Pipeline Trace"
        tagline="TELEMETRY EXECUTION FLOW"
        subtitle="Trace security telemetry through detection, risk, and response."
        icon={GitCommit}
        badge={{ label: "PROVENANCE AUDIT", variant: "primary", pulse: true }}
        actions={
          <button
            onClick={() => fetchTraceFor(selectedType, selectedId)}
            disabled={loading || !selectedId}
            className="flex items-center gap-2 px-3 py-2 cyber-panel-subtle hover:bg-[#0c244d] border border-[#1E3A8A]/50 text-slate-200 hover:text-cyan-300 rounded-xl text-sm transition-colors font-mono disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            Refresh Trace
          </button>
        }
      />

      {/* Selector Ribbon */}
      <div className="cyber-panel rounded-xl p-4 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-3 items-center">
          <div className="md:col-span-3">
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Source Object Type
            </label>
            <select
              value={selectedType}
              onChange={(e) => {
                setSelectedType(e.target.value);
                setSelectedId("");
              }}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 text-slate-200 text-sm rounded-lg focus:outline-none focus:border-cyan-500"
            >
              <option value="incident">Incident</option>
              <option value="alert">SOC Alert</option>
              <option value="detection">Sigma Detection</option>
              <option value="log">Telemetry File</option>
              <option value="scan">Security Scan</option>
            </select>
          </div>

          <div className="md:col-span-7">
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
              Object UUID / Target ID
            </label>
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
              <input
                type="text"
                value={selectedId}
                onChange={(e) => setSelectedId(e.target.value)}
                placeholder="Enter or paste UUID (e.g. e87f8b9e-4a6c-48c2-a4e9...)"
                className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-700 text-slate-200 text-sm font-mono rounded-lg focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          <div className="md:col-span-2 flex items-end">
            <button
              onClick={() => fetchTraceFor(selectedType, selectedId)}
              disabled={loading || !selectedId.trim()}
              className="w-full px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold text-sm rounded-lg transition-colors flex items-center justify-center gap-2"
            >
              {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Layers className="w-4 h-4" />}
              Trace Object
            </button>
          </div>
        </div>

        {/* Quick select chips */}
        {(recentItems || []).length > 0 && (
          <div className="pt-3 border-t border-slate-800">
            <div className="text-xs text-slate-400 font-medium mb-2 flex items-center gap-2">
              <span>Recent {selectedType}s in database (click to trace):</span>
              {loadingRecent && <RefreshCw className="w-3 h-3 animate-spin text-cyan-400" />}
            </div>
            <div className="flex flex-wrap gap-2">
              {(recentItems || []).map((item) => (
                <button
                  key={item.id}
                  onClick={() => {
                    setSelectedId(item.id);
                    fetchTraceFor(selectedType, item.id);
                  }}
                  className={`text-xs px-2.5 py-1 rounded-lg border transition-all truncate max-w-xs ${
                    selectedId === item.id
                      ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-300 font-semibold"
                      : "bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
                  }`}
                  title={item.label}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Main Content Area */}
      {loading ? (
        <div className="p-16 text-center bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto mb-3" />
          <p className="text-slate-300 font-medium">Reconstructing provenance graph across 7 database entities...</p>
          <p className="text-slate-500 text-xs mt-1">Connecting SecurityLog &rarr; ParsedLog &rarr; SigmaDetection &rarr; RiskAssessment &rarr; Alert &rarr; Incident</p>
        </div>
      ) : error ? (
        <div className="p-10 bg-slate-900/80 border border-red-500/30 rounded-xl text-center">
          <AlertOctagon className="w-10 h-10 text-red-400 mx-auto mb-2" />
          <p className="text-red-300 font-semibold text-base">{error}</p>
          <p className="text-slate-400 text-xs mt-1">Make sure the UUID exists in your database and matches the selected object type.</p>
        </div>
      ) : traceData ? (
        <div className="space-y-6">
          {/* Provenance Verification Checklist */}
          <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-3 flex items-center justify-between">
              <span>Pipeline Provenance Integrity</span>
              <span className="text-cyan-400 font-mono">
                {traceData.stages_count} Active Stages Verified
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
              {[
                { label: "Telemetry Source", active: traceData.provenance?.has_telemetry_source },
                { label: "Normalized Event", active: traceData.provenance?.has_normalized_event },
                { label: "Sigma / AST Rule", active: traceData.provenance?.has_detection },
                { label: "Deterministic Risk", active: traceData.provenance?.has_risk_assessment },
                { label: "SOC Alert", active: traceData.provenance?.has_alert },
                { label: "Correlated Incident", active: traceData.provenance?.has_incident },
              ].map((item, idx) => (
                <div
                  key={idx}
                  className={`p-2.5 rounded-lg border text-center transition-all ${
                    item.active
                      ? "bg-emerald-950/30 border-emerald-800/50 text-emerald-300"
                      : "bg-slate-950 border-slate-800 text-slate-500"
                  }`}
                >
                  <CheckCircle2
                    className={`w-4 h-4 mx-auto mb-1 ${
                      item.active ? "text-emerald-400" : "text-slate-600"
                    }`}
                  />
                  <div className="text-[11px] font-medium leading-tight">{item.label}</div>
                  <div className="text-[10px] font-mono mt-0.5 opacity-80">
                    {item.active ? "VERIFIED" : "SKIPPED"}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Connected IOCs */}
          {traceData.iocs && (traceData.iocs || []).length > 0 && (
            <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
                <Fingerprint className="w-4 h-4 text-cyan-400" />
                <span>Correlated Threat Artifacts ({(traceData.iocs || []).length})</span>
              </div>
              <div className="flex flex-wrap gap-2">
                {(traceData.iocs || []).map((ioc, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300"
                  >
                    <span className="text-cyan-400 font-bold uppercase text-[10px]">{ioc.type}:</span>
                    <span>{ioc.value}</span>
                    <span className="text-slate-500 text-[10px]">({Math.round((ioc.confidence || 0) * 100)}%)</span>
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Stepper Pipeline Visualization */}
          <div className="relative pl-6 md:pl-8 space-y-6 before:absolute before:left-3 md:before:left-4 before:top-4 before:bottom-4 before:w-0.5 before:bg-slate-800">
            {(traceData.stages || []).map((st, idx) => {
              const IconComponent = getStageIcon(st.stage);
              const colorClasses = getStageColor(st.stage);
              const isExpanded = expandedStages.has(idx);

              return (
                <div key={idx} className="relative group">
                  {/* Step Icon Badge */}
                  <div
                    className={`absolute -left-6 md:-left-8 top-3.5 w-6 h-6 rounded-full border flex items-center justify-center ${colorClasses}`}
                  >
                    <IconComponent className="w-3.5 h-3.5" />
                  </div>

                  {/* Stage Card */}
                  <div className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition-all">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span
                          className={`text-xs px-2.5 py-0.5 rounded-md font-semibold border ${colorClasses}`}
                        >
                          Stage {idx + 1}: {st.name}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono">
                          {st.status}
                        </span>
                      </div>

                      <div className="text-xs text-slate-400 flex items-center gap-1 font-mono">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {st.timestamp ? new Date(st.timestamp).toLocaleString() : "Real-time stream"}
                      </div>
                    </div>

                    <div className="mt-2 text-sm text-slate-100 font-medium">
                      {st.summary}
                    </div>

                    <div className="mt-1 text-xs text-slate-400 font-mono flex items-center gap-2 flex-wrap">
                      <span className="text-slate-500">Object ID:</span>
                      {getStageRoute(st.stage, st.entity_id) ? (
                        <button
                          type="button"
                          onClick={() => navigate(getStageRoute(st.stage, st.entity_id)!)}
                          className="text-cyan-400 hover:text-cyan-300 font-bold hover:underline inline-flex items-center gap-1 group"
                          title="Open related live record"
                        >
                          <span>{st.entity_id}</span>
                          <ExternalLink className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition" />
                        </button>
                      ) : (
                        <span className="text-slate-300">{st.entity_id}</span>
                      )}
                    </div>

                    {/* Expand Details Toggle */}
                    {Object.keys(st.details || {}).length > 0 && (
                      <div className="mt-3 pt-2 border-t border-slate-800">
                        <button
                          onClick={() => toggleStageExpand(idx)}
                          className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium transition-colors"
                        >
                          {isExpanded ? (
                            <>
                              <ChevronDown className="w-3.5 h-3.5" />
                              Hide Technical Metadata
                            </>
                          ) : (
                            <>
                              <ChevronRight className="w-3.5 h-3.5" />
                              View Technical Metadata ({Object.keys(st.details || {}).length} attributes)
                            </>
                          )}
                        </button>

                        {isExpanded && (
                          <div className="mt-2 p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                            <pre>{JSON.stringify(st.details, null, 2)}</pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="p-16 text-center bg-slate-900/80 border border-slate-800 rounded-xl">
          <GitCommit className="w-12 h-12 text-slate-600 mx-auto mb-3" />
          <p className="text-slate-300 font-medium text-base">Select an object to trace its end-to-end lifecycle</p>
          <p className="text-slate-500 text-xs mt-1">
            Choose an Incident, Alert, Detection, Telemetry Log, or Web Scan above to reconstruct its multi-stage graph.
          </p>
        </div>
      )}
      </div>
    </div>
  );
};
