import React, { useEffect, useState } from "react";
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
} from "lucide-react";
import { Modal } from "./Modal";
import { api } from "../../services/api";

interface PipelineTraceModalProps {
  isOpen: boolean;
  onClose: () => void;
  objectType: string;
  objectId: string | null;
}

interface TraceStage {
  stage: string;
  name: string;
  status: string;
  timestamp: string | null;
  summary: string;
  entity_id: string;
  details: Record<string, any>;
}

export const PipelineTraceModal: React.FC<PipelineTraceModalProps> = ({
  isOpen,
  onClose,
  objectType,
  objectId,
}) => {
  const [loading, setLoading] = useState<boolean>(false);
  const [traceData, setTraceData] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!isOpen || !objectId) {
      setTraceData(null);
      setError(null);
      return;
    }

    const fetchTrace = async () => {
      setLoading(true);
      setError(null);
      try {
        const res = await api.get(`/pipeline/trace/${objectType}/${objectId}`);
        if (res.data?.data) {
          setTraceData(res.data.data);
        }
      } catch (err: any) {
        setError(err.response?.data?.message || "Failed to load pipeline trace provenance.");
      } finally {
        setLoading(false);
      }
    };

    fetchTrace();
  }, [isOpen, objectType, objectId]);

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
        return "text-red-400 bg-red-950/60 border-red-800/60";
      case "RISK_ASSESSMENT":
        return "text-yellow-400 bg-yellow-950/60 border-yellow-800/60";
      case "ALERT":
        return "text-amber-400 bg-amber-950/60 border-amber-800/60";
      case "INCIDENT":
        return "text-rose-400 bg-rose-950/60 border-rose-800/60";
      default:
        return "text-slate-400 bg-slate-900 border-slate-700";
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="End-to-End SOC Pipeline Provenance Trace"
      maxWidth="4xl"
    >
      <div className="space-y-6">
        {/* Header Description */}
        <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 text-xs text-slate-300">
          <p>
            Deterministic provenance chain tracing raw telemetry ingestion, Sigma AST evaluations,
            multi-factor risk assessments, SOC alerts, and incident resolution.
          </p>
          <div className="mt-2 flex items-center gap-4 text-[11px] font-mono text-slate-400">
            <span>Root Object: <strong className="text-cyan-400 uppercase">{objectType}</strong></span>
            <span>•</span>
            <span className="truncate max-w-sm">ID: <strong className="text-slate-200">{objectId}</strong></span>
          </div>
        </div>

        {loading && (
          <div className="py-12 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Traversing Relational Provenance Graph...
            </p>
          </div>
        )}

        {error && (
          <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 text-xs text-red-300">
            {error}
          </div>
        )}

        {traceData && traceData.stages && (
          <div className="space-y-4">
            <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-800">
              {traceData.stages.map((stage: TraceStage, idx: number) => {
                const Icon = getStageIcon(stage.stage);
                const colorClasses = getStageColor(stage.stage);
                return (
                  <div key={idx} className="relative group">
                    {/* Node Dot */}
                    <div className={`absolute -left-6 top-1 w-5 h-5 rounded-full border flex items-center justify-center ${colorClasses}`}>
                      <Icon className="w-2.5 h-2.5" />
                    </div>

                    {/* Stage Card */}
                    <div className="p-4 rounded-xl bg-slate-950 border border-slate-800/90 shadow-sm space-y-2 hover:border-slate-700 transition">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-white uppercase tracking-wide">
                            {stage.name}
                          </span>
                          <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-slate-900 border border-slate-700 text-slate-300">
                            {stage.status}
                          </span>
                        </div>
                        {stage.timestamp && (
                          <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {new Date(stage.timestamp).toLocaleString()}
                          </span>
                        )}
                      </div>

                      <p className="text-xs text-slate-300">{stage.summary}</p>

                      {/* Detail Pill Badges */}
                      <div className="flex flex-wrap gap-2 pt-1 text-[11px] font-mono">
                        {Object.entries(stage.details || {}).map(([k, v]) => {
                          if (v === null || v === undefined || typeof v === "object") return null;
                          return (
                            <span
                              key={k}
                              className="px-2 py-0.5 rounded bg-slate-900/80 border border-slate-800 text-slate-400"
                            >
                              <span className="text-slate-500">{k}:</span>{" "}
                              <strong className="text-slate-200">{String(v)}</strong>
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Related IOCs if available */}
            {traceData.iocs && traceData.iocs.length > 0 && (
              <div className="mt-4 p-4 rounded-xl bg-slate-950 border border-slate-800">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 mb-2.5">
                  <Fingerprint className="w-4 h-4 text-cyan-400" />
                  Correlated Threat Intelligence IOCs ({traceData.iocs.length})
                </label>
                <div className="flex flex-wrap gap-2">
                  {traceData.iocs.map((ioc: any, idx: number) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-cyan-300"
                    >
                      <span className="text-slate-500 text-[10px] uppercase mr-1.5">{ioc.type}:</span>
                      {ioc.value}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        <div className="pt-3 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 transition"
          >
            Close Trace
          </button>
        </div>
      </div>
    </Modal>
  );
};
