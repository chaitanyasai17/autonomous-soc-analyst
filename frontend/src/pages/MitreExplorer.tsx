import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Network,
  ExternalLink,
  RefreshCw,
  Layers,
  ShieldAlert,
  Search,
  Target,
  AlertOctagon,
  ArrowRight,
  BookOpen,
} from "lucide-react";
import { api } from "../services/api";
import { MitreMatrixData, MitreTechnique } from "../types";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";

export const MitreExplorer: React.FC = () => {
  const [matrix, setMatrix] = useState<MitreMatrixData | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [activeTechnique, setActiveTechnique] = useState<MitreTechnique | null>(null);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const fetchMatrix = async () => {
    setIsLoading(true);
    try {
      const res = await api.get("/mitre/matrix");
      if (res.data?.data) {
        setMatrix(res.data.data);
      }
    } catch (err: any) {
      toastError("Failed to load MITRE ATT&CK matrix.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchMatrix();
  }, []);

  const handleSeed = async () => {
    try {
      const res = await api.post("/mitre/seed");
      success(res.data?.message || "MITRE catalog synchronized.");
      fetchMatrix();
    } catch (err: any) {
      toastError("Seeding failed.");
    }
  };

  // Filter columns and techniques by search query
  const filteredTactics = (matrix?.tactics || []).map((col) => {
    if (!searchQuery.trim()) return col;
    const lower = searchQuery.toLowerCase();
    const matchesTechniques = (col.techniques || []).filter(
      (t) =>
        (t.technique_id || "").toLowerCase().includes(lower) ||
        (t.technique_name || "").toLowerCase().includes(lower) ||
        (t.description || "").toLowerCase().includes(lower)
    );
    return {
      ...col,
      techniques: matchesTechniques,
    };
  });

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with network nodes */}
      <CyberGridBackground variant="mitre" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
        <SOCPageHeader
        title="MITRE ATT&CK Coverage"
        tagline="ADVERSARY MATRIX COVERAGE"
        subtitle="Map observed detections to adversary tactics and techniques."
        icon={Network}
        badge={{ label: `${matrix?.total_techniques ?? 0} TECHNIQUES INDEXED`, variant: "primary", pulse: true }}
        actions={
          <div className="flex items-center gap-2.5">
            <SOCButton
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              loading={isLoading}
              onClick={fetchMatrix}
            >
              Refresh Matrix
            </SOCButton>
            <SOCButton
              variant="primary"
              size="sm"
              icon={Layers}
              onClick={handleSeed}
            >
              Sync ATT&CK Catalog
            </SOCButton>
          </div>
        }
      />

      {/* Summary KPI Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <SOCStatCard
          label="Tactics Covered"
          value={matrix?.total_tactics ?? 0}
          icon={Layers}
          variant="cyan"
          subtitle="Enterprise ATT&CK categories"
        />

        <SOCStatCard
          label="Techniques Indexed"
          value={matrix?.total_techniques ?? 0}
          icon={Network}
          variant="purple"
          subtitle="Techniques in reference catalog"
        />

        <SOCStatCard
          label="Distinct Detections Mapped"
          value={matrix?.total_detections_mapped ?? 0}
          icon={ShieldAlert}
          variant="danger"
          subtitle="Unique detection records with MITRE tags"
        />
      </div>

      {/* Matrix Search & Filter Bar */}
      <div className="cyber-panel p-3.5 rounded-xl flex items-center gap-3 backdrop-blur-md">
        <Search className="w-4 h-4 text-cyan-400 shrink-0" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter techniques by ID (e.g. T1059), name, or keyword..."
          className="bg-transparent text-xs text-white placeholder-slate-500 flex-1 focus:outline-none font-mono"
        />
        {searchQuery && (
          <button
            onClick={() => setSearchQuery("")}
            className="text-xs text-slate-400 hover:text-cyan-300 font-mono"
          >
            Clear
          </button>
        )}
      </div>

      {/* Matrix Horizontal Scrollboard */}
      <div className="cyber-panel rounded-2xl p-5 overflow-x-auto">
        <div className="flex gap-4 min-w-[1400px] pb-4">
          {filteredTactics.map((col) => (
            <div key={col.tactic.id} className="w-64 shrink-0 flex flex-col">
              {/* Tactic Column Header */}
              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 mb-3 shadow-md">
                <span className="text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider block">
                  {col.tactic.id}
                </span>
                <h4 className="text-xs font-bold text-white mt-0.5 truncate">{col.tactic.name}</h4>
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2 pt-2 border-t border-slate-800 font-mono">
                  <span>{col.techniques.length} techs</span>
                  <span className={col.tactic.active_detections_count > 0 ? "text-red-400 font-bold" : ""}>
                    {col.tactic.active_detections_count} hits
                  </span>
                </div>
              </div>

              {/* Techniques Cards */}
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {col.techniques.length === 0 ? (
                  <p className="text-[11px] text-slate-600 text-center py-4">No matching techniques</p>
                ) : (
                  col.techniques.map((tech) => {
                    const hasHits = (tech.detection_count || 0) > 0;
                    return (
                      <div
                        key={tech.id}
                        onClick={() => setActiveTechnique(tech)}
                        className={`p-3 rounded-xl border text-left cursor-pointer transition-all duration-150 ${
                          hasHits
                            ? "bg-red-950/40 border-red-500/50 hover:border-red-400 shadow-md shadow-red-950/30"
                            : "bg-slate-950 border-slate-800 hover:border-slate-700 hover:bg-slate-900"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className="text-[10px] font-mono font-bold text-cyan-400">
                            {tech.technique_id}
                          </span>
                          {hasHits && (
                            <span className="px-1.5 py-0.2 rounded bg-red-600 text-white font-mono text-[9px] font-black animate-pulse">
                              {tech.detection_count} HITS
                            </span>
                          )}
                        </div>
                        <div className="text-xs font-semibold text-slate-200 line-clamp-2">
                          {tech.technique_name}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique Detail Modal */}
      <Modal
        isOpen={!!activeTechnique}
        onClose={() => setActiveTechnique(null)}
        title="MITRE ATT&CK Technique Intel"
        maxWidth="2xl"
      >
        {activeTechnique && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-mono text-cyan-400 font-bold">
                  {activeTechnique.technique_id} • Tactic: {activeTechnique.tactic}
                </span>
                {activeTechnique.detection_count ? (
                  <span className="px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-300 font-mono text-xs font-bold">
                    {activeTechnique.detection_count} Active Detection(s)
                  </span>
                ) : (
                  <span className="text-xs text-slate-500 font-mono">No active detections</span>
                )}
              </div>
              <h3 className="text-base font-bold text-white mb-2">{activeTechnique.technique_name}</h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                {activeTechnique.description || "Adversary technique indexed in MITRE ATT&CK Enterprise Matrix."}
              </p>
            </div>

            {/* External Reference & Actions */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                onClick={() => {
                  setActiveTechnique(null);
                  navigate("/detections");
                }}
                className="p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 flex items-center justify-between text-left transition-all"
              >
                <div>
                  <p className="text-xs font-bold text-white flex items-center gap-1.5">
                    <Target className="w-3.5 h-3.5 text-cyan-400" />
                    Inspect Telemetry Hits
                  </p>
                  <p className="text-[11px] text-slate-400 mt-0.5">Browse matched detections</p>
                </div>
                <ArrowRight className="w-4 h-4 text-cyan-400" />
              </button>

              <button
                onClick={() => {
                  setActiveTechnique(null);
                  navigate("/alerts");
                }}
                className="p-3 rounded-xl bg-slate-950 border border-slate-800 hover:border-red-500/50 flex items-center justify-between text-left transition-all"
              >
                <div>
                  <p className="text-xs font-bold text-white flex items-center gap-1.5">
                    <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
                    Active Alerts Queue
                  </p>
                  <p className="text-[11px] text-slate-400 mt-0.5">Triage associated security alerts</p>
                </div>
                <ArrowRight className="w-4 h-4 text-red-400" />
              </button>
            </div>

            <div className="pt-2 flex items-center justify-between border-t border-slate-800">
              <a
                href={activeTechnique.reference_url || `https://attack.mitre.org/techniques/${activeTechnique.technique_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-semibold"
              >
                <BookOpen className="w-3.5 h-3.5" />
                <span>Official MITRE ATT&CK Documentation</span>
                <ExternalLink className="w-3 h-3 ml-0.5" />
              </a>

              <button
                onClick={() => setActiveTechnique(null)}
                className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300"
              >
                Close
              </button>
            </div>
          </div>
        )}
      </Modal>
      </div>
    </div>
  );
};
