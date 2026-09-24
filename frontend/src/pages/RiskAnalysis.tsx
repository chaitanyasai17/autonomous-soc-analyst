import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Gauge,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  Info,
  SlidersHorizontal,
  Eye,
  AlertOctagon,
  Sparkles,
  ArrowRight,
  TrendingUp,
  Activity,
  Layers,
} from "lucide-react";
import { api } from "../services/api";
import { RiskAssessment, RiskLevel } from "../types";
import { SeverityBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";

export const RiskAnalysis: React.FC = () => {
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [levelFilter, setLevelFilter] = useState<string>("");
  const [stats, setStats] = useState<{ total_assessments: number; average_risk_score: number; by_level: Record<string, number> } | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isBatchScoring, setIsBatchScoring] = useState<boolean>(false);
  const [activeAssessment, setActiveAssessment] = useState<RiskAssessment | null>(null);
  const [explanationData, setExplanationData] = useState<any>(null);
  const [isExplaining, setIsExplaining] = useState<boolean>(false);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const handleOpenExplain = async (item: RiskAssessment) => {
    setActiveAssessment(item);
    setExplanationData(null);
    setIsExplaining(true);
    try {
      const res = await api.get(`/risk/explain/${item.id}`);
      if (res.data?.data) {
        setExplanationData(res.data.data);
      }
    } catch (err) {
      console.error("Failed to fetch risk explanation:", err);
    } finally {
      setIsExplaining(false);
    }
  };

  const fetchRiskData = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        skip: (page - 1) * 10,
        limit: 10,
      };
      if (levelFilter) params.level = levelFilter;

      const [statsRes, listRes] = await Promise.all([
        api.get("/risk/statistics"),
        api.get("/risk/assessments", { params }),
      ]);
      setStats(statsRes.data?.data || null);
      setAssessments(listRes.data?.data || []);
      setTotal(listRes.data?.total || 0);
    } catch (err: any) {
      toastError("Failed loading risk scoring intelligence.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRiskData();
  }, [page, levelFilter]);

  const handleBatchScore = async () => {
    setIsBatchScoring(true);
    try {
      const res = await api.post("/risk/assess-batch");
      success(`Evaluated ${res.data?.data?.assessed_count || 0} detection(s) with deterministic scoring.`);
      fetchRiskData();
    } catch (err: any) {
      toastError("Failed batch risk evaluation.");
    } finally {
      setIsBatchScoring(false);
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 85) return "text-red-400 bg-red-950/40 border-red-800/60";
    if (score >= 60) return "text-orange-400 bg-orange-950/40 border-orange-800/60";
    if (score >= 40) return "text-yellow-400 bg-yellow-950/40 border-yellow-800/60";
    return "text-emerald-400 bg-emerald-950/40 border-emerald-800/60";
  };

  const columns: Column<RiskAssessment>[] = [
    {
      header: "Risk Level",
      accessor: "risk_level",
      render: (item) => <SeverityBadge severity={item.risk_level} />,
    },
    {
      header: "Composite Risk Score",
      accessor: "risk_score",
      render: (item) => (
        <div className="flex items-baseline gap-1.5">
          <span className="font-mono text-base font-black text-white">
            {item.risk_score}
          </span>
          <span className="text-[11px] text-slate-500 font-mono">/ 100</span>
        </div>
      ),
    },
    {
      header: "Target Detection",
      accessor: "sigma_detection_id",
      render: (item) => (
        <span className="font-mono text-xs text-cyan-400 font-semibold">
          DET-{item.sigma_detection_id.substring(0, 8)}
        </span>
      ),
    },
    {
      header: "Score Rationale & Breakdown",
      accessor: "explanation",
      render: (item) => (
        <div>
          <p className="text-xs text-slate-200 line-clamp-1 max-w-md font-medium">
            {item.explanation || "Calculated by deterministic risk engine."}
          </p>
          <p className="text-[10px] text-slate-500 font-mono mt-0.5">
            Confidence: {(item.confidence * 100).toFixed(0)}% • Factors: {item.contributing_factors?.length || 0}
          </p>
        </div>
      ),
    },
    {
      header: "Evaluated At",
      accessor: "calculated_at",
      render: (item) => (
        <span className="font-mono text-xs text-slate-400">
          {new Date(item.calculated_at).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Actions",
      className: "text-right",
      render: (item) => (
        <button
          onClick={() => handleOpenExplain(item)}
          className="px-2.5 py-1 rounded-lg bg-cyan-950 border border-cyan-800/50 text-cyan-300 hover:bg-cyan-900 text-xs font-semibold flex items-center gap-1 transition-colors"
          title="Explain Score Rationale & Calculation Matrix"
        >
          <Info className="w-3.5 h-3.5 text-cyan-400" />
          Explain Score
        </button>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with threat radar */}
      <CyberGridBackground variant="risk" />

      {/* Foreground Content */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header Controls */}
      <SOCPageHeader
        title="Risk Analysis"
        tagline="EXPLAINABLE RISK ENGINE"
        subtitle="Deterministic risk scoring and explainable security assessment."
        icon={Gauge}
        badge={{ label: "DETERMINISTIC EVALUATION", variant: "warning", pulse: true }}
        actions={
          <SOCButton
            variant="warning"
            size="sm"
            icon={RefreshCw}
            loading={isBatchScoring}
            onClick={handleBatchScore}
          >
            Batch Score Unassessed
          </SOCButton>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <SOCStatCard
          label="Total Risk Assessments"
          value={stats?.total_assessments ?? 0}
          subtitle="Processed threat detections"
          icon={ShieldCheck}
          variant="cyan"
        />
        <SOCStatCard
          label="Composite Average Risk"
          value={`${stats?.average_risk_score ?? 0} / 100`}
          subtitle="Fleet-wide risk posture"
          icon={Gauge}
          variant="amber"
        />
        <SOCStatCard
          label="Critical Risk Events"
          value={stats?.by_level?.critical ?? 0}
          subtitle="Severity score >= 85"
          icon={AlertTriangle}
          variant="danger"
        />
      </div>

      {/* Methodology Explainability Banner */}
      <div className="cyber-panel p-4 rounded-xl text-xs text-slate-300 flex items-start gap-3.5 backdrop-blur-md">
        <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-bold text-white uppercase tracking-wider text-[11px] flex items-center gap-1.5">
            <span className="w-1.5 h-3 bg-cyan-400 rounded-full"></span>
            Explainable Deterministic Scoring Formula
          </div>
          <p className="text-slate-400 leading-relaxed font-mono">
            Composite Risk = <code className="text-cyan-300 bg-[#020617] px-2 py-0.5 rounded border border-[#1E3A8A]/50">BaseSeverity (15–85 pts) + (Confidence - 0.7) × 15 pts + MITRE Tactic Weights (3–15 pts) + Asset Context Anomalies (5–10 pts)</code> clamped strictly to [0, 100].
          </p>
          <p className="text-slate-500 text-[11px] pt-0.5">
            Every point contribution is logged to provide full SOC transparency and eliminate black-box score ambiguity.
          </p>
        </div>
      </div>

      {/* Filter and Assessments Table */}
      <DataTable
        columns={columns}
        data={assessments}
        isLoading={isLoading}
        total={total}
        page={page}
        pageSize={10}
        onPageChange={setPage}
        searchPlaceholder="Filter risk evaluations..."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={levelFilter}
              onChange={(e) => setLevelFilter(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">All Risk Tiers</option>
              <option value="critical">Critical (85–100)</option>
              <option value="high">High (60–84)</option>
              <option value="medium">Medium (30–59)</option>
              <option value="low">Low (0–29)</option>
            </select>

            <button
              onClick={fetchRiskData}
              className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-400 hover:text-white"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        }
      />

      {/* Detailed Risk Explainability Modal */}
      <Modal
        isOpen={!!activeAssessment}
        onClose={() => {
          setActiveAssessment(null);
          setExplanationData(null);
        }}
        title="WHY THIS RISK SCORE? — Deterministic Evaluation Ledger"
        maxWidth="2xl"
      >
        {activeAssessment && (
          <div className="space-y-4">
            {/* Top Score Summary Banner */}
            <div className="p-4 rounded-xl bg-slate-950 border border-cyan-500/30 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Overall Evaluated Risk Tier
                </span>
                <div className="flex items-center gap-2.5">
                  <SeverityBadge severity={activeAssessment.risk_level} />
                  <span className="text-2xl font-black text-white font-mono">
                    {activeAssessment.risk_score} <span className="text-xs text-slate-400 font-normal">/ 100</span>
                  </span>
                </div>
              </div>

              <div className="text-right">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  Model Confidence
                </span>
                <span className="text-base font-bold text-cyan-400 font-mono">
                  {(activeAssessment.confidence * 100).toFixed(0)}%
                </span>
              </div>
            </div>

            {/* Formula Banner */}
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 text-xs font-mono">
              <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block mb-1">
                Deterministic Scoring Equation:
              </span>
              <p className="text-slate-200">
                {explanationData?.calculation_formula ||
                  "Final Score = (Base Severity + Σ Tactic Weights) × Confidence Multiplier + Asset Weight"}
              </p>
            </div>

            {/* Executive Rationale */}
            <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1.5">
              <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
                <TrendingUp className="w-4 h-4" />
                Score Rationale:
              </h4>
              <p className="text-xs text-slate-200 leading-relaxed font-sans">
                {explanationData?.explanation || activeAssessment.explanation || "Calculated by deterministic risk engine."}
              </p>
            </div>

            {/* Mathematical Factor Ledger */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                  Mathematical Factor Ledger (Transparent Audit)
                </h4>
                {isExplaining && (
                  <span className="text-[10px] font-mono text-cyan-400 flex items-center gap-1">
                    <RefreshCw className="w-3 h-3 animate-spin" /> Fetching engine weights...
                  </span>
                )}
              </div>

              <div className="space-y-2">
                {/* Base Rule Severity Row */}
                {explanationData?.base_severity_score !== undefined && (
                  <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                    <div>
                      <p className="font-bold text-white">Base Rule Severity</p>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Baseline points derived from detection rule severity level
                      </p>
                    </div>
                    <span className="px-2.5 py-1 rounded-lg bg-blue-950/60 border border-blue-800/40 font-mono text-xs font-bold text-blue-300">
                      +{explanationData.base_severity_score} pts
                    </span>
                  </div>
                )}

                {/* Contributing Factor Items */}
                {((explanationData?.contributing_factors || activeAssessment.contributing_factors || [])).length === 0 ? (
                  !isExplaining && (
                    <p className="text-xs text-slate-500 py-3 text-center">
                      Single baseline severity model applied.
                    </p>
                  )
                ) : (
                  (explanationData?.contributing_factors || activeAssessment.contributing_factors || []).map(
                    (factor: any, idx: number) => (
                      <div
                        key={idx}
                        className="p-3 rounded-xl bg-slate-950 border border-slate-800 flex items-center justify-between text-xs"
                      >
                        <div>
                          <p className="font-bold text-white">{factor.name}</p>
                          <p className="text-[11px] text-slate-400 mt-0.5">{factor.detail}</p>
                        </div>
                        <span className="px-2.5 py-1 rounded-lg bg-yellow-950/60 border border-yellow-800/40 font-mono text-xs font-bold text-yellow-300">
                          +{factor.impact} pts
                        </span>
                      </div>
                    )
                  )
                )}

                {/* Ledger Total Row */}
                <div className="p-3 rounded-xl bg-[#030d22] border border-cyan-500/40 flex items-center justify-between text-xs font-mono">
                  <span className="font-bold text-slate-200 uppercase">
                    Final Evaluated Risk Score:
                  </span>
                  <span className="text-base font-black text-cyan-400">
                    = {activeAssessment.risk_score} / 100
                  </span>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => {
                  setActiveAssessment(null);
                  navigate("/alerts");
                }}
                className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-red-950 border border-red-800/50 text-red-300 hover:bg-red-900 text-xs font-bold transition-colors"
              >
                <AlertOctagon className="w-3.5 h-3.5" />
                Escalate to Alert Queue
              </button>

              <button
                onClick={() => {
                  setActiveAssessment(null);
                  setExplanationData(null);
                }}
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
