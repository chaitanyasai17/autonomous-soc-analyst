import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  FileCode,
  RefreshCw,
  Eye,
  Shield,
  Tag,
  Play,
  CheckCircle2,
  SlidersHorizontal,
  Search,
  ExternalLink,
  Layers,
} from "lucide-react";
import { api } from "../services/api";
import { SigmaRule } from "../types";
import { SeverityBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";

export const SigmaRules: React.FC = () => {
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [search, setSearch] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isReloading, setIsReloading] = useState<boolean>(false);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [activeRule, setActiveRule] = useState<SigmaRule | null>(null);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const fetchRules = async () => {
    setIsLoading(true);
    try {
      const res = await api.get("/rules");
      if (res.data?.data) {
        setRules(res.data.data);
      }
    } catch (err: any) {
      toastError("Failed to fetch Sigma rules.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  const handleReload = async () => {
    setIsReloading(true);
    try {
      const res = await api.post("/rules/reload");
      success(`Reloaded rules from storage: ${res.data?.data?.rules_loaded || 0} active rules.`);
      fetchRules();
    } catch (err: any) {
      toastError("Failed to reload Sigma rules.");
    } finally {
      setIsReloading(false);
    }
  };

  const handleScanAll = async () => {
    setIsScanning(true);
    try {
      const res = await api.post("/detections/run-all");
      const count = res.data?.data?.detections_created || 0;
      success(`Detection scan complete: ${count} threat detections generated.`);
      navigate("/detections");
    } catch (err: any) {
      toastError("Failed running rule scan.");
    } finally {
      setIsScanning(false);
    }
  };

  const filteredRules = rules.filter((r) => {
    const matchesSearch =
      !search ||
      r.title.toLowerCase().includes(search.toLowerCase()) ||
      r.id.toLowerCase().includes(search.toLowerCase()) ||
      (r.tags || []).some((t) => t.toLowerCase().includes(search.toLowerCase()));

    const matchesCategory =
      !categoryFilter || r.category?.toLowerCase() === categoryFilter.toLowerCase();

    const matchesSeverity =
      !severityFilter || r.level?.toLowerCase() === severityFilter.toLowerCase();

    return matchesSearch && matchesCategory && matchesSeverity;
  });

  const categories = Array.from(new Set(rules.map((r) => r.category).filter(Boolean)));

  const columns: Column<SigmaRule>[] = [
    {
      header: "Severity",
      accessor: "level",
      render: (item) => <SeverityBadge severity={item.level} />,
    },
    {
      header: "Sigma Rule Title & Identifier",
      accessor: "title",
      render: (item) => (
        <div>
          <div className="font-bold text-white">{item.title}</div>
          <div className="text-[11px] text-slate-400 font-mono mt-0.5 flex items-center gap-2">
            <span className="text-cyan-400 font-semibold">{item.id}</span>
            <span>•</span>
            <span>Category: {item.category || "general"}</span>
          </div>
        </div>
      ),
    },
    {
      header: "MITRE ATT&CK Techniques",
      accessor: "tags",
      render: (item) => (
        <div className="flex flex-wrap gap-1 max-w-xs">
          {(item.tags || []).slice(0, 3).map((tag, idx) => (
            <span
              key={idx}
              className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-cyan-300"
            >
              {tag.replace("attack.", "")}
            </span>
          ))}
          {(item.tags || []).length > 3 && (
            <span className="text-[10px] text-slate-500 font-mono">
              +{item.tags!.length - 3} more
            </span>
          )}
        </div>
      ),
    },
    {
      header: "Engine Status",
      accessor: "enabled",
      render: (item) => (
        <span
          className={`px-2.5 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wider ${
            item.enabled !== false
              ? "text-emerald-300 bg-emerald-950/80 border border-emerald-800/60"
              : "text-slate-400 bg-slate-800"
          }`}
        >
          {item.enabled !== false ? "Active" : "Disabled"}
        </span>
      ),
    },
    {
      header: "Actions",
      className: "text-right",
      render: (item) => (
        <button
          onClick={() => setActiveRule(item)}
          className="px-2.5 py-1 rounded-lg bg-cyan-950 border border-cyan-800/50 text-cyan-300 hover:bg-cyan-900 text-xs font-semibold flex items-center gap-1 transition-colors"
        >
          <Eye className="w-3.5 h-3.5" />
          View Rule AST
        </button>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with circuit traces */}
      <CyberGridBackground variant="sigma" />

      {/* Foreground Content */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header Controls */}
      <SOCPageHeader
        title="Sigma Detection Rules"
        tagline="DETECTION AS CODE ENGINE"
        subtitle="Explore, author, and test deterministic Sigma detection rules."
        icon={FileCode}
        badge={{ label: `${rules.length} COMPILED RULES`, variant: "primary", pulse: true }}
        actions={
          <div className="flex items-center gap-2.5">
            <SOCButton
              variant="danger"
              size="sm"
              icon={Play}
              loading={isScanning}
              onClick={handleScanAll}
            >
              Scan Rules on Logs
            </SOCButton>

            <SOCButton
              variant="secondary"
              size="sm"
              icon={RefreshCw}
              loading={isReloading}
              onClick={handleReload}
            >
              Reload Repository
            </SOCButton>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <SOCStatCard
          label="Active Sigma Rules"
          value={rules.length}
          icon={FileCode}
          variant="cyan"
          subtitle="Indexed AST signature rules"
        />

        <SOCStatCard
          label="Rule Categories"
          value={categories.length}
          icon={Layers}
          variant="purple"
          subtitle="Tactical MITRE domains covered"
        />

        <SOCStatCard
          label="Compiler Engine"
          value="AST Evaluator"
          icon={Shield}
          variant="emerald"
          subtitle="Real-time condition matching"
        />
      </div>

      {/* Rules Table */}
      <DataTable
        columns={columns}
        data={filteredRules}
        isLoading={isLoading}
        total={filteredRules.length}
        searchValue={search}
        onSearchChange={setSearch}
        searchPlaceholder="Search rules by title, ID, or ATT&CK tag..."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="">All Categories ({categories.length})</option>
              {categories.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>

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
          </div>
        }
      />

      {/* Rule Definition Modal */}
      <Modal
        isOpen={!!activeRule}
        onClose={() => setActiveRule(null)}
        title="Sigma Detection Definition & Selections"
        maxWidth="2xl"
      >
        {activeRule && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-slate-950 border border-slate-800">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-cyan-400 font-bold">Rule ID: {activeRule.id}</span>
                <SeverityBadge severity={activeRule.level} />
              </div>
              <h3 className="text-base font-bold text-white mb-1">{activeRule.title}</h3>
              <p className="text-xs text-slate-400 leading-relaxed">{activeRule.description}</p>
            </div>

            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                Associated MITRE ATT&CK Tags
              </label>
              <div className="flex flex-wrap gap-1.5">
                {(activeRule.tags || []).map((tag, idx) => (
                  <span
                    key={idx}
                    className="px-2.5 py-1 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-300 text-xs font-mono flex items-center gap-1.5"
                  >
                    <Tag className="w-3 h-3 text-cyan-400" />
                    <span>{tag}</span>
                  </span>
                ))}
              </div>
            </div>

            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                AST Detection Selections & Conditions
              </label>
              <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
                {JSON.stringify(activeRule.detection, null, 2)}
              </pre>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setActiveRule(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-bold text-slate-300"
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
