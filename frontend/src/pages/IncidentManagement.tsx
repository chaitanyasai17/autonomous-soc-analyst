import React, { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import {
  Flame,
  Plus,
  RefreshCw,
  Eye,
  SlidersHorizontal,
  Layers,
  Sparkles,
  Briefcase,
  ShieldCheck,
  AlertTriangle,
  Clock,
  CheckCircle2,
} from "lucide-react";
import { api } from "../services/api";
import { Incident, RiskLevel } from "../types";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";
import { notifyBadgeRefresh } from "../hooks/useNotificationBadges";

export const IncidentManagement: React.FC = () => {
  const [searchParams] = useSearchParams();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [statusFilter, setStatusFilter] = useState<string>(searchParams.get("status") || "");
  const [priorityFilter, setPriorityFilter] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isCorrelating, setIsCorrelating] = useState<boolean>(false);
  const [stats, setStats] = useState<any | null>(null);

  // New Incident Modal
  const [isCreateOpen, setIsCreateOpen] = useState<boolean>(false);
  const [newPriority, setNewPriority] = useState<RiskLevel>("high");
  const [isSubmitting, setIsSubmitting] = useState(false);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const fetchStats = async () => {
    try {
      const res = await api.get("/incidents/statistics");
      if (res.data?.data) {
        setStats(res.data.data);
      }
    } catch {
      // stats fallback
    }
  };

  const fetchIncidents = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        skip: (page - 1) * 10,
        limit: 10,
      };
      if (statusFilter) params.status = statusFilter;
      if (priorityFilter) params.priority = priorityFilter;

      const res = await api.get("/incidents", { params });
      if (res.data) {
        setIncidents(res.data.data || []);
        setTotal(res.data.total || 0);
      }
    } catch (err: any) {
      toastError("Failed to fetch incidents list.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    fetchIncidents();
  }, [page, statusFilter, priorityFilter]);

  const handleAutoCorrelate = async () => {
    setIsCorrelating(true);
    try {
      const res = await api.post("/incidents/auto-correlate");
      if (res.data?.success) {
        success(res.data.message || "Auto-correlation finished.");
        fetchStats();
        fetchIncidents();
        notifyBadgeRefresh();
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Auto-correlation failed.");
    } finally {
      setIsCorrelating(false);
    }
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    try {
      const res = await api.post("/incidents", {
        priority: newPriority,
      });
      if (res.data?.success) {
        success(`Incident ${res.data.data.incident_number} initialized.`);
        setIsCreateOpen(false);
        fetchStats();
        fetchIncidents();
        notifyBadgeRefresh();
        navigate(`/incidents/${res.data.data.id}`);
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to create incident.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const columns: Column<Incident>[] = [
    {
      header: "Incident Case #",
      accessor: "incident_number",
      render: (inc) => (
        <span className="font-mono text-cyan-400 font-bold tracking-wider">
          {inc.incident_number}
        </span>
      ),
    },
    {
      header: "Investigation Scope",
      render: (inc) => (
        <div>
          <p className="font-bold text-white">
            {inc.title || `Investigation Case ${inc.incident_number}`}
          </p>
          <p className="text-xs text-slate-400 truncate max-w-md mt-0.5">
            {inc.description || "Active security incident investigation dossier"}
          </p>
        </div>
      ),
    },
    {
      header: "Priority",
      render: (inc) => <SeverityBadge severity={inc.priority} />,
    },
    {
      header: "Lifecycle State",
      render: (inc) => <StatusBadge status={inc.status} />,
    },
    {
      header: "Correlated Alerts",
      render: (inc) => (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          {inc.alert_count} Alerts
        </span>
      ),
    },
    {
      header: "Declared At",
      render: (inc) => (
        <span className="text-xs text-slate-400 font-mono">
          {new Date(inc.opened_at).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Actions",
      className: "text-right",
      render: (inc) => (
        <button
          onClick={() => navigate(`/incidents/${inc.id}`)}
          className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold bg-cyan-950/80 text-cyan-300 hover:bg-cyan-900 border border-cyan-700/50 rounded-lg transition-colors"
        >
          <Eye className="w-3.5 h-3.5" />
          Investigate
        </button>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background */}
      <CyberGridBackground variant="incidents" />

      {/* Foreground Content */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header Controls */}
      <SOCPageHeader
        title="Incident Management"
        tagline="CORRELATED CASE MANAGEMENT"
        subtitle="Correlated alerts, investigation lifecycle, and response tracking."
        icon={Briefcase}
        badge={{ label: `${stats?.total_incidents ?? total} ACTIVE CASES`, variant: "danger", pulse: true }}
        actions={
          <div className="flex items-center gap-2.5">
            <SOCButton
              variant="secondary"
              size="sm"
              icon={Sparkles}
              loading={isCorrelating}
              onClick={handleAutoCorrelate}
            >
              {isCorrelating ? "Correlating Alerts..." : "Auto-Correlate Alerts"}
            </SOCButton>

            <SOCButton
              variant="danger"
              size="sm"
              icon={Plus}
              onClick={() => setIsCreateOpen(true)}
            >
              New Incident
            </SOCButton>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SOCStatCard
          label="Total Cases Declared"
          value={stats?.total_incidents ?? total}
          subtitle="All security investigations"
          icon={Briefcase}
          variant="cyan"
        />
        <SOCStatCard
          label="Open / Triage"
          value={stats?.by_status?.open ?? 0}
          subtitle="Pending lead assignment"
          icon={Clock}
          variant="amber"
        />
        <SOCStatCard
          label="Active Investigations"
          value={stats?.by_status?.investigating ?? 0}
          subtitle="Under containment"
          icon={Flame}
          variant="danger"
        />
        <SOCStatCard
          label="Resolved & Contained"
          value={(stats?.by_status?.resolved ?? 0) + (stats?.by_status?.contained ?? 0)}
          subtitle="Threat eliminated"
          icon={CheckCircle2}
          variant="purple"
        />
      </div>

      {/* Filters bar */}
      <div className="bg-slate-900/60 backdrop-blur-md border border-slate-800 rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 font-bold uppercase tracking-wider">Filters:</span>
          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>

          <select
            value={priorityFilter}
            onChange={(e) => {
              setPriorityFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-700 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          >
            <option value="">All Priorities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        <button
          onClick={() => {
            fetchStats();
            fetchIncidents();
          }}
          className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          title="Refresh Incidents"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Incidents Table */}
      <DataTable
        columns={columns}
        data={incidents}
        isLoading={isLoading}
        page={page}
        pageSize={10}
        total={total}
        onPageChange={setPage}
        emptyMessage="No incidents found. Run auto-correlation or manually declare an incident."
      />

      {/* Create Incident Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Declare New Security Incident Investigation"
        maxWidth="md"
      >
        <form onSubmit={handleCreateIncident} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
              Investigation Priority
            </label>
            <select
              value={newPriority}
              onChange={(e) => setNewPriority(e.target.value as RiskLevel)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
            >
              <option value="critical">Critical (Immediate containment required)</option>
              <option value="high">High (Active exploitation or compromised host)</option>
              <option value="medium">Medium (Suspicious multi-event sequence)</option>
              <option value="low">Low (Policy violation or informational escalation)</option>
            </select>
          </div>

          <p className="text-xs text-slate-400 leading-relaxed">
            A unique sequence identifier (<span className="font-mono text-cyan-400">INC-YYYY-XXXX</span>) will be assigned automatically. You can attach alerts, log findings, and track containment after creation.
          </p>

          <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className="px-4 py-2 text-xs font-bold text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-5 py-2 text-xs font-black text-white bg-red-600 hover:bg-red-500 rounded-lg disabled:opacity-50 shadow-md shadow-red-950/30"
            >
              {isSubmitting ? "Declaring..." : "Declare Case"}
            </button>
          </div>
        </form>
      </Modal>
      </div>
    </div>
  );
};
