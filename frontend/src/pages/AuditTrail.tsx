import React, { useEffect, useState } from "react";
import {
  Shield,
  ScrollText,
  Clock,
  User,
  Activity,
  FileCode,
  Search,
  RefreshCw,
  Eye,
  SlidersHorizontal,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react";
import { api } from "../services/api";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

interface AuditLogEntry {
  id: string;
  timestamp: string;
  user_id?: string;
  username?: string;
  role?: string;
  action: string;
  object_type?: string;
  object_id?: string;
  details?: Record<string, any>;
  ip_address?: string;
  status: string;
  created_at: string;
}

export const AuditTrail: React.FC = () => {
  const [logs, setLogs] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(15);
  const [actionFilter, setActionFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [usernameSearch, setUsernameSearch] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [selectedLog, setSelectedLog] = useState<AuditLogEntry | null>(null);

  const { error: toastError } = useToast();

  const fetchLogs = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        skip: (page - 1) * pageSize,
        limit: pageSize,
      };
      if (actionFilter) params.action = actionFilter;
      if (statusFilter) params.status = statusFilter;
      if (usernameSearch) params.username = usernameSearch;

      const res = await api.get("/audit-logs", { params });
      if (res.data) {
        setLogs(res.data.data || []);
        setTotal(res.data.total || 0);
      }
    } catch {
      toastError("Failed to load SOC audit trail logs.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [page, actionFilter, statusFilter, usernameSearch]);

  const getActionColor = (action: string) => {
    if (action.includes("LOGIN") || action.includes("AUTH")) {
      return "bg-cyan-500/15 text-cyan-400 border-cyan-500/30";
    }
    if (action.includes("SCAN") || action.includes("ASSESSMENT")) {
      return "bg-purple-500/15 text-purple-300 border-purple-500/30";
    }
    if (action.includes("INCIDENT")) {
      return "bg-rose-500/15 text-rose-300 border-rose-500/30";
    }
    if (action.includes("ALERT")) {
      return "bg-amber-500/15 text-amber-300 border-amber-500/30";
    }
    if (action.includes("DETECTION")) {
      return "bg-blue-500/15 text-blue-300 border-blue-500/30";
    }
    if (action.includes("ENDPOINT") || action.includes("ISOLAT")) {
      return "bg-teal-500/15 text-teal-300 border-teal-500/30";
    }
    if (action.includes("UPLOAD")) {
      return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
    }
    return "bg-slate-800 text-slate-300 border-slate-700";
  };

  const columns: Column<AuditLogEntry>[] = [
    {
      header: "Timestamp",
      accessor: "timestamp",
      render: (item) => (
        <span className="font-mono text-xs text-slate-400 flex items-center gap-1.5">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          {new Date(item.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Action",
      accessor: "action",
      render: (item) => (
        <span
          className={`px-2 py-0.5 rounded-md text-[11px] font-bold border font-mono tracking-wide ${getActionColor(
            item.action
          )}`}
        >
          {item.action}
        </span>
      ),
    },
    {
      header: "Actor",
      accessor: "username",
      render: (item) => (
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-md bg-slate-800 border border-slate-700 flex items-center justify-center text-[10px] font-bold text-cyan-400">
            {item.username ? item.username.charAt(0).toUpperCase() : "S"}
          </div>
          <div>
            <span className="text-xs font-semibold text-slate-200 block">
              {item.username || "system"}
            </span>
            <span className="text-[10px] text-slate-500 uppercase font-mono">
              {item.role ? item.role.replace("_", " ") : "SYSTEM"}
            </span>
          </div>
        </div>
      ),
    },
    {
      header: "Target Entity",
      accessor: "object_type",
      render: (item) => (
        <div>
          <span className="text-xs font-mono text-slate-300">
            {item.object_type || "N/A"}
          </span>
          {item.object_id && (
            <span className="block text-[10px] text-slate-500 font-mono truncate max-w-[140px]" title={item.object_id}>
              {item.object_id}
            </span>
          )}
        </div>
      ),
    },
    {
      header: "Status",
      accessor: "status",
      render: (item) => (
        <span
          className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-bold ${
            item.status === "SUCCESS"
              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              : "bg-red-500/10 text-red-400 border border-red-500/30"
          }`}
        >
          {item.status === "SUCCESS" ? (
            <CheckCircle2 className="w-3 h-3" />
          ) : (
            <AlertTriangle className="w-3 h-3" />
          )}
          {item.status}
        </span>
      ),
    },
    {
      header: "Payload",
      className: "text-right",
      render: (item) => (
        <div className="flex justify-end">
          <button
            onClick={() => setSelectedLog(item)}
            className="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700/80 text-cyan-400 text-xs font-medium flex items-center gap-1.5 transition-colors"
          >
            <Eye className="w-3 h-3" />
            Inspect
          </button>
        </div>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="audit" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="Audit Trail"
        tagline="IMMUTABLE COMPLIANCE LEDGER"
        subtitle="Immutable record of security and administrative activity."
        icon={ScrollText}
        badgeText={`${total} Events Recorded`}
        actions={
          <SOCButton
            variant="secondary"
            onClick={fetchLogs}
            icon={<RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />}
          >
            Refresh
          </SOCButton>
        }
      />

      {/* KPI Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Total Recorded Events</p>
            <p className="text-2xl font-black text-white mt-1 font-mono">{total}</p>
          </div>
          <Activity className="w-8 h-8 text-cyan-500/20" />
        </div>
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Active Operations Tracked</p>
            <p className="text-2xl font-black text-emerald-400 mt-1 font-mono">100%</p>
          </div>
          <CheckCircle2 className="w-8 h-8 text-emerald-500/20" />
        </div>
        <div className="cyber-panel p-4 flex items-center justify-between">
          <div>
            <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">Storage Integrity</p>
            <p className="text-2xl font-black text-cyan-400 mt-1 font-mono">APPEND ONLY</p>
          </div>
          <Shield className="w-8 h-8 text-cyan-500/20" />
        </div>
      </div>

      {/* Table */}
      <DataTable
        columns={columns}
        data={logs}
        isLoading={isLoading}
        total={total}
        page={page}
        pageSize={pageSize}
        onPageChange={setPage}
        searchValue={usernameSearch}
        onSearchChange={setUsernameSearch}
        searchPlaceholder="Filter by username..."
        actions={
          <div className="flex items-center gap-2">
            <select
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#030a18]/90 border border-slate-700/80 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
            >
              <option value="">All Actions</option>
              <option value="USER_LOGIN">USER_LOGIN</option>
              <option value="LOG_UPLOAD">LOG_UPLOAD</option>
              <option value="DETECTION_FEEDBACK">DETECTION_FEEDBACK</option>
              <option value="ALERT_STATUS_UPDATE">ALERT_STATUS_UPDATE</option>
              <option value="INCIDENT_STATUS_UPDATE">INCIDENT_STATUS_UPDATE</option>
              <option value="SECURITY_SCAN_RUN">SECURITY_SCAN_RUN</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#030a18]/90 border border-slate-700/80 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
            >
              <option value="">All Statuses</option>
              <option value="SUCCESS">SUCCESS</option>
              <option value="FAILURE">FAILURE</option>
            </select>
          </div>
        }
        emptyMessage="No audit logs recorded matching this criteria."
      />

      {/* Audit Detail Modal */}
      <Modal
        isOpen={!!selectedLog}
        onClose={() => setSelectedLog(null)}
        title="Audit Log Event Forensics"
        maxWidth="2xl"
      >
        {selectedLog && (
          <div className="space-y-4">
            <div className="p-4 rounded-xl bg-[#030a18]/90 border border-cyan-900/30 space-y-2 font-mono text-xs">
              <div className="flex justify-between border-b border-slate-800/80 pb-2">
                <span className="text-slate-400">Event ID:</span>
                <span className="text-cyan-400">{selectedLog.id}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800/80 pb-2">
                <span className="text-slate-400">Timestamp:</span>
                <span className="text-white">{new Date(selectedLog.timestamp).toISOString()}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800/80 pb-2">
                <span className="text-slate-400">Actor / User ID:</span>
                <span className="text-slate-300">{selectedLog.username || "System"} ({selectedLog.user_id || "N/A"})</span>
              </div>
              <div className="flex justify-between border-b border-slate-800/80 pb-2">
                <span className="text-slate-400">Action:</span>
                <span className="text-amber-400 font-bold">{selectedLog.action}</span>
              </div>
              <div className="flex justify-between border-b border-slate-800/80 pb-2">
                <span className="text-slate-400">Target Object:</span>
                <span className="text-slate-300">{selectedLog.object_type || "N/A"} [{selectedLog.object_id || "N/A"}]</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Client IP Address:</span>
                <span className="text-slate-300">{selectedLog.ip_address || "127.0.0.1"}</span>
              </div>
            </div>

            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-2">
                Event Payload / Forensic Details
              </label>
              <pre className="p-3.5 rounded-xl bg-[#020712]/95 border border-slate-800 text-xs font-mono text-emerald-400 overflow-x-auto max-h-64">
                {JSON.stringify(selectedLog.details || {}, null, 2)}
              </pre>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <SOCButton
                variant="secondary"
                onClick={() => setSelectedLog(null)}
              >
                Close
              </SOCButton>
            </div>
          </div>
        )}
      </Modal>
      </div>
    </div>
  );
};
