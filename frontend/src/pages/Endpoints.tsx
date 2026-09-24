import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import {
  Laptop,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Search,
  Filter,
  Plus,
  RefreshCw,
  Clock,
  Activity,
  AlertTriangle,
  Radio,
  ExternalLink,
  Power,
  Lock,
  Unlock,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { Modal } from "../components/common/Modal";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";

interface Endpoint {
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

interface EndpointStats {
  total_endpoints: number;
  online_endpoints: number;
  offline_endpoints: number;
  degraded_endpoints: number;
  isolated_endpoints: number;
  by_risk_level: Record<string, number>;
}

export const Endpoints: React.FC = () => {
  const { showToast } = useToast();

  const [loading, setLoading] = useState(true);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [stats, setStats] = useState<EndpointStats>({
    total_endpoints: 0,
    online_endpoints: 0,
    offline_endpoints: 0,
    degraded_endpoints: 0,
    isolated_endpoints: 0,
    by_risk_level: {},
  });

  // Filters
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState("");
  const [selectedRisk, setSelectedRisk] = useState("");

  // Modals
  const [isEnrollModalOpen, setIsEnrollModalOpen] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [formData, setFormData] = useState({
    hostname: "",
    ip_address: "",
    operating_system: "Windows 11 Enterprise",
    agent_version: "1.4.2-asoc",
    tags: "workstation, sales",
  });

  const [isolateTarget, setIsolateTarget] = useState<Endpoint | null>(null);
  const [isolationReason, setIsolationReason] = useState("");
  const [isolating, setIsolating] = useState(false);

  const fetchEndpoints = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (searchQuery.trim()) params.append("search", searchQuery.trim());
      if (selectedStatus) params.append("status", selectedStatus);
      if (selectedRisk) params.append("risk_level", selectedRisk);
      params.append("limit", "100");

      const [listRes, statsRes] = await Promise.all([
        api.get(`/endpoints?${params.toString()}`),
        api.get("/endpoints/statistics"),
      ]);

      setEndpoints(listRes.data.data || []);
      setStats(statsRes.data.data || {
        total_endpoints: 0,
        online_endpoints: 0,
        offline_endpoints: 0,
        degraded_endpoints: 0,
        isolated_endpoints: 0,
        by_risk_level: {},
      });
    } catch (err: any) {
      showToast("Failed to load endpoints data", "error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEndpoints();
  }, [selectedStatus, selectedRisk]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    fetchEndpoints();
  };

  const handleEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.hostname.trim()) {
      showToast("Hostname is required", "error");
      return;
    }

    try {
      setEnrolling(true);
      const tagsArray = formData.tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);

      await api.post("/endpoints", {
        hostname: formData.hostname.trim(),
        ip_address: formData.ip_address.trim() || undefined,
        operating_system: formData.operating_system,
        agent_version: formData.agent_version,
        tags: tagsArray,
      });

      showToast(`Endpoint '${formData.hostname}' enrolled successfully`, "success");
      setIsEnrollModalOpen(false);
      setFormData({
        hostname: "",
        ip_address: "",
        operating_system: "Windows 11 Enterprise",
        agent_version: "1.4.2-asoc",
        tags: "workstation, corporate",
      });
      fetchEndpoints();
    } catch (err: any) {
      const msg = err.response?.data?.message || err.response?.data?.detail || "Failed to enroll endpoint";
      showToast(msg, "error");
    } finally {
      setEnrolling(false);
    }
  };

  const handleToggleIsolation = async () => {
    if (!isolateTarget) return;
    try {
      setIsolating(true);
      const nextState = !isolateTarget.is_isolated;
      await api.post(`/endpoints/${isolateTarget.id}/isolate`, {
        is_isolated: nextState,
        reason: nextState ? (isolationReason || "Analyst initiated forensic containment") : undefined,
      });

      showToast(
        nextState
          ? `Host '${isolateTarget.hostname}' isolated from network.`
          : `Host '${isolateTarget.hostname}' reconnected to network.`,
        "success"
      );
      setIsolateTarget(null);
      setIsolationReason("");
      fetchEndpoints();
    } catch (err: any) {
      showToast("Failed to update isolation state", "error");
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

  const getStatusBadge = (status: string, isIsolated: boolean) => {
    if (isIsolated) {
      return (
        <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-red-950 text-red-300 border border-red-800">
          <Lock className="w-3 h-3 text-red-400" />
          ISOLATED
        </span>
      );
    }
    switch (status.toLowerCase()) {
      case "online":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
            ONLINE
          </span>
        );
      case "degraded":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-950/80 text-amber-300 border border-amber-800">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
            DEGRADED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
            OFFLINE
          </span>
        );
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background */}
      <CyberGridBackground variant="minimal" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Top Header */}
      <SOCPageHeader
        title="Endpoint Management"
        tagline="HOST INVENTORY & TELEMETRY"
        subtitle="Monitor and manage authorized hosts connected to the Autonomous SOC telemetry mesh."
        icon={Laptop}
        badge={{ label: `${stats.online_endpoints} HOSTS ONLINE`, variant: "success", pulse: true }}
        actions={
          <div className="flex items-center gap-2.5">
            <button
              onClick={fetchEndpoints}
              disabled={loading}
              className="p-2 rounded-xl cyber-panel-subtle hover:bg-[#0c244d] border border-[#1E3A8A]/50 text-slate-300 hover:text-cyan-300 transition-colors"
              title="Refresh"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin text-cyan-400" : ""}`} />
            </button>
            <SOCButton
              variant="primary"
              size="sm"
              icon={Plus}
              onClick={() => setIsEnrollModalOpen(true)}
            >
              Enroll Endpoint
            </SOCButton>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SOCStatCard
          label="Total Enrolled"
          value={stats.total_endpoints}
          icon={Laptop}
          variant="cyan"
          subtitle="Authorized corporate machines"
        />

        <SOCStatCard
          label="Active Agents"
          value={stats.online_endpoints}
          icon={Radio}
          variant="emerald"
          subtitle="Telemetry heartbeat healthy"
        />

        <SOCStatCard
          label="Isolated Hosts"
          value={stats.isolated_endpoints}
          icon={Lock}
          variant="danger"
          subtitle="Contained for forensics"
        />

        <SOCStatCard
          label="High / Critical Risk"
          value={(stats.by_risk_level?.high || 0) + (stats.by_risk_level?.critical || 0)}
          icon={ShieldAlert}
          variant="amber"
          subtitle="Hosts requiring analyst triage"
        />
      </div>

      {/* Filter and Search Bar */}
      <div className="cyber-panel p-4 rounded-xl flex flex-col md:flex-row gap-3 items-center justify-between">
        <form onSubmit={handleSearch} className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-cyan-400/70" />
          <input
            type="text"
            placeholder="Search hostname, IP, OS..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-500/30 transition-all font-mono"
          />
        </form>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <select
            value={selectedStatus}
            onChange={(e) => setSelectedStatus(e.target.value)}
            className="bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400 font-mono"
          >
            <option value="">All Statuses</option>
            <option value="online">Online</option>
            <option value="offline">Offline</option>
            <option value="degraded">Degraded</option>
          </select>

          <select
            value={selectedRisk}
            onChange={(e) => setSelectedRisk(e.target.value)}
            className="bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg px-3 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-400 font-mono"
          >
            <option value="">All Risk Levels</option>
            <option value="low">Low Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="high">High Risk</option>
            <option value="critical">Critical Risk</option>
          </select>
        </div>
      </div>

      {/* Endpoints Table */}
      <div className="cyber-panel rounded-xl overflow-hidden shadow-xl">
        {loading ? (
          <div className="p-12 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
            <p className="text-xs text-slate-400 font-mono">Loading enrolled endpoints...</p>
          </div>
        ) : endpoints.length === 0 ? (
          <div className="p-12 text-center">
            <Laptop className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <h3 className="text-base font-semibold text-slate-300">No Endpoints Found</h3>
            <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
              No authorized computers matched your current search filters, or no endpoints are registered yet.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Hostname</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4">Operating System</th>
                  <th className="py-3 px-4">Owner</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Risk</th>
                  <th className="py-3 px-4 text-center">Events</th>
                  <th className="py-3 px-4 text-center">Alerts</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {endpoints.map((ep) => (
                  <tr key={ep.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4 font-medium text-white flex items-center gap-2">
                      <Server className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <Link
                        to={`/endpoints/${ep.id}`}
                        className="hover:text-cyan-400 underline-offset-2 hover:underline"
                      >
                        {ep.hostname}
                      </Link>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">{ep.ip_address || "N/A"}</td>
                    <td className="py-3 px-4 text-slate-400">
                      <div>{ep.operating_system}</div>
                      <div className="text-[10px] text-slate-500">Agent {ep.agent_version}</div>
                    </td>
                    <td className="py-3 px-4 text-slate-300">
                      <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-[11px]">
                        {ep.owner_username || "system"}
                      </span>
                    </td>
                    <td className="py-3 px-4">{getStatusBadge(ep.status, ep.is_isolated)}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${getRiskBadge(
                          ep.risk_level
                        )}`}
                      >
                        {ep.risk_level}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center font-mono font-medium">{ep.event_count}</td>
                    <td className="py-3 px-4 text-center font-mono font-medium">
                      {ep.alert_count > 0 ? (
                        <span className="text-rose-400 font-bold">{ep.alert_count}</span>
                      ) : (
                        <span className="text-slate-500">0</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => {
                            setIsolateTarget(ep);
                            setIsolationReason(ep.isolation_reason || "");
                          }}
                          className={`p-1.5 rounded text-xs font-semibold border transition-all ${
                            ep.is_isolated
                              ? "bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border-emerald-800"
                              : "bg-rose-950/80 hover:bg-rose-900 text-rose-300 border-rose-800"
                          }`}
                          title={ep.is_isolated ? "Reconnect host" : "Isolate host"}
                        >
                          {ep.is_isolated ? <Unlock className="w-3.5 h-3.5" /> : <Lock className="w-3.5 h-3.5" />}
                        </button>
                        <Link
                          to={`/endpoints/${ep.id}`}
                          className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 transition-colors"
                        >
                          <span>Telemetry</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Enroll Endpoint Modal */}
      <Modal
        isOpen={isEnrollModalOpen}
        onClose={() => setIsEnrollModalOpen(false)}
        title="Enroll New SOC Endpoint"
        maxWidth="md"
      >
        <form onSubmit={handleEnroll} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Hostname *</label>
            <input
              type="text"
              required
              placeholder="e.g. workstation-corp-04"
              value={formData.hostname}
              onChange={(e) => setFormData({ ...formData, hostname: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">IP Address</label>
            <input
              type="text"
              placeholder="e.g. 192.168.1.120"
              value={formData.ip_address}
              onChange={(e) => setFormData({ ...formData, ip_address: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Operating System</label>
            <select
              value={formData.operating_system}
              onChange={(e) => setFormData({ ...formData, operating_system: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="Windows 11 Enterprise">Windows 11 Enterprise</option>
              <option value="Windows 10 Pro">Windows 10 Pro</option>
              <option value="Windows Server 2022">Windows Server 2022</option>
              <option value="Ubuntu Linux 24.04 LTS">Ubuntu Linux 24.04 LTS</option>
              <option value="macOS Sonoma 14.5">macOS Sonoma 14.5</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Agent Version</label>
            <input
              type="text"
              value={formData.agent_version}
              onChange={(e) => setFormData({ ...formData, agent_version: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Tags (comma-separated)</label>
            <input
              type="text"
              placeholder="workstation, finance, production"
              value={formData.tags}
              onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setIsEnrollModalOpen(false)}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={enrolling}
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow-lg shadow-cyan-600/20 disabled:opacity-50 transition-all"
            >
              {enrolling ? "Enrolling..." : "Enroll Endpoint"}
            </button>
          </div>
        </form>
      </Modal>

      {/* Isolation Confirmation Modal */}
      {isolateTarget && (
        <Modal
          isOpen={true}
          onClose={() => setIsolateTarget(null)}
          title={isolateTarget.is_isolated ? "Reconnect Endpoint to Network" : "Isolate Endpoint (Network Containment)"}
          maxWidth="md"
        >
          <div className="space-y-4">
            <p className="text-xs text-slate-300">
              {isolateTarget.is_isolated
                ? `You are about to reconnect '${isolateTarget.hostname}' (${isolateTarget.ip_address}) to the network.`
                : `Containment action: This will signal the ASOC host agent to terminate untrusted network socket connections for '${isolateTarget.hostname}' (${isolateTarget.ip_address}) while preserving SOC telemetry communication.`}
            </p>

            {!isolateTarget.is_isolated && (
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">
                  Isolation Justification / Incident ID
                </label>
                <input
                  type="text"
                  placeholder="e.g. Active credential dumping detected (INC-2026-0042)"
                  value={isolationReason}
                  onChange={(e) => setIsolationReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>
            )}

            <div className="pt-2 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setIsolateTarget(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleToggleIsolation}
                disabled={isolating}
                className={`px-4 py-2 rounded-lg text-white text-xs font-semibold shadow-lg disabled:opacity-50 transition-all ${
                  isolateTarget.is_isolated
                    ? "bg-emerald-600 hover:bg-emerald-500 shadow-emerald-600/20"
                    : "bg-rose-600 hover:bg-rose-500 shadow-rose-600/20"
                }`}
              >
                {isolating
                  ? "Processing..."
                  : isolateTarget.is_isolated
                  ? "Reconnect Endpoint"
                  : "Confirm Isolation"}
              </button>
            </div>
          </div>
        </Modal>
      )}
      </div>
    </div>
  );
};
