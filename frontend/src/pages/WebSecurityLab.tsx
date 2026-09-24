import React, { useState, useEffect } from "react";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Globe,
  Play,
  Settings,
  ArrowRight,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  Filter,
  RefreshCw,
  ExternalLink,
  ChevronRight,
  Zap,
  Sliders,
  Layers,
  Lock,
  Eye,
  FileText,
  Plus,
  Trash2,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { Modal } from "../components/common/Modal";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { notifyBadgeRefresh } from "../hooks/useNotificationBadges";

interface Finding {
  id: string;
  finding_id: string;
  title: string;
  category: string;
  severity: "critical" | "high" | "medium" | "low";
  confidence: number;
  status: string;
  endpoint: string;
  http_method: string;
  parameter?: string;
  evidence: string;
  description: string;
  remediation: string;
  cwe_id?: string;
  owasp_category?: string;
  mitre_technique_id?: string;
  discovered_at: string;
  risk_score: number;
  related_alert_id?: string;
  related_incident_id?: string;
}

interface ExposedService {
  port: number;
  service: string;
  state: string;
}

interface Scan {
  id: string;
  scan_id: string;
  target_url: string;
  target_host: string;
  resolved_ip?: string;
  scan_profile: string;
  status: string;
  started_at: string;
  completed_at?: string;
  duration_seconds?: number;
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  informational_count?: number;
  posture_score: number;
  posture_breakdown?: Record<string, number>;
  exposed_services?: ExposedService[];
}

interface PostureSummary {
  posture_score: number;
  target_host?: string;
  scan_id?: string;
  evaluated_at: string;
  breakdown: Record<string, number>;
  active_findings: number;
  critical_findings: number;
  targets_monitored: number;
}

interface AllowlistEntry {
  id: string;
  pattern: string;
  description?: string;
  is_active: boolean;
  created_at: string;
}

export const WebSecurityLab: React.FC = () => {
  const { showToast } = useToast();

  const [loading, setLoading] = useState(true);
  const [posture, setPosture] = useState<PostureSummary | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Modals
  const [isScanModalOpen, setIsScanModalOpen] = useState(false);
  const [isAllowlistModalOpen, setIsAllowlistModalOpen] = useState(false);
  const [isPromoting, setIsPromoting] = useState(false);
  const [isScanning, setIsScanning] = useState(false);

  // Scan Launch Form
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:8000");
  const [scanProfile, setScanProfile] = useState("standard");
  const [timeoutSeconds, setTimeoutSeconds] = useState(5);

  // Allowlist
  const [allowlist, setAllowlist] = useState<AllowlistEntry[]>([]);
  const [newPattern, setNewPattern] = useState("");
  const [newPatternDesc, setNewPatternDesc] = useState("");

  const fetchData = async () => {
    try {
      setLoading(true);
      const [postureRes, scansRes] = await Promise.all([
        api.get("/web-security/posture"),
        api.get("/web-security/scans?limit=10"),
      ]);

      setPosture(postureRes.data);
      const scanList = scansRes.data.items || [];
      setScans(scanList);

      if (scanList.length > 0) {
        setSelectedScan(scanList[0]);
        fetchFindings(scanList[0].id);
      }
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to load Web Security data", "error");
    } finally {
      setLoading(false);
    }
  };

  const fetchFindings = async (scanId: string) => {
    try {
      const res = await api.get(`/web-security/scans/${scanId}/findings?limit=100`);
      setFindings(res.data.items || []);
    } catch (err: any) {
      showToast("Failed to load scan findings", "error");
    }
  };

  const fetchAllowlist = async () => {
    try {
      const res = await api.get("/web-security/allowlist?limit=100");
      setAllowlist(res.data.items || []);
    } catch (err: any) {
      showToast("Failed to load target allowlist", "error");
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleLaunchScan = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsScanning(true);
      const res = await api.post("/web-security/scans", {
        target_url: targetUrl,
        scan_profile: scanProfile,
        timeout_seconds: timeoutSeconds,
      });

      showToast(`Scan launched against ${targetUrl}`, "success");
      setIsScanModalOpen(false);
      await fetchData();
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to launch scan. Check allowlist permissions.", "error");
    } finally {
      setIsScanning(false);
    }
  };

  const handlePromoteFinding = async (finding: Finding) => {
    try {
      setIsPromoting(true);
      const res = await api.post(`/web-security/findings/${finding.id}/promote-to-alert?auto_correlate=true`);
      showToast(`Finding successfully promoted to SOC Alert (${res.data.severity.toUpperCase()}) and correlated!`, "success");
      notifyBadgeRefresh();

      // Update finding locally
      const updated = { ...finding, related_alert_id: res.data.id };
      setSelectedFinding(updated);
      setFindings((prev) => prev.map((f) => (f.id === finding.id ? updated : f)));
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to promote finding to Alert", "error");
    } finally {
      setIsPromoting(false);
    }
  };

  const handleCancelScan = async (scanId: string) => {
    try {
      await api.post(`/web-security/scans/${scanId}/cancel`);
      showToast("Scan audit successfully cancelled", "info");
      await fetchData();
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to cancel scan", "error");
    }
  };

  const handleAddAllowlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPattern.trim()) return;
    try {
      await api.post("/web-security/allowlist", {
        pattern: newPattern.trim(),
        description: newPatternDesc.trim(),
      });
      showToast(`Pattern '${newPattern}' added to Target Allowlist`, "success");
      setNewPattern("");
      setNewPatternDesc("");
      fetchAllowlist();
    } catch (err: any) {
      showToast(err.response?.data?.message || "Failed to add allowlist entry", "error");
    }
  };

  const handleDeleteAllowlist = async (id: string) => {
    try {
      await api.delete(`/web-security/allowlist/${id}`);
      showToast("Allowlist entry removed", "info");
      fetchAllowlist();
    } catch (err: any) {
      showToast("Failed to delete allowlist entry", "error");
    }
  };

  const filteredFindings = findings.filter((f) => {
    const matchesSev = !severityFilter || f.severity.toLowerCase() === severityFilter.toLowerCase();
    const matchesSearch =
      !searchQuery ||
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const getScoreColor = (score: number) => {
    if (score >= 90) return "text-emerald-400 border-emerald-500/30 bg-emerald-500/10";
    if (score >= 75) return "text-cyan-400 border-cyan-500/30 bg-cyan-500/10";
    if (score >= 60) return "text-amber-400 border-amber-500/30 bg-amber-500/10";
    return "text-rose-400 border-rose-500/30 bg-rose-500/10";
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-rose-500/20 text-rose-300 border border-rose-500/40";
      case "high":
        return "bg-orange-500/20 text-orange-300 border border-orange-500/40";
      case "medium":
        return "bg-amber-500/20 text-amber-300 border border-amber-500/40";
      default:
        return "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40";
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with target matrix */}
      <CyberGridBackground variant="web-security" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-5 text-slate-200">
        {/* Page Header */}
        <SOCPageHeader
          title="Web Security Lab"
          tagline="ACTIVE POSTURE & VULNERABILITY AUDIT"
          subtitle="Authorized security assessment and web posture findings."
        icon={Globe}
        badge={{ label: "DEFENSIVE AUDIT", variant: "primary", pulse: true }}
        actions={
          <div className="flex items-center gap-3">
            <button
              onClick={() => {
                fetchAllowlist();
                setIsAllowlistModalOpen(true);
              }}
              className="flex items-center gap-2 px-3.5 py-2 rounded-xl cyber-panel-subtle hover:bg-[#0c244d] border border-[#1E3A8A]/50 text-xs font-medium text-slate-200 hover:text-cyan-300 transition font-mono"
            >
              <Shield className="w-4 h-4 text-cyan-400" />
              Target Allowlist
            </button>

            <button
              onClick={() => setIsScanModalOpen(true)}
              className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold shadow-lg shadow-cyan-500/20 transition font-mono"
            >
              <Play className="w-4 h-4" />
              New Security Audit
            </button>
          </div>
        }
      />

      {/* Real-World Safety & Scope Guarantee Banner */}
      <div className="p-4 rounded-xl cyber-panel-subtle border border-cyan-500/30 flex items-start gap-3.5 shadow-sm bg-[#040D21]/80 backdrop-blur-md">
        <ShieldCheck className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
              Safety & Authorization Policy Enforced
            </span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-cyan-300 border border-blue-500/20">
              RFC1918 • Loopback • Non-Destructive
            </span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            All security assessments execute non-destructive, rate-limited passive audits against strictly authorized targets (127.0.0.1, localhost, private IP subnets, or admin-approved domains). No exploit execution, denial-of-service, or credential brute-forcing is performed.
          </p>
        </div>
      </div>

      {/* Posture Score & Executive KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Posture Score Card */}
        <div className="cyber-panel p-5 flex items-center justify-between">
          <div>
            <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 block mb-1">
              Security Posture Score
            </span>
            <div className="flex items-baseline gap-2">
              <span className="text-3xl font-extrabold text-white">
                {posture ? posture.posture_score : 100}
              </span>
              <span className="text-xs text-slate-500 font-mono">/ 100.0</span>
            </div>
            <span className="text-[10px] text-slate-400 mt-1 block">
              Target: {posture?.target_host || "127.0.0.1"}
            </span>
          </div>
          <div
            className={`w-14 h-14 rounded-2xl flex items-center justify-center border font-bold text-xl ${getScoreColor(
              posture?.posture_score || 100
            )}`}
          >
            {posture ? (posture.posture_score >= 90 ? "A" : posture.posture_score >= 75 ? "B" : posture.posture_score >= 60 ? "C" : "D") : "A"}
          </div>
        </div>

        {/* Monitored Targets */}
        <div className="cyber-panel p-5">
          <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 block mb-1">
            Targets Monitored
          </span>
          <span className="text-3xl font-extrabold text-cyan-400 font-mono">
            {posture?.targets_monitored || 1}
          </span>
          <span className="text-[10px] text-slate-400 block mt-1">
            Localhost & Authorized Subnets
          </span>
        </div>

        {/* Active Findings */}
        <div className="cyber-panel p-5">
          <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 block mb-1">
            Active Findings
          </span>
          <span className="text-3xl font-extrabold text-amber-400 font-mono">
            {posture?.active_findings || 0}
          </span>
          <span className="text-[10px] text-slate-400 block mt-1">
            Requires configuration hardening
          </span>
        </div>

        {/* Critical Issues */}
        <div className="cyber-panel p-5">
          <span className="text-[11px] uppercase tracking-wider font-semibold text-slate-400 block mb-1">
            Critical Findings
          </span>
          <span className="text-3xl font-extrabold text-rose-400 font-mono">
            {posture?.critical_findings || 0}
          </span>
          <span className="text-[10px] text-slate-400 block mt-1">
            Immediate remediation priority
          </span>
        </div>
      </div>

      {/* Category Breakdown Progress Grid */}
      {posture?.breakdown && (
        <div className="cyber-panel p-5">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-4 flex items-center gap-2">
            <Sliders className="w-4 h-4 text-cyan-400" />
            Deterministic Posture Category Evaluation
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-6 gap-4">
            {Object.entries(posture.breakdown).map(([category, score]) => (
              <div key={category} className="p-3 rounded-lg bg-[#030a18]/90 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-medium truncate block mb-1">
                  {category}
                </span>
                <div className="flex items-baseline justify-between mb-1.5">
                  <span className="text-base font-bold text-white">{score}</span>
                  <span className="text-[10px] text-slate-400 font-mono">pts</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full"
                    style={{ width: `${Math.min(100, (score / 25) * 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Main Content Area: Scan History + Findings Table */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Recent Audit Scans */}
        <div className="cyber-panel p-5 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              Audit Scan History
            </h2>
            <button
              onClick={fetchData}
              className="p-1 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition"
              title="Refresh"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-2.5 max-h-[500px] overflow-y-auto pr-1">
            {scans.length === 0 ? (
              <div className="py-8 text-center text-xs text-slate-500">
                No web audit scans recorded. Launch your first scan above.
              </div>
            ) : (
              scans.map((s) => (
                <div
                  key={s.id}
                  onClick={() => {
                    setSelectedScan(s);
                    fetchFindings(s.id);
                  }}
                  className={`p-3.5 rounded-lg border cursor-pointer transition ${
                    selectedScan?.id === s.id
                      ? "bg-cyan-500/10 border-cyan-500/40 shadow-sm"
                      : "bg-slate-950/60 border-slate-800/80 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-slate-200">{s.target_host}</span>
                    <span
                      className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${
                        s.status === "completed"
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                      }`}
                    >
                      {s.status}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-slate-400">
                    <span>{s.scan_id}</span>
                    <span className="font-mono text-cyan-400 font-bold">{s.posture_score} pts</span>
                  </div>
                  <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500 border-t border-slate-800/50 pt-1.5">
                    <span>{new Date(s.started_at).toLocaleDateString()}</span>
                    <span>{s.findings_count} findings ({s.duration_seconds || 0}s)</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Right Column: Empirical Findings Table */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                Empirical Scan Findings ({filteredFindings.length})
              </h2>
              <p className="text-[10px] text-slate-500 mt-0.5">
                Session: {selectedScan ? selectedScan.scan_id : "None selected"}
              </p>
            </div>

            {/* Filter controls */}
            <div className="flex items-center gap-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter findings..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-8 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="px-2.5 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>

          {/* Selected Session Metadata & Service Exposure Bar */}
          {selectedScan && (
            <div className="p-3.5 rounded-lg bg-slate-950/90 border border-slate-800 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2.5 flex-wrap">
                  <div className="flex items-center gap-1.5 font-mono text-cyan-300">
                    <Globe className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{selectedScan.target_host}</span>
                  </div>
                  {selectedScan.resolved_ip && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                      Resolved IP: {selectedScan.resolved_ip}
                    </span>
                  )}
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Profile: {selectedScan.scan_profile}
                  </span>
                  <span
                    className={`text-[9px] uppercase font-bold px-1.5 py-0.5 rounded ${
                      selectedScan.status === "completed"
                        ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    }`}
                  >
                    {selectedScan.status}
                  </span>
                </div>

                <div className="flex items-center gap-3">
                  {(selectedScan.status === "running" || selectedScan.status === "queued") && (
                    <button
                      onClick={() => handleCancelScan(selectedScan.id)}
                      className="px-2.5 py-1 rounded text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30 hover:bg-rose-500/20 transition"
                    >
                      Cancel Scan
                    </button>
                  )}
                  <span className="font-mono text-xs text-white font-bold">
                    Score: {selectedScan.posture_score} / 100
                  </span>
                </div>
              </div>

              {/* Service Exposure Ports */}
              {selectedScan.exposed_services && selectedScan.exposed_services.length > 0 && (
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5 flex items-center gap-1.5">
                    <Shield className="w-3 h-3 text-cyan-400" />
                    Observed Open Network Ports ({selectedScan.exposed_services.length}):
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedScan.exposed_services.map((svc) => (
                      <span
                        key={svc.port}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-slate-300 flex items-center gap-1"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        Port {svc.port} ({svc.service})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Findings List */}
          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
            {filteredFindings.length === 0 ? (
              <div className="py-12 text-center text-xs text-slate-500">
                No findings match the current criteria for this scan session.
              </div>
            ) : (
              filteredFindings.map((f) => (
                <div
                  key={f.id}
                  className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 hover:border-slate-700 transition flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="space-y-1 max-w-xl">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[9px] uppercase font-bold px-2 py-0.5 rounded ${getSeverityBadge(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/40 px-1.5 py-0.5 rounded border border-cyan-800/40">
                        {f.http_method} {f.endpoint}
                      </span>
                      <span className="text-[10px] text-slate-400 font-medium">{f.category}</span>
                    </div>
                    <h4 className="text-xs font-semibold text-slate-200">{f.title}</h4>
                    <p className="text-[11px] text-slate-400 line-clamp-1">{f.description}</p>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    {f.related_alert_id ? (
                      <span className="flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-950/40 border border-emerald-800/50 px-2 py-1 rounded">
                        <CheckCircle2 className="w-3 h-3" /> Promoted
                      </span>
                    ) : (
                      <button
                        onClick={() => handlePromoteFinding(f)}
                        disabled={isPromoting}
                        className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30 hover:bg-amber-500/20 transition"
                      >
                        <Zap className="w-3 h-3" />
                        Promote to Alert
                      </button>
                    )}

                    <button
                      onClick={() => setSelectedFinding(f)}
                      className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition"
                      title="View Details"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <Modal
          isOpen={Boolean(selectedFinding)}
          onClose={() => setSelectedFinding(null)}
          title="Vulnerability Finding Inspection"
        >
          <div className="space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded ${getSeverityBadge(selectedFinding.severity)}`}>
                  {selectedFinding.severity}
                </span>
                <h3 className="text-sm font-bold text-white mt-1.5">{selectedFinding.title}</h3>
                <span className="text-[11px] text-slate-400">
                  {selectedFinding.finding_id} • Category: {selectedFinding.category}
                </span>
              </div>
              <div className="text-right">
                <span className="text-xs font-mono text-cyan-400 font-bold block">
                  Risk Score: {selectedFinding.risk_score} / 100
                </span>
                <span className="text-[10px] text-slate-500">
                  Confidence: {Math.round(selectedFinding.confidence * 100)}%
                </span>
              </div>
            </div>

            {/* Target & Standards Mapping */}
            <div className="grid grid-cols-2 gap-2 text-[11px]">
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[9px] uppercase font-bold">Target Endpoint</span>
                <span className="text-cyan-400 font-mono">
                  {selectedFinding.http_method} {selectedFinding.endpoint}
                </span>
              </div>
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[9px] uppercase font-bold">Compliance / MITRE</span>
                <span className="text-slate-300 font-mono">
                  {selectedFinding.cwe_id || "N/A"} • {selectedFinding.mitre_technique_id || "T1190"}
                </span>
              </div>
            </div>

            {/* Description */}
            <div>
              <span className="text-slate-400 font-semibold uppercase text-[10px] block mb-1">Description</span>
              <p className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 text-slate-300 leading-relaxed">
                {selectedFinding.description}
              </p>
            </div>

            {/* Evidence */}
            <div>
              <span className="text-slate-400 font-semibold uppercase text-[10px] block mb-1">Empirical Evidence</span>
              <pre className="p-2.5 rounded bg-slate-950 border border-slate-800 text-slate-300 font-mono text-[11px] overflow-x-auto whitespace-pre-wrap">
                {selectedFinding.evidence}
              </pre>
            </div>

            {/* Remediation */}
            <div>
              <span className="text-emerald-400 font-semibold uppercase text-[10px] block mb-1">Remediation Guidance</span>
              <p className="p-2.5 rounded bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 leading-relaxed">
                {selectedFinding.remediation}
              </p>
            </div>

            {/* Promotion Action Footer */}
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
              {selectedFinding.related_alert_id ? (
                <div className="flex items-center gap-2 text-emerald-400">
                  <CheckCircle2 className="w-4 h-4" />
                  <span className="font-semibold text-xs">
                    Linked to Alert: {selectedFinding.related_alert_id}
                  </span>
                </div>
              ) : (
                <button
                  onClick={() => handlePromoteFinding(selectedFinding)}
                  disabled={isPromoting}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-amber-600 to-orange-600 hover:from-amber-500 hover:to-orange-500 text-white font-semibold text-xs shadow-lg transition"
                >
                  <Zap className="w-4 h-4" />
                  {isPromoting ? "Promoting..." : "Promote to SOC Alert & Correlate"}
                </button>
              )}

              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/* Launch Scan Modal */}
      {isScanModalOpen && (
        <Modal
          isOpen={isScanModalOpen}
          onClose={() => setIsScanModalOpen(false)}
          title="Launch Authorized Security Audit"
        >
          <form onSubmit={handleLaunchScan} className="space-y-4 text-xs">
            <div>
              <label className="block font-medium text-slate-300 mb-1">
                Target URL / Host (Must be in authorized allowlist)
              </label>
              <input
                type="text"
                required
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="e.g. 127.0.0.1:8000 or localhost"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                <span className="text-[10px] text-slate-400">Quick Presets:</span>
                <button
                  type="button"
                  onClick={() => setTargetUrl("127.0.0.1:8000")}
                  className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-cyan-400 hover:bg-slate-800"
                >
                  127.0.0.1:8000 (Backend API)
                </button>
                <button
                  type="button"
                  onClick={() => setTargetUrl("127.0.0.1:5173")}
                  className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-cyan-400 hover:bg-slate-800"
                >
                  127.0.0.1:5173 (Frontend UI)
                </button>
                <button
                  type="button"
                  onClick={() => setTargetUrl("localhost")}
                  className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] font-mono text-cyan-400 hover:bg-slate-800"
                >
                  localhost
                </button>
              </div>
              <span className="text-[10px] text-slate-500 block mt-1">
                Authorized targets: localhost, 127.0.0.1, private RFC1918 subnets, or registered allowlist domains.
              </span>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block font-medium text-slate-300 mb-1">Audit Profile</label>
                <select
                  value={scanProfile}
                  onChange={(e) => setScanProfile(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="standard">Standard (Headers, Cookies, TLS, Exposure)</option>
                  <option value="quick">Quick (Headers & TLS Only)</option>
                  <option value="deep">Deep (Comprehensive Non-Destructive Probe)</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-slate-300 mb-1">Timeout (seconds)</label>
                <input
                  type="number"
                  min="2"
                  max="15"
                  value={timeoutSeconds}
                  onChange={(e) => setTimeoutSeconds(parseInt(e.target.value) || 5)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
              <button
                type="button"
                onClick={() => setIsScanModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isScanning}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold shadow-lg shadow-cyan-500/20"
              >
                <Play className="w-3.5 h-3.5" />
                {isScanning ? "Running Audit..." : "Execute Audit"}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {/* Target Allowlist Modal */}
      {isAllowlistModalOpen && (
        <Modal
          isOpen={isAllowlistModalOpen}
          onClose={() => setIsAllowlistModalOpen(false)}
          title="Target Authorization Allowlist"
        >
          <div className="space-y-4 text-xs">
            <p className="text-slate-400 leading-relaxed text-[11px]">
              The Web Security Lab strictly prevents unauthorized external testing. Only localhost, loopback, private subnets, and domains registered here can be audited.
            </p>

            {/* Add Entry Form */}
            <form onSubmit={handleAddAllowlist} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <span className="font-semibold text-slate-300 uppercase text-[10px] block">Register Authorized Domain / Subnet</span>
              <div className="grid grid-cols-2 gap-3">
                <input
                  type="text"
                  required
                  placeholder="e.g. api.internal.corp or *.corp"
                  value={newPattern}
                  onChange={(e) => setNewPattern(e.target.value)}
                  className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200 font-mono text-xs focus:outline-none focus:border-cyan-500"
                />
                <input
                  type="text"
                  placeholder="Description / Authorizing owner"
                  value={newPatternDesc}
                  onChange={(e) => setNewPatternDesc(e.target.value)}
                  className="px-3 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200 text-xs focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  className="flex items-center gap-1.5 px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold text-xs shadow"
                >
                  <Plus className="w-3.5 h-3.5" /> Add Target
                </button>
              </div>
            </form>

            {/* Allowlist Table */}
            <div className="max-h-60 overflow-y-auto space-y-2">
              {allowlist.length === 0 ? (
                <div className="py-6 text-center text-slate-500">
                  No custom allowlist patterns registered yet. Default loopback & RFC1918 apply.
                </div>
              ) : (
                allowlist.map((item) => (
                  <div
                    key={item.id}
                    className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <span className="font-mono text-cyan-400 font-bold block">{item.pattern}</span>
                      <span className="text-[10px] text-slate-400">{item.description || "No description"}</span>
                    </div>
                    <button
                      onClick={() => handleDeleteAllowlist(item.id)}
                      className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-900 transition"
                      title="Remove Target"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))
              )}
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setIsAllowlistModalOpen(false)}
                className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                Done
              </button>
            </div>
          </div>
        </Modal>
      )}
      </div>
    </div>
  );
};
