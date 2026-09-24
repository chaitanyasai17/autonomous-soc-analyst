import React, { useEffect, useState, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  UploadCloud,
  FileText,
  Play,
  RotateCcw,
  Trash2,
  Download,
  Eye,
  CheckCircle2,
  RefreshCw,
  Search,
  Filter,
  Layers,
  Database,
  SlidersHorizontal,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";
import { api } from "../services/api";
import { LogSource, SecurityLog, ParsedLog, RiskLevel } from "../types";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCStatCard } from "../components/common/SOCStatCard";
import { SOCButton } from "../components/common/SOCButton";
import { GlassCard } from "../components/common/GlassCard";

export const LogManagement: React.FC = () => {
  // Tabs: "files" vs "events"
  const [activeTab, setActiveTab] = useState<"files" | "events">("files");

  // Tab 1: Uploaded File State
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [totalFiles, setTotalFiles] = useState<number>(0);
  const [filePage, setFilePage] = useState<number>(1);
  const [fileSearch, setFileSearch] = useState<string>("");
  const [sourceFilter, setSourceFilter] = useState<string>("");
  const [isFilesLoading, setIsFilesLoading] = useState<boolean>(true);

  // Tab 2: Parsed Records State
  const [parsedEvents, setParsedEvents] = useState<ParsedLog[]>([]);
  const [totalEvents, setTotalEvents] = useState<number>(0);
  const [eventPage, setEventPage] = useState<number>(1);
  const [eventSearch, setEventSearch] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [eventTypeFilter, setEventTypeFilter] = useState<string>("");
  const [isEventsLoading, setIsEventsLoading] = useState<boolean>(false);
  const [activeEvent, setActiveEvent] = useState<ParsedLog | null>(null);

  // Statistics
  const [logStats, setLogStats] = useState<any | null>(null);

  // Upload State
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [selectedSource, setSelectedSource] = useState<LogSource>("endpoint");
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [isDragging, setIsDragging] = useState<boolean>(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const fetchStats = async () => {
    try {
      const res = await api.get("/logs/statistics");
      if (res.data?.data) {
        setLogStats(res.data.data);
      }
    } catch {
      // stats endpoint fallback
    }
  };

  const fetchLogs = async () => {
    setIsFilesLoading(true);
    try {
      const params: any = {
        skip: (filePage - 1) * 10,
        limit: 10,
      };
      if (fileSearch) params.search = fileSearch;
      if (sourceFilter) params.log_source = sourceFilter;

      const res = await api.get("/logs", { params });
      if (res.data) {
        setLogs(res.data.data || []);
        setTotalFiles(res.data.total || 0);
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to load uploaded log files.");
    } finally {
      setIsFilesLoading(false);
    }
  };

  const fetchParsedEvents = async () => {
    setIsEventsLoading(true);
    try {
      const params: any = {
        skip: (eventPage - 1) * 10,
        limit: 10,
      };
      if (eventSearch) params.search = eventSearch;
      if (severityFilter) params.severity = severityFilter;
      if (eventTypeFilter) params.event_type = eventTypeFilter;

      const res = await api.get("/parsed-logs", { params });
      if (res.data) {
        setParsedEvents(res.data.data || []);
        setTotalEvents(res.data.total || 0);
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to fetch parsed log events.");
    } finally {
      setIsEventsLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  useEffect(() => {
    if (activeTab === "files") {
      fetchLogs();
    } else {
      fetchParsedEvents();
    }
  }, [activeTab, filePage, fileSearch, sourceFilter, eventPage, eventSearch, severityFilter, eventTypeFilter]);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      toastError("Please select a file to upload.");
      return;
    }

    setIsUploading(true);
    const formData = new FormData();
    formData.append("file", selectedFile);
    formData.append("log_source", selectedSource);

    try {
      const res = await api.post("/logs/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      const uploadedLog = res.data?.data;
      success(`Uploaded '${selectedFile.name}' successfully. Auto-parsing...`);
      setSelectedFile(null);
      if (fileInputRef.current) fileInputRef.current.value = "";

      // Trigger automatic parsing immediately upon upload
      if (uploadedLog?.id) {
        try {
          const parseRes = await api.post(`/logs/${uploadedLog.id}/parse`);
          const count = parseRes.data?.data?.entries_created ?? 0;
          success(`Auto-parsed ${count} normalized events.`);
        } catch {
          // parsing error caught in table
        }
      }

      fetchStats();
      fetchLogs();
    } catch (err: any) {
      toastError(err.response?.data?.message || "File upload failed.");
    } finally {
      setIsUploading(false);
    }
  };

  const handleParse = async (logId: string) => {
    try {
      const res = await api.post(`/logs/${logId}/parse`);
      const count = res.data?.data?.entries_created ?? 0;
      success(`Log parsed successfully: ${count} normalized events generated.`);
      fetchStats();
      fetchLogs();
    } catch (err: any) {
      toastError(err.response?.data?.message || "Log parsing failed.");
    }
  };

  const handleReparse = async (logId: string) => {
    try {
      const res = await api.post(`/logs/${logId}/reparse`);
      const count = res.data?.data?.entries_created ?? 0;
      success(`Re-parsing complete: ${count} normalized events generated.`);
      fetchStats();
      fetchLogs();
    } catch (err: any) {
      toastError(err.response?.data?.message || "Log re-parsing failed.");
    }
  };

  const handleDelete = async (logId: string) => {
    if (!window.confirm("Are you sure you want to delete this log file and its parsed records?")) return;
    try {
      await api.delete(`/logs/${logId}`);
      success("Log file removed.");
      fetchStats();
      fetchLogs();
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to delete log file.");
    }
  };

  // Authenticated file download handler
  const handleDownloadFile = async (logId: string, filename: string) => {
    try {
      const res = await api.get(`/logs/${logId}/download`, {
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      success("Download started.");
    } catch (err: any) {
      toastError("Failed downloading log file.");
    }
  };

  const fileColumns: Column<SecurityLog>[] = [
    {
      header: "File Name",
      accessor: "original_filename",
      render: (item) => (
        <div className="flex items-center gap-2">
          <FileText className="w-4 h-4 text-cyan-400 shrink-0" />
          <span className="font-semibold text-white">{item.original_filename}</span>
        </div>
      ),
    },
    {
      header: "Log Source",
      accessor: "log_source",
      render: (item) => (
        <span className="px-2 py-0.5 rounded text-xs uppercase font-mono bg-slate-800 text-slate-300 border border-slate-700">
          {item.log_source}
        </span>
      ),
    },
    {
      header: "File Size",
      accessor: "file_size",
      render: (item) => (
        <span className="text-xs text-slate-400 font-mono">
          {(item.file_size / 1024).toFixed(1)} KB
        </span>
      ),
    },
    {
      header: "Ingestion Status",
      accessor: "processing_status",
      render: (item) => <StatusBadge status={item.processing_status} />,
    },
    {
      header: "Parsed Events",
      accessor: "event_count",
      render: (item) => (
        <span className="text-xs font-mono text-cyan-400 font-bold">
          {item.event_count ?? 0}
        </span>
      ),
    },
    {
      header: "Uploaded At",
      accessor: "upload_time",
      render: (item) => (
        <span className="text-xs text-slate-400 font-mono">
          {new Date(item.upload_time).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Actions",
      className: "text-right",
      render: (item) => (
        <div className="flex items-center justify-end gap-1.5">
          {item.processing_status !== "completed" ? (
            <button
              onClick={() => handleParse(item.id)}
              className="px-2.5 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1 transition-colors"
              title="Parse Log File"
            >
              <Play className="w-3 h-3" />
              <span>Parse</span>
            </button>
          ) : (
            <button
              onClick={() => handleReparse(item.id)}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
              title="Re-parse file"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          )}

          <Link
            to={`/logs/${item.id}`}
            className="p-1.5 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-300 hover:bg-cyan-900 transition-colors"
            title="Inspect parsed events in detail"
          >
            <Eye className="w-3.5 h-3.5" />
          </Link>

          <button
            onClick={() => handleDownloadFile(item.id, item.original_filename)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            title="Download raw file"
          >
            <Download className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={() => handleDelete(item.id)}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-red-950 text-slate-400 hover:text-red-400 transition-colors"
            title="Delete log"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      ),
    },
  ];

  const eventColumns: Column<ParsedLog>[] = [
    {
      header: "Timestamp",
      accessor: "timestamp",
      render: (item) => (
        <span className="font-mono text-xs text-slate-300">
          {new Date(item.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Severity",
      accessor: "severity",
      render: (item) => <SeverityBadge severity={item.severity} />,
    },
    {
      header: "Event Type",
      accessor: "event_type",
      render: (item) => (
        <span className="font-mono text-xs text-cyan-400 uppercase font-semibold">
          {item.event_type}
        </span>
      ),
    },
    {
      header: "Source / Host",
      render: (item) => (
        <div className="text-xs font-mono">
          <span className="text-slate-200">{item.hostname || "—"}</span>
          {item.source_ip && (
            <span className="text-slate-500 block text-[11px]">{item.source_ip}</span>
          )}
        </div>
      ),
    },
    {
      header: "User Identity",
      accessor: "username",
      render: (item) => (
        <span className="font-mono text-xs text-slate-300">
          {item.username || "—"}
        </span>
      ),
    },
    {
      header: "Normalized Message",
      accessor: "message",
      render: (item) => (
        <span className="max-w-xs truncate block text-xs text-slate-300 font-mono">
          {item.message || item.raw_log}
        </span>
      ),
    },
    {
      header: "Inspect",
      className: "text-right",
      render: (item) => (
        <button
          onClick={() => setActiveEvent(item)}
          className="px-2.5 py-1 rounded-lg bg-cyan-950 border border-cyan-800/50 text-cyan-300 text-xs font-semibold hover:bg-cyan-900 transition-colors"
        >
          Inspect
        </button>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background with network nodes */}
      <CyberGridBackground variant="detections" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="Log Management"
        tagline="TELEMETRY INGESTION PIPELINE"
        subtitle="Ingest, parse, normalize, and validate raw security telemetry logs."
        icon={Database}
        actions={
          <div className="flex items-center gap-2 cyber-panel-subtle p-1 rounded-xl border border-[#1E3A8A]/50 bg-[#030B1C]/80">
            <button
              onClick={() => setActiveTab("files")}
              className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all ${
                activeTab === "files"
                  ? "bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(0,217,255,0.4)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Log Files ({totalFiles})
            </button>
            <button
              onClick={() => setActiveTab("events")}
              className={`px-3.5 py-1.5 text-xs font-bold rounded-lg transition-all ${
                activeTab === "events"
                  ? "bg-cyan-500 text-slate-950 shadow-[0_0_15px_rgba(0,217,255,0.4)]"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Parsed Events ({logStats?.total_parsed_records ?? totalEvents})
            </button>
          </div>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <SOCStatCard
          label="Total Uploads"
          value={logStats?.total_uploads ?? totalFiles}
          icon={FileText}
          variant="cyan"
          subtitle="Indexed raw telemetry payloads"
        />

        <SOCStatCard
          label="Normalized Events"
          value={logStats?.total_parsed_records ?? totalEvents}
          icon={Layers}
          variant="blue"
          subtitle="Correlated schema events"
        />

        <SOCStatCard
          label="Parsing Success"
          value={
            logStats?.total_uploads
              ? `${Math.round(
                  ((logStats.by_processing_status?.completed || 0) / logStats.total_uploads) * 100
                )}%`
              : "100%"
          }
          icon={ShieldCheck}
          variant="emerald"
          subtitle={`${logStats?.by_processing_status?.completed || 0} of ${logStats?.total_uploads || 0} parsed`}
        />

        <SOCStatCard
          label="Active Parsers"
          value="JSON • CSV"
          icon={Database}
          variant="purple"
          subtitle="RFC 8259, Syslog 5424"
        />
      </div>

      {activeTab === "files" ? (
        <div className="space-y-6">
          {/* Drag and Drop Upload Area */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setIsDragging(true);
            }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            className={`cyber-panel border-2 border-dashed rounded-2xl p-6 transition-all duration-200 backdrop-blur-md ${
              isDragging
                ? "border-cyan-400 bg-cyan-950/30 shadow-[0_0_30px_rgba(0,217,255,0.2)]"
                : "border-[#1E3A8A]/60 hover:border-cyan-500/50"
            }`}
          >
            <div className="flex flex-col md:flex-row items-center justify-between gap-6">
              <div className="flex items-center gap-4">
                <div className="p-4 rounded-2xl bg-cyan-950/70 border border-cyan-800/40 text-cyan-400 shadow-lg shadow-cyan-950/30">
                  <UploadCloud className="w-8 h-8" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">
                    Ingest Telemetry Log Files
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Supports JSON (RFC 8259), CSV formatted telemetry, RFC 3164/5424 Syslog, and unstructured text up to 50MB.
                  </p>
                  {selectedFile && (
                    <div className="mt-2.5 flex items-center gap-2 text-xs font-mono text-cyan-300 bg-cyan-950/60 px-3 py-1 rounded-lg border border-cyan-800/40 w-fit">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>Selected: <strong>{selectedFile.name}</strong> ({(selectedFile.size / 1024).toFixed(1)} KB)</span>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
                <div>
                  <label className="block text-[10px] uppercase font-bold text-slate-400 mb-1">
                    Log Source Origin
                  </label>
                  <select
                    value={selectedSource}
                    onChange={(e) => setSelectedSource(e.target.value as LogSource)}
                    className="px-3 py-2 bg-slate-950 border border-slate-700 rounded-xl text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  >
                    <option value="endpoint">Endpoint Logs (EDR/Sysmon)</option>
                    <option value="firewall">Firewall / Network Logs</option>
                    <option value="ids_ips">IDS / IPS Snort/Suricata</option>
                    <option value="server">Linux / Windows Server Syslog</option>
                    <option value="application">Web & App Server Logs</option>
                    <option value="cloud">Cloud Audit (AWS/GCP/Azure)</option>
                  </select>
                </div>

                <div className="mt-auto">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileSelect}
                    accept=".csv,.json,.log,.txt"
                    className="hidden"
                    id="log-file-input"
                  />
                  <label
                    htmlFor="log-file-input"
                    className="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold cursor-pointer transition-colors block"
                  >
                    Browse Files
                  </label>
                </div>

                <div className="mt-auto">
                  <button
                    onClick={handleUpload}
                    disabled={!selectedFile || isUploading}
                    className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-teal-500 hover:from-cyan-400 hover:to-teal-400 text-slate-950 text-xs font-black shadow-lg shadow-cyan-500/20 disabled:opacity-40 transition-all flex items-center gap-2"
                  >
                    {isUploading ? (
                      <>
                        <span className="w-3.5 h-3.5 border-2 border-slate-950/30 border-t-slate-950 rounded-full animate-spin" />
                        <span>Ingesting...</span>
                      </>
                    ) : (
                      <span>Upload & Parse</span>
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Files Table */}
          <DataTable
            columns={fileColumns}
            data={logs}
            isLoading={isFilesLoading}
            total={totalFiles}
            page={filePage}
            pageSize={10}
            onPageChange={setFilePage}
            searchValue={fileSearch}
            onSearchChange={setFileSearch}
            searchPlaceholder="Filter files by filename..."
            actions={
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-300 focus:outline-none focus:ring-2 focus:ring-cyan-500"
              >
                <option value="">All Log Sources</option>
                <option value="endpoint">Endpoint</option>
                <option value="firewall">Firewall</option>
                <option value="ids_ips">IDS / IPS</option>
                <option value="server">Server</option>
                <option value="application">Application</option>
              </select>
            }
          />
        </div>
      ) : (
        /* Tab 2: Normalized Events Explorer */
        <div className="space-y-4">
          <DataTable
            columns={eventColumns}
            data={parsedEvents}
            isLoading={isEventsLoading}
            total={totalEvents}
            page={eventPage}
            pageSize={10}
            onPageChange={setEventPage}
            searchValue={eventSearch}
            onSearchChange={setEventSearch}
            searchPlaceholder="Search message, IP, username, hostname..."
            actions={
              <div className="flex items-center gap-2">
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

                <button
                  onClick={fetchParsedEvents}
                  className="p-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-400 hover:text-white"
                  title="Refresh Events"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
            }
          />
        </div>
      )}

      {/* Raw Event Inspector Modal */}
      <Modal
        isOpen={!!activeEvent}
        onClose={() => setActiveEvent(null)}
        title="Parsed Security Event Telemetry Inspector"
        maxWidth="2xl"
      >
        {activeEvent && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Target Host</span>
                <span className="text-white font-bold">{activeEvent.hostname || "N/A"}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Identity</span>
                <span className="text-white font-bold">{activeEvent.username || "N/A"}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Event Type</span>
                <span className="text-cyan-400 font-bold uppercase">{activeEvent.event_type}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Severity</span>
                <SeverityBadge severity={activeEvent.severity} />
              </div>
            </div>

            <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono">
              <span className="text-slate-500 block mb-1">Network Transmission Route:</span>
              <span className="text-slate-200">
                {activeEvent.source_ip || "Internal"}
                {activeEvent.source_port ? `:${activeEvent.source_port}` : ""} &rarr;{" "}
                {activeEvent.destination_ip || "Internal"}
                {activeEvent.destination_port ? `:${activeEvent.destination_port}` : ""} (
                {activeEvent.protocol || "TCP/IP"})
              </span>
            </div>

            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                Normalized Telemetry Message
              </label>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 break-all">
                {activeEvent.message || "No message field"}
              </div>
            </div>

            <div>
              <label className="text-xs font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                Raw Log Payload Evidence
              </label>
              <pre className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                {activeEvent.raw_log}
              </pre>
            </div>
          </div>
        )}
      </Modal>
      </div>
    </div>
  );
};
