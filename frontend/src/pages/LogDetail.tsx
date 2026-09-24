import React, { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import { ArrowLeft, Play, ShieldAlert, FileText, CheckCircle2 } from "lucide-react";
import { api } from "../services/api";
import { ParsedLog, SecurityLog } from "../types";
import { SeverityBadge, StatusBadge } from "../components/common/Badge";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCButton } from "../components/common/SOCButton";

export const LogDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [log, setLog] = useState<SecurityLog | null>(null);
  const [parsedEvents, setParsedEvents] = useState<ParsedLog[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isDetecting, setIsDetecting] = useState<boolean>(false);
  const [activeEvent, setActiveEvent] = useState<ParsedLog | null>(null);

  const { success, error: toastError } = useToast();

  const fetchLogDetails = async () => {
    if (!id) return;
    setIsLoading(true);
    try {
      const logRes = await api.get(`/logs/${id}`);
      setLog(logRes.data?.data || null);

      const eventsRes = await api.get(`/logs/${id}/parsed-records`, {
        params: { skip: (page - 1) * 10, limit: 10 },
      });
      setParsedEvents(eventsRes.data?.data || []);
      setTotal(eventsRes.data?.total || 0);
    } catch (err: any) {
      toastError("Failed to fetch parsed log events.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchLogDetails();
  }, [id, page]);

  const handleRunDetection = async () => {
    if (!id) return;
    setIsDetecting(true);
    try {
      const res = await api.post(`/detections/run-file/${id}`);
      const summary = res.data?.data;
      success(
        `Sigma detection run complete: ${summary.detections_created} threats identified across ${summary.events_scanned} events.`
      );
      navigate("/detections");
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed running Sigma detections.");
    } finally {
      setIsDetecting(false);
    }
  };

  const columns: Column<ParsedLog>[] = [
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
      header: "Host",
      accessor: "hostname",
      render: (item) => (
        <span className="font-mono text-xs text-cyan-300">{item.hostname || "—"}</span>
      ),
    },
    {
      header: "User",
      accessor: "username",
      render: (item) => (
        <span className="font-mono text-xs text-slate-200">{item.username || "—"}</span>
      ),
    },
    {
      header: "Source IP",
      accessor: "source_ip",
      render: (item) => (
        <span className="font-mono text-xs text-slate-400">{item.source_ip || "—"}</span>
      ),
    },
    {
      header: "Severity",
      accessor: "severity",
      render: (item) => <SeverityBadge severity={item.severity} />,
    },
    {
      header: "Message Telemetry",
      accessor: "message",
      render: (item) => (
        <span className="max-w-xs truncate block text-xs text-slate-300">
          {item.message || item.raw_log}
        </span>
      ),
    },
    {
      header: "Details",
      render: (item) => (
        <button
          onClick={() => setActiveEvent(item)}
          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-cyan-400 font-medium"
        >
          Inspect
        </button>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      {/* Deep Cyber Background */}
      <CyberGridBackground variant="detections" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 cyber-panel p-5 rounded-xl">
        <div className="flex items-center gap-3">
          <Link
            to="/logs"
            className="p-2 rounded-lg bg-[#040d21] border border-[#1E3A8A]/50 hover:bg-[#0c244d] text-slate-300 hover:text-cyan-300 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              <span className="w-2 h-5 bg-cyan-400 rounded-full shadow-[0_0_10px_#00D9FF]"></span>
              <span>{log?.original_filename || "Log Details"}</span>
            </h1>
            <p className="text-xs text-slate-400 font-mono mt-0.5">
              Source: <span className="text-cyan-300">{log?.log_source}</span> • Size: {((log?.file_size || 0) / 1024).toFixed(1)} KB • Status: <span className="text-emerald-400 font-semibold uppercase">{log?.processing_status}</span>
            </p>
          </div>
        </div>

        <SOCButton
          variant="danger"
          size="sm"
          icon={ShieldAlert}
          loading={isDetecting}
          onClick={handleRunDetection}
        >
          Execute Sigma Detections
        </SOCButton>
      </div>

      {/* Events Table */}
      <DataTable
        columns={columns}
        data={parsedEvents}
        isLoading={isLoading}
        total={total}
        page={page}
        pageSize={10}
        onPageChange={setPage}
        searchPlaceholder="Filter parsed events..."
      />

      {/* Raw Event Modal */}
      <Modal
        isOpen={!!activeEvent}
        onClose={() => setActiveEvent(null)}
        title="Parsed Event Telemetry Inspector"
        maxWidth="2xl"
      >
        {activeEvent && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Hostname / Target</span>
                <span className="text-white font-semibold">{activeEvent.hostname || "N/A"}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Account Identity</span>
                <span className="text-white font-semibold">{activeEvent.username || "N/A"}</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Network Route</span>
                <span className="text-white font-semibold">
                  {activeEvent.source_ip || "—"} &rarr; {activeEvent.destination_ip || "—"}
                </span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block mb-1">Severity Classification</span>
                <SeverityBadge severity={activeEvent.severity} />
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                Normalized Telemetry Message
              </label>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 break-all">
                {activeEvent.message || "No normalized message field available."}
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1.5">
                Raw Log Payload
              </label>
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
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
