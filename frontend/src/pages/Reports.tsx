import React, { useEffect, useState } from "react";
import {
  FileText,
  Download,
  Plus,
  RefreshCw,
  FileCheck,
  FileSpreadsheet,
} from "lucide-react";
import { api } from "../services/api";
import { Report } from "../types";
import { DataTable, Column } from "../components/common/DataTable";
import { Modal } from "../components/common/Modal";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

export const Reports: React.FC = () => {
  const [reports, setReports] = useState<Report[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [page, setPage] = useState<number>(1);
  const [typeFilter, setTypeFilter] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Generate Report Modal
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [reportName, setReportName] = useState("");
  const [reportType, setReportType] = useState<"pdf" | "csv">("pdf");
  const [isGenerating, setIsGenerating] = useState(false);

  const { success, error: toastError } = useToast();

  const fetchReports = async () => {
    setIsLoading(true);
    try {
      const params: any = {
        skip: (page - 1) * 10,
        limit: 10,
      };
      if (typeFilter) params.report_type = typeFilter;

      const res = await api.get("/reports", { params });
      if (res.data) {
        setReports(res.data.data || []);
        setTotal(res.data.total || 0);
      }
    } catch (err: any) {
      toastError("Failed to fetch generated reports list.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchReports();
  }, [page, typeFilter]);

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reportName.trim()) return;
    setIsGenerating(true);
    try {
      const res = await api.post("/reports/generate", {
        report_name: reportName,
        report_type: reportType,
      });
      if (res.data?.success) {
        success(`Report '${reportName}' generated successfully.`);
        setIsModalOpen(false);
        setReportName("");
        fetchReports();
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to generate report.");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleDownload = async (report: Report) => {
    try {
      const res = await api.get(`/reports/${report.id}/download`, {
        responseType: "blob",
      });
      const blob = new Blob([res.data], {
        type: report.report_type === "pdf" ? "application/pdf" : "text/csv",
      });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      const extension = report.report_type === "pdf" ? ".pdf" : ".csv";
      link.setAttribute(
        "download",
        `${report.report_name.replace(/\s+/g, "_")}${extension}`
      );
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      success("Report download started.");
    } catch (err: any) {
      toastError("Failed to download report artifact.");
    }
  };

  const columns: Column<Report>[] = [
    {
      header: "Report Name",
      render: (rep) => (
        <div className="flex items-center gap-2.5">
          {rep.report_type === "pdf" ? (
            <FileCheck className="w-5 h-5 text-red-400 shrink-0" />
          ) : (
            <FileSpreadsheet className="w-5 h-5 text-emerald-400 shrink-0" />
          )}
          <span className="font-semibold text-slate-100">{rep.report_name}</span>
        </div>
      ),
    },
    {
      header: "Format",
      render: (rep) => (
        <span
          className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold uppercase tracking-wider ${
            rep.report_type === "pdf"
              ? "bg-red-950/80 text-red-400 border border-red-800/50"
              : "bg-emerald-950/80 text-emerald-400 border border-emerald-800/50"
          }`}
        >
          {rep.report_type.toUpperCase()}
        </span>
      ),
    },
    {
      header: "Generated Date",
      render: (rep) => (
        <span className="text-xs text-slate-400 font-mono">
          {new Date(rep.generated_at).toLocaleString()}
        </span>
      ),
    },
    {
      header: "Action",
      className: "text-right",
      render: (rep) => (
        <button
          onClick={() => handleDownload(rep)}
          className="inline-flex items-center gap-1.5 px-3 py-1 text-xs font-semibold bg-cyan-950/80 text-cyan-300 hover:bg-cyan-900 border border-cyan-700/50 rounded-lg transition-colors"
        >
          <Download className="w-3.5 h-3.5" />
          Download
        </button>
      ),
    },
  ];

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="reports" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header & Generate Button */}
      <SOCPageHeader
        title="Security Reports"
        tagline="EXECUTIVE & AUDIT EXPORTS"
        subtitle="Investigation reports, exports, and security summaries."
        icon={FileText}
        badgeText={`${total} Artifacts Available`}
        actions={
          <SOCButton
            variant="primary"
            onClick={() => setIsModalOpen(true)}
            icon={<Plus className="w-4 h-4" />}
            glow
          >
            Generate New Report
          </SOCButton>
        }
      />

      {/* Filter bar */}
      <div className="cyber-panel p-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-xs text-slate-400 font-bold uppercase tracking-wider">
            Format:
          </span>
          <select
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value);
              setPage(1);
            }}
            className="bg-[#030a18]/90 border border-slate-700/80 text-slate-200 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
          >
            <option value="">All Formats</option>
            <option value="pdf">PDF Executive Brief</option>
            <option value="csv">CSV Telemetry Log</option>
          </select>
        </div>

        <button
          onClick={fetchReports}
          className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-[#030a18] rounded-lg transition-colors border border-transparent hover:border-cyan-500/30"
          title="Refresh Reports"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* Reports Table */}
      <DataTable
        columns={columns}
        data={reports}
        isLoading={isLoading}
        page={page}
        pageSize={10}
        total={total}
        onPageChange={setPage}
        emptyMessage="No reports generated yet. Click 'Generate New Report' to create your first SOC artifact."
      />

      {/* Generate Report Modal */}
      <Modal
        isOpen={isModalOpen}
        onClose={() => setIsModalOpen(false)}
        title="Generate SOC Incident & Posture Report"
        maxWidth="md"
      >
        <form onSubmit={handleGenerateReport} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
              Report Title
            </label>
            <input
              type="text"
              required
              value={reportName}
              onChange={(e) => setReportName(e.target.value)}
              placeholder="e.g. Q3 Executive Threat & Incident Posture"
              className="w-full bg-[#030a18]/90 border border-slate-700 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
              Artifact Format
            </label>
            <div className="grid grid-cols-2 gap-3">
              <label
                className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center gap-3 ${
                  reportType === "pdf"
                    ? "bg-red-950/30 border-red-500/80 text-slate-100 shadow-md shadow-red-950/30"
                    : "bg-[#030a18]/80 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <input
                  type="radio"
                  name="reportType"
                  value="pdf"
                  checked={reportType === "pdf"}
                  onChange={() => setReportType("pdf")}
                  className="hidden"
                />
                <FileCheck className="w-5 h-5 text-red-400" />
                <div>
                  <p className="text-xs font-bold text-slate-200">PDF Document</p>
                  <p className="text-[11px] text-slate-400">Executive metrics & tables</p>
                </div>
              </label>

              <label
                className={`p-3 rounded-xl border cursor-pointer transition-all flex items-center gap-3 ${
                  reportType === "csv"
                    ? "bg-emerald-950/30 border-emerald-500/80 text-slate-100 shadow-md shadow-emerald-950/30"
                    : "bg-[#030a18]/80 border-slate-800 text-slate-400 hover:border-slate-700"
                }`}
              >
                <input
                  type="radio"
                  name="reportType"
                  value="csv"
                  checked={reportType === "csv"}
                  onChange={() => setReportType("csv")}
                  className="hidden"
                />
                <FileSpreadsheet className="w-5 h-5 text-emerald-400" />
                <div>
                  <p className="text-xs font-bold text-slate-200">CSV Export</p>
                  <p className="text-[11px] text-slate-400">Raw tabular security telemetry</p>
                </div>
              </label>
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
            <SOCButton
              type="button"
              variant="ghost"
              onClick={() => setIsModalOpen(false)}
            >
              Cancel
            </SOCButton>
            <SOCButton
              type="submit"
              variant="primary"
              disabled={isGenerating}
            >
              {isGenerating ? "Compiling..." : "Generate Artifact"}
            </SOCButton>
          </div>
        </form>
      </Modal>
      </div>
    </div>
  );
};
