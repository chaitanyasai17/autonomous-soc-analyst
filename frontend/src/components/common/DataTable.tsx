import React from "react";
import { ChevronLeft, ChevronRight, Search } from "lucide-react";

export interface Column<T> {
  header: string;
  accessor?: keyof T;
  render?: (item: T) => React.ReactNode;
  className?: string;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  isLoading?: boolean;
  total?: number;
  page?: number;
  pageSize?: number;
  onPageChange?: (page: number) => void;
  searchValue?: string;
  onSearchChange?: (val: string) => void;
  searchPlaceholder?: string;
  emptyMessage?: string;
  actions?: React.ReactNode;
}

export function DataTable<T extends { id?: string | number }>({
  columns = [],
  data = [],
  isLoading = false,
  total = 0,
  page = 1,
  pageSize = 10,
  onPageChange,
  searchValue,
  onSearchChange,
  searchPlaceholder = "Search records...",
  emptyMessage = "No records found.",
  actions,
}: DataTableProps<T>) {
  const safeColumns = Array.isArray(columns) ? columns : [];
  const safeData = Array.isArray(data) ? data : [];
  const totalPages = Math.max(1, Math.ceil(total / (pageSize || 10)));

  return (
    <div className="cyber-panel rounded-xl overflow-hidden shadow-[0_10px_35px_rgba(2,6,23,0.7)]">
      {/* Table Toolbar */}
      {(onSearchChange || actions) && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4 p-4 border-b border-[#1E3A8A]/40 bg-[#040D21]/60 backdrop-blur-md">
          {onSearchChange ? (
            <div className="relative w-full sm:w-80">
              <Search className="absolute left-3 top-2.5 w-4 h-4 text-cyan-400/70" />
              <input
                type="text"
                value={searchValue || ""}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder={searchPlaceholder}
                className="w-full pl-9 pr-4 py-1.5 bg-[#020617]/80 border border-[#1E3A8A]/60 rounded-lg text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-500/30 transition-all font-mono text-xs"
              />
            </div>
          ) : (
            <div />
          )}
          {actions && <div className="flex items-center gap-3">{actions}</div>}
        </div>
      )}

      {/* Table Content */}
      <div className="overflow-x-auto">
        <table className="cyber-table w-full text-left text-sm text-slate-300">
          <thead className="bg-[#030B1C]/90 text-[11px] uppercase tracking-wider text-slate-400 font-semibold border-b border-[#1E3A8A]/50">
            <tr>
              {safeColumns.map((col, idx) => (
                <th key={idx} className={`px-5 py-3.5 ${col.className || ""}`}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E3A8A]/25 font-mono text-xs">
            {isLoading ? (
              Array.from({ length: 5 }).map((_, rIdx) => (
                <tr key={rIdx} className="animate-pulse">
                  {safeColumns.map((_, cIdx) => (
                    <td key={cIdx} className="px-5 py-4">
                      <div className="h-4 bg-[#0a1e42]/60 rounded w-3/4"></div>
                    </td>
                  ))}
                </tr>
              ))
            ) : safeData.length === 0 ? (
              <tr>
                <td colSpan={Math.max(1, safeColumns.length)} className="text-center py-12 text-slate-500 font-sans text-sm">
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              safeData.map((item, rowIdx) => (
                <tr
                  key={item?.id || rowIdx}
                  className="hover:bg-[#00D9FF]/[0.04] transition-colors duration-150 group"
                >
                  {safeColumns.map((col, colIdx) => {
                    let cellContent: React.ReactNode = "";
                    try {
                      if (col.render) {
                        cellContent = col.render(item);
                      } else if (col.accessor && item) {
                        cellContent = String(item[col.accessor] ?? "");
                      }
                    } catch {
                      cellContent = "—";
                    }

                    return (
                      <td key={colIdx} className={`px-5 py-3.5 font-sans group-hover:text-slate-100 ${col.className || ""}`}>
                        {cellContent}
                      </td>
                    );
                  })}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {onPageChange && total > 0 && (
        <div className="flex items-center justify-between px-5 py-3.5 border-t border-[#1E3A8A]/40 bg-[#030B1C]/70 text-xs text-slate-400">
          <span>
            Showing <strong className="text-cyan-300 font-mono">{(page - 1) * pageSize + 1}</strong> to{" "}
            <strong className="text-cyan-300 font-mono">{Math.min(page * pageSize, total)}</strong> of{" "}
            <strong className="text-cyan-300 font-mono">{total}</strong> records
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => onPageChange(page - 1)}
              disabled={page <= 1 || isLoading}
              className="p-1 rounded bg-[#0a1b38] hover:bg-[#122e5e] border border-[#1E3A8A]/60 text-slate-300 hover:text-cyan-300 disabled:opacity-40 disabled:hover:bg-[#0a1b38] disabled:hover:text-slate-300 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2 font-mono text-slate-300">
              Page {page} of {totalPages}
            </span>
            <button
              onClick={() => onPageChange(page + 1)}
              disabled={page >= totalPages || isLoading}
              className="p-1 rounded bg-[#0a1b38] hover:bg-[#122e5e] border border-[#1E3A8A]/60 text-slate-300 hover:text-cyan-300 disabled:opacity-40 disabled:hover:bg-[#0a1b38] disabled:hover:text-slate-300 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
