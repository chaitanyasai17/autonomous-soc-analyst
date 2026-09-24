import React from "react";

export const CardSkeleton: React.FC<{ count?: number; className?: string }> = ({
  count = 1,
  className = "",
}) => {
  return (
    <>
      {Array.from({ length: count }).map((_, idx) => (
        <div
          key={idx}
          className={`p-4 cyber-panel-subtle rounded-xl animate-pulse space-y-3 ${className}`}
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[rgba(14,35,70,0.6)]" />
            <div className="space-y-1.5 flex-1">
              <div className="h-3 w-24 bg-[rgba(14,35,70,0.7)] rounded" />
              <div className="h-6 w-16 bg-[rgba(14,35,70,0.9)] rounded" />
            </div>
          </div>
          <div className="h-2 w-full bg-[rgba(14,35,70,0.4)] rounded pt-1" />
        </div>
      ))}
    </>
  );
};

export const TableSkeleton: React.FC<{ rows?: number; columns?: number }> = ({
  rows = 5,
  columns = 5,
}) => {
  return (
    <div className="cyber-panel rounded-xl overflow-hidden animate-pulse">
      <div className="p-4 border-b border-[rgba(0,183,255,0.15)] flex justify-between items-center bg-[rgba(3,11,28,0.85)]">
        <div className="h-4 w-40 bg-[rgba(14,35,70,0.8)] rounded" />
        <div className="h-7 w-28 bg-[rgba(14,35,70,0.6)] rounded-lg" />
      </div>
      <div className="divide-y divide-[rgba(21,34,56,0.6)]">
        {Array.from({ length: rows }).map((_, rIdx) => (
          <div key={rIdx} className="px-4 py-3.5 flex items-center gap-4">
            {Array.from({ length: columns }).map((_, cIdx) => (
              <div
                key={cIdx}
                className="h-3.5 bg-[rgba(14,35,70,0.6)] rounded"
                style={{ width: `${Math.max(12, 100 / columns - 3)}%` }}
              />
            ))}
          </div>
        ))}
      </div>
    </div>
  );
};

export const ChartSkeleton: React.FC<{ height?: string }> = ({
  height = "h-64",
}) => {
  return (
    <div
      className={`cyber-panel rounded-xl p-5 animate-pulse flex flex-col justify-between ${height}`}
    >
      <div className="flex justify-between items-center border-b border-[rgba(0,183,255,0.15)] pb-3">
        <div className="h-4 w-48 bg-[rgba(14,35,70,0.8)] rounded" />
        <div className="h-4 w-20 bg-[rgba(14,35,70,0.5)] rounded" />
      </div>
      <div className="flex items-end gap-3 h-36 pt-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <div
            key={i}
            className="flex-1 bg-[rgba(14,35,70,0.6)] rounded-t"
            style={{ height: `${20 + ((i * 17) % 70)}%` }}
          />
        ))}
      </div>
      <div className="h-2 w-full bg-[rgba(14,35,70,0.4)] rounded mt-3" />
    </div>
  );
};

export const PageSkeleton: React.FC = () => {
  return (
    <div className="space-y-5 animate-pulse">
      <div className="flex justify-between items-center pb-3 border-b border-[rgba(0,183,255,0.15)]">
        <div className="space-y-2">
          <div className="h-7 w-64 bg-[rgba(14,35,70,0.8)] rounded" />
          <div className="h-3.5 w-96 bg-[rgba(14,35,70,0.5)] rounded" />
        </div>
        <div className="h-9 w-32 bg-[rgba(14,35,70,0.7)] rounded-xl" />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <CardSkeleton count={4} />
      </div>
      <TableSkeleton rows={6} columns={6} />
    </div>
  );
};
