import React, { Suspense, useState, useRef, useEffect } from "react";
import { Outlet, useLocation } from "react-router-dom";
import { Sidebar } from "../components/common/Sidebar";
import { Navbar } from "../components/common/Navbar";
import { ErrorBoundary } from "../components/common/ErrorBoundary";

const ModuleLoadingSkeleton: React.FC = () => {
  return (
    <div className="space-y-6 animate-pulse p-2">
      {/* Header Skeleton */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-[rgba(0,183,255,0.15)]">
        <div className="space-y-2">
          <div className="h-6 w-64 bg-[rgba(14,35,70,0.8)] rounded-lg" />
          <div className="h-4 w-96 bg-[rgba(14,35,70,0.5)] rounded-md" />
        </div>
        <div className="flex items-center gap-2">
          <div className="h-9 w-28 bg-[rgba(14,35,70,0.7)] rounded-xl" />
          <div className="h-9 w-32 bg-[rgba(14,35,70,0.7)] rounded-xl" />
        </div>
      </div>

      {/* KPI Cards Skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {[1, 2, 3, 4, 5].map((i) => (
          <div key={i} className="p-4 rounded-xl cyber-panel-subtle space-y-3">
            <div className="h-3 w-24 bg-[rgba(14,35,70,0.7)] rounded" />
            <div className="h-7 w-16 bg-[rgba(14,35,70,0.9)] rounded" />
            <div className="h-2 w-32 bg-[rgba(14,35,70,0.4)] rounded" />
          </div>
        ))}
      </div>

      {/* Main Content Area Skeleton */}
      <div className="rounded-xl cyber-panel p-5 space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-[rgba(0,183,255,0.15)]">
          <div className="h-5 w-48 bg-[rgba(14,35,70,0.8)] rounded" />
          <div className="h-8 w-60 bg-[rgba(14,35,70,0.5)] rounded-lg" />
        </div>
        <div className="space-y-2 pt-2">
          {[1, 2, 3, 4, 5].map((row) => (
            <div
              key={row}
              className="h-10 w-full bg-[rgba(4,13,28,0.7)] rounded-lg flex items-center px-4 gap-4 border border-[rgba(0,183,255,0.1)]"
            >
              <div className="h-3 w-16 bg-[rgba(14,35,70,0.7)] rounded" />
              <div className="h-3 w-48 bg-[rgba(14,35,70,0.8)] rounded flex-1" />
              <div className="h-3 w-20 bg-[rgba(14,35,70,0.6)] rounded" />
              <div className="h-3 w-24 bg-[rgba(14,35,70,0.5)] rounded" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export const AppLayout: React.FC = () => {
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  const mainRef = useRef<HTMLElement>(null);
  const location = useLocation();

  const toggleSidebar = () => {
    setIsSidebarCollapsed((prev) => !prev);
  };

  // Ensure scroll is reset to top on route navigation so the page header is always at the top
  useEffect(() => {
    if ("scrollRestoration" in window.history) {
      window.history.scrollRestoration = "manual";
    }
    if (mainRef.current) {
      mainRef.current.scrollTop = 0;
    }
    window.scrollTo(0, 0);
  }, [location.pathname]);

  return (
    <div className="flex h-screen w-screen bg-[#020617] text-slate-100 overflow-hidden font-sans">
      {/* Fixed Persistent Sidebar */}
      <Sidebar
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={toggleSidebar}
      />

      {/* Main Content Area with Persistent Navbar */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden bg-[#020617]">
        <Navbar
          isSidebarCollapsed={isSidebarCollapsed}
          onToggleSidebar={toggleSidebar}
        />
        <main ref={mainRef} className="flex-1 overflow-y-auto p-4 sm:p-6 bg-[#020617] relative scroll-smooth">
          <div className="w-full max-w-[1720px] mx-auto space-y-5 relative z-10">
            <ErrorBoundary moduleName="SOC Module">
              <Suspense fallback={<ModuleLoadingSkeleton />}>
                <div className="animate-fade-in relative min-h-full">
                  <Outlet />
                </div>
              </Suspense>
            </ErrorBoundary>
          </div>
        </main>
      </div>
    </div>
  );
};
