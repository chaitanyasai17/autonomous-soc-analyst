import React from "react";
import { NavLink } from "react-router-dom";
import {
  ShieldAlert,
  LayoutDashboard,
  Laptop,
  FileText,
  Target,
  BarChart3,
  FileCode,
  Network,
  Gauge,
  AlertOctagon,
  Briefcase,
  Fingerprint,
  Clock,
  GitCommit,
  Globe,
  Crosshair,
  Sparkles,
  Activity,
  ScrollText,
  Settings,
  ChevronsLeft,
  ChevronsRight,
} from "lucide-react";

import { useNotificationBadges } from "../../hooks/useNotificationBadges";

interface SidebarProps {
  isCollapsed?: boolean;
  onToggleCollapse?: () => void;
}

interface NavItem {
  name: string;
  path: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string | number | null;
  badgeTooltip?: string;
  badgeColor?: "red" | "purple" | "cyan" | "gray";
}

export const Sidebar: React.FC<SidebarProps> = ({
  isCollapsed = false,
  onToggleCollapse,
}) => {
  const { alerts, incidents } = useNotificationBadges();

  const alertBadgeValue = alerts.error
    ? "—"
    : alerts.loading
    ? null
    : alerts.count;
  const alertBadgeTooltip = alerts.error
    ? "Failed to load alert count"
    : alerts.loading
    ? "Loading alerts count..."
    : `${alerts.count ?? 0} untriaged alerts`;

  const incidentBadgeValue = incidents.error
    ? "—"
    : incidents.loading
    ? null
    : incidents.count;
  const incidentBadgeTooltip = incidents.error
    ? "Failed to load incident count"
    : incidents.loading
    ? "Loading incidents count..."
    : `${incidents.count ?? 0} active incidents`;

  const operationsNav: NavItem[] = [
    { name: "Dashboard", path: "/", icon: LayoutDashboard },
    { name: "Endpoints", path: "/endpoints", icon: Laptop },
    { name: "Log Management", path: "/logs", icon: FileText },
    { name: "Detections", path: "/detections", icon: Target },
    { name: "Detection Analytics", path: "/detection-analytics", icon: BarChart3 },
    { name: "Sigma Rules", path: "/sigma", icon: FileCode },
    { name: "MITRE ATT&CK", path: "/mitre", icon: Network },
    { name: "Risk Analysis", path: "/risk", icon: Gauge },
    {
      name: "Alerts",
      path: "/alerts",
      icon: AlertOctagon,
      badge: alertBadgeValue,
      badgeColor: alerts.error ? "gray" : "red",
      badgeTooltip: alertBadgeTooltip,
    },
    {
      name: "Incidents",
      path: "/incidents",
      icon: Briefcase,
      badge: incidentBadgeValue,
      badgeColor: incidents.error ? "gray" : "purple",
      badgeTooltip: incidentBadgeTooltip,
    },
  ];

  const intelligenceNav: NavItem[] = [
    { name: "IOC Explorer", path: "/iocs", icon: Fingerprint },
    { name: "Evidence Timeline", path: "/evidence-timeline", icon: Clock },
    { name: "Pipeline Trace", path: "/pipeline", icon: GitCommit },
    { name: "Web Security Lab", path: "/web-security", icon: Globe },
    { name: "Attack Simulator", path: "/simulator", icon: Crosshair },
    { name: "AI Threat Copilot", path: "/ai", icon: Sparkles },
    { name: "SOC Health", path: "/soc-health", icon: Activity },
    { name: "Audit Trail", path: "/audit", icon: ScrollText },
    { name: "Reports", path: "/reports", icon: BarChart3 },
    { name: "Settings", path: "/settings", icon: Settings },
  ];

  const renderBadge = (
    badge?: string | number | null,
    color?: "red" | "purple" | "cyan" | "gray",
    tooltip?: string
  ) => {
    if (badge === undefined || badge === null) return null;
    // Handle zero: consistently hide when 0
    if (badge === 0) return null;

    const colorClasses = {
      red: "bg-red-500/20 text-red-400 border-red-500/40 hover:bg-red-500/30",
      purple: "bg-purple-500/20 text-purple-300 border-purple-500/40 hover:bg-purple-500/30",
      cyan: "bg-cyan-500/20 text-cyan-300 border-cyan-500/40 hover:bg-cyan-500/30",
      gray: "bg-slate-800 text-slate-400 border-slate-700",
    };

    return (
      <span
        title={tooltip}
        className={`ml-auto px-1.5 py-0.5 rounded-full text-[10px] font-mono font-bold border transition-colors cursor-default ${
          colorClasses[color || "cyan"]
        }`}
      >
        {badge}
      </span>
    );
  };

  return (
    <aside
      className={`${
        isCollapsed ? "w-16" : "w-64"
      } bg-[#020617] border-r border-[rgba(0,183,255,0.15)] flex flex-col shrink-0 transition-all duration-200 select-none z-30`}
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-[rgba(0,183,255,0.15)] bg-[#030B1C]/80 backdrop-blur-md">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="p-2 rounded-xl bg-[#008CFF]/15 border border-[#00B7FF]/40 text-[#00D9FF] shrink-0 shadow-cyber-glow-sm">
            <ShieldAlert className="w-5 h-5 text-[#00D9FF]" />
          </div>
          {!isCollapsed && (
            <div className="min-w-0">
              <h1 className="text-base font-black tracking-wider text-white uppercase">
                ASOC
              </h1>
              <p className="text-[9px] uppercase font-mono font-semibold text-[#00D9FF] tracking-widest whitespace-nowrap">
                Autonomous SOC
              </p>
            </div>
          )}
        </div>

        {onToggleCollapse && (
          <button
            onClick={onToggleCollapse}
            className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-white/5 border border-transparent hover:border-[rgba(0,183,255,0.3)] transition"
            title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
          >
            {isCollapsed ? (
              <ChevronsRight className="w-4 h-4 text-[#00D9FF]" />
            ) : (
              <ChevronsLeft className="w-4 h-4 text-slate-400 hover:text-white" />
            )}
          </button>
        )}
      </div>

      {/* Navigation Links Scrollable Area */}
      <div className="flex-1 overflow-y-auto py-3 px-2 space-y-5">
        {/* Operations Section */}
        <div>
          {!isCollapsed && (
            <div className="px-3 pb-2 text-[11px] font-semibold tracking-[0.12em] text-[#5B8DB8] uppercase flex items-center gap-2">
              <span>Operations</span>
              <div className="flex-1 h-px bg-[rgba(0,183,255,0.15)]" />
            </div>
          )}
          <div className="space-y-1">
            {operationsNav.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === "/"}
                title={
                  isCollapsed
                    ? item.badgeTooltip
                      ? `${item.name} (${item.badgeTooltip})`
                      : item.name
                    : item.badgeTooltip || undefined
                }
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium transition-all duration-150 group relative ${
                    isActive
                      ? "bg-[rgba(0,140,255,0.16)] text-white border-l-2 border-l-[#00D9FF] border border-[rgba(0,183,255,0.3)] shadow-[inset_0_0_12px_rgba(0,217,255,0.12)] font-semibold"
                      : "text-slate-400 hover:text-slate-100 hover:bg-[rgba(0,140,255,0.08)] border border-transparent"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <item.icon
                      className={`w-4 h-4 shrink-0 transition-colors ${
                        isActive
                          ? "text-[#00D9FF] drop-shadow-[0_0_6px_rgba(0,217,255,0.6)]"
                          : "text-slate-400 group-hover:text-slate-200"
                      }`}
                    />
                    {!isCollapsed && (
                      <span className="truncate flex-1">{item.name}</span>
                    )}
                    {!isCollapsed && renderBadge(item.badge, item.badgeColor, item.badgeTooltip)}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        </div>

        {/* Intelligence & Lab Section */}
        <div>
          {!isCollapsed && (
            <div className="px-3 pb-2 text-[11px] font-semibold tracking-[0.12em] text-[#5B8DB8] uppercase flex items-center gap-2">
              <span>Intelligence &amp; Lab</span>
              <div className="flex-1 h-px bg-[rgba(0,183,255,0.15)]" />
            </div>
          )}
          <div className="space-y-1">
            {intelligenceNav.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                title={isCollapsed ? item.name : undefined}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-xl text-xs font-medium transition-all duration-150 group relative ${
                    isActive
                      ? "bg-[rgba(0,140,255,0.16)] text-white border-l-2 border-l-[#00D9FF] border border-[rgba(0,183,255,0.3)] shadow-[inset_0_0_12px_rgba(0,217,255,0.12)] font-semibold"
                      : "text-slate-400 hover:text-slate-100 hover:bg-[rgba(0,140,255,0.08)] border border-transparent"
                  }`
                }
              >
                {({ isActive }) => (
                  <>
                    <item.icon
                      className={`w-4 h-4 shrink-0 transition-colors ${
                        isActive
                          ? "text-[#00D9FF] drop-shadow-[0_0_6px_rgba(0,217,255,0.6)]"
                          : "text-slate-400 group-hover:text-slate-200"
                      }`}
                    />
                    {!isCollapsed && (
                      <span className="truncate flex-1">{item.name}</span>
                    )}
                    {!isCollapsed && renderBadge(item.badge, item.badgeColor)}
                  </>
                )}
              </NavLink>
            ))}
          </div>
        </div>
      </div>

      {/* Footer System Status Widget */}
      {!isCollapsed && (
        <div className="p-3 border-t border-[rgba(0,183,255,0.15)] bg-[#030B1C]/60 text-[11px]">
          <div className="flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-slate-400">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              SOC Engine
            </span>
            <span className="font-mono text-[10px] text-[#00D9FF] font-bold">ONLINE</span>
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-1 flex justify-between">
            <span>ASOC Command</span>
            <span>v1.0.0</span>
          </div>
        </div>
      )}
    </aside>
  );
};
