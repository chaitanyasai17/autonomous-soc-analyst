import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Bell,
  Clock,
  Search,
  User as UserIcon,
  ChevronsLeft,
  ChevronsRight,
  LogOut,
} from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { api } from "../../services/api";
import { GlobalSearchModal } from "./GlobalSearchModal";

interface NavbarProps {
  isSidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  isSidebarCollapsed = false,
  onToggleSidebar,
}) => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [currentTime, setCurrentTime] = useState<string>("");
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [isHealthy, setIsHealthy] = useState<boolean>(true);
  const [isSearchOpen, setIsSearchOpen] = useState<boolean>(false);

  // Global keyboard shortcut for search (Ctrl+K / Cmd+K)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setIsSearchOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Live UTC Clock matching screenshot: 2026-09-23 14:32:17 UTC
  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      const yr = now.getUTCFullYear();
      const mo = String(now.getUTCMonth() + 1).padStart(2, "0");
      const da = String(now.getUTCDate()).padStart(2, "0");
      const hr = String(now.getUTCHours()).padStart(2, "0");
      const mi = String(now.getUTCMinutes()).padStart(2, "0");
      const se = String(now.getUTCSeconds()).padStart(2, "0");
      setCurrentTime(`${yr}-${mo}-${da} ${hr}:${mi}:${se} UTC`);
    };
    updateTime();
    const timer = setInterval(updateTime, 1000);
    return () => clearInterval(timer);
  }, []);

  // Fetch unread notifications count & health check
  useEffect(() => {
    let isMounted = true;
    const fetchStatus = async () => {
      try {
        const [notifRes, healthRes] = await Promise.all([
          api.get("/notifications/unread-count"),
          api.get("/health"),
        ]);
        if (isMounted) {
          if (notifRes.data?.data) {
            setUnreadCount(Number(notifRes.data.data.unread_count || 0));
          }
          if (healthRes.data?.success) {
            setIsHealthy(true);
          }
        }
      } catch {
        if (isMounted) {
          setIsHealthy(true);
        }
      }
    };

    fetchStatus();
    const interval = setInterval(fetchStatus, 30000);

    const onNotificationsUpdated = (e: any) => {
      if (typeof e.detail?.unreadCount === "number") {
        setUnreadCount(e.detail.unreadCount);
      } else {
        fetchStatus();
      }
    };
    window.addEventListener("asoc_notifications_updated", onNotificationsUpdated);

    return () => {
      isMounted = false;
      clearInterval(interval);
      window.removeEventListener("asoc_notifications_updated", onNotificationsUpdated);
    };
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/login");
  };

  return (
    <header className="h-16 bg-[#030B1C]/85 backdrop-blur-md border-b border-[rgba(0,183,255,0.15)] flex items-center justify-between px-4 sm:px-6 z-20 shrink-0 select-none">
      {/* Left Area: Toggle & Search */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            className="p-2 rounded-xl cyber-panel-subtle hover:border-[rgba(0,183,255,0.4)] text-slate-400 hover:text-white transition"
            title={isSidebarCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
          >
            {isSidebarCollapsed ? (
              <ChevronsRight className="w-4 h-4 text-[#00D9FF]" />
            ) : (
              <ChevronsLeft className="w-4 h-4 text-slate-400 hover:text-white" />
            )}
          </button>
        )}

        {/* Global Search Pill Input */}
        <div
          onClick={() => setIsSearchOpen(true)}
          className="flex items-center gap-3 px-3.5 py-1.5 rounded-xl cyber-panel-subtle hover:border-[#00D9FF]/50 text-slate-400 text-xs w-[280px] sm:w-[380px] md:w-[420px] cursor-pointer transition shadow-inner"
        >
          <Search className="w-4 h-4 text-[#00D9FF]" />
          <span className="text-slate-400 text-xs flex-1 truncate">
            Search events, IPs, domains, hashes, users...
          </span>
          <kbd className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-[#020617] border border-[rgba(0,183,255,0.2)] text-[10px] font-mono text-[#00D9FF]">
            Ctrl + K
          </kbd>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3 sm:gap-4">
        {/* SOC LIVE + Status Pill */}
        <div className="flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-950/40 border border-emerald-500/40 text-emerald-400 text-xs font-bold shadow-cyber-glow-emerald">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>SOC LIVE +</span>
        </div>

        {/* UTC Clock */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-xl cyber-panel-subtle text-xs font-mono text-[#00D9FF]">
          <Clock className="w-3.5 h-3.5 text-[#00D9FF]" />
          <span>{currentTime}</span>
        </div>

        {/* Notifications Bell */}
        <Link
          to="/notifications"
          className="relative p-2 rounded-xl cyber-panel-subtle text-slate-300 hover:text-white hover:border-[#00D9FF]/40 transition"
          title="Incident & Alert Notifications"
        >
          <Bell className="w-4 h-4 text-[#00D9FF]" />
          {unreadCount > 0 && (
            <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center shadow-cyber-glow-red">
              {unreadCount > 9 ? "9+" : unreadCount}
            </span>
          )}
        </Link>

        {/* User Profile */}
        <div className="flex items-center gap-2.5 pl-2 border-l border-[rgba(0,183,255,0.15)]">
          <div className="w-8 h-8 rounded-full bg-[#008CFF]/15 border border-[#00B7FF]/40 flex items-center justify-center text-[#00D9FF] shadow-cyber-glow-sm">
            <UserIcon className="w-4 h-4 text-[#00D9FF]" />
          </div>
          <div className="hidden sm:flex flex-col">
            <span className="text-xs font-bold text-white leading-tight">
              {user?.username || "admin"}
            </span>
            <span className="text-[9px] font-mono tracking-wider text-[#00D9FF]/80 uppercase font-semibold">
              SUPER ADMIN
            </span>
          </div>
          <button
            onClick={handleLogout}
            className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-white/5 transition"
            title="Sign Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Global Intelligence Search Modal */}
      <GlobalSearchModal isOpen={isSearchOpen} onClose={() => setIsSearchOpen(false)} />
    </header>
  );
};
