import React, { useEffect, useState } from "react";
import {
  Bell,
  CheckCheck,
  CheckCircle2,
  AlertTriangle,
  Flame,
  Info,
  RefreshCw,
  Clock,
  Sparkles,
} from "lucide-react";
import { api } from "../services/api";
import { Notification } from "../types";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

export const Notifications: React.FC = () => {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [unreadOnly, setUnreadOnly] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);

  const { success, error: toastError, info } = useToast();

  const fetchNotifications = async () => {
    setIsLoading(true);
    try {
      const [listRes, countRes] = await Promise.all([
        api.get("/notifications", { params: { unread_only: unreadOnly, limit: 50 } }),
        api.get("/notifications/unread-count"),
      ]);

      if (listRes.data) {
        setNotifications(listRes.data.data || []);
      }
      if (countRes.data?.data) {
        const count = Number(countRes.data.data.unread_count || 0);
        setUnreadCount(count);
        window.dispatchEvent(
          new CustomEvent("asoc_notifications_updated", { detail: { unreadCount: count } })
        );
      }
    } catch (err: any) {
      toastError("Failed to fetch notification feed.");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchNotifications();
  }, [unreadOnly]);

  const handleMarkRead = async (id: string) => {
    try {
      await api.patch(`/notifications/${id}/read`);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, is_read: true } : n))
      );
      const newCount = Math.max(0, unreadCount - 1);
      setUnreadCount(newCount);
      window.dispatchEvent(
        new CustomEvent("asoc_notifications_updated", { detail: { unreadCount: newCount } })
      );
      success("Notification marked as read.");
    } catch (err: any) {
      toastError("Failed to update notification.");
    }
  };

  const handleMarkAllRead = async () => {
    setIsProcessing(true);
    try {
      const res = await api.post("/notifications/read-all");
      if (res.data?.success) {
        success("All notifications marked as read.");
        setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
        setUnreadCount(0);
        window.dispatchEvent(
          new CustomEvent("asoc_notifications_updated", { detail: { unreadCount: 0 } })
        );
      } else {
        info("All notifications are already marked as read.");
      }
    } catch (err: any) {
      toastError("Failed to mark all as read.");
    } finally {
      setIsProcessing(false);
    }
  };

  const getIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "critical_alert":
      case "alert":
      case "alert_created":
      case "risk_escalation":
        return <AlertTriangle className="w-5 h-5 text-red-400" />;
      case "incident":
      case "incident_assigned":
        return <Flame className="w-5 h-5 text-amber-400" />;
      default:
        return <Info className="w-5 h-5 text-cyan-400" />;
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="alerts" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 max-w-4xl mx-auto text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="Notifications"
        tagline="REAL-TIME ACTIVITY FEED"
        subtitle="Security telemetry escalations, critical threshold warnings, and analyst action feed."
        icon={Bell}
        badgeText={unreadCount > 0 ? `${unreadCount} Unread Alerts` : "Stream Synchronized"}
        actions={
          <SOCButton
            variant={unreadCount > 0 ? "primary" : "secondary"}
            onClick={handleMarkAllRead}
            disabled={isProcessing}
            icon={<CheckCheck className="w-4 h-4 text-emerald-400" />}
            glow={unreadCount > 0}
          >
            {isProcessing
              ? "Updating..."
              : unreadCount > 0
              ? `Mark All as Read (${unreadCount})`
              : "Mark All as Read"}
          </SOCButton>
        }
      />

      {/* Filter Switcher */}
      <div className="cyber-panel p-3 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setUnreadOnly(false)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all ${
              !unreadOnly
                ? "bg-cyan-500 text-slate-950 font-extrabold shadow-md shadow-cyan-500/30"
                : "text-slate-400 hover:text-white"
            }`}
          >
            All Notifications
          </button>
          <button
            onClick={() => setUnreadOnly(true)}
            className={`px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              unreadOnly
                ? "bg-cyan-500 text-slate-950 font-extrabold shadow-md shadow-cyan-500/30"
                : "text-slate-400 hover:text-white"
            }`}
          >
            Unread Only
            {unreadCount > 0 && (
              <span className="px-1.5 py-0.5 rounded-full text-[10px] font-black bg-red-500 text-white animate-pulse">
                {unreadCount}
              </span>
            )}
          </button>
        </div>

        <button
          onClick={fetchNotifications}
          className="p-2 text-slate-400 hover:text-cyan-400 hover:bg-[#030a18] border border-transparent hover:border-cyan-500/30 rounded-lg transition"
          title="Refresh Feed"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? "animate-spin text-cyan-400" : ""}`} />
        </button>
      </div>

      {/* Notifications List */}
      {isLoading ? (
        <div className="py-20 text-center text-slate-400 flex items-center justify-center cyber-panel">
          <div className="w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin mr-3" />
          Loading security notifications...
        </div>
      ) : notifications.length === 0 ? (
        <div className="py-16 text-center cyber-panel p-6">
          <CheckCircle2 className="w-12 h-12 text-emerald-400/80 mx-auto mb-3" />
          <h3 className="text-base font-bold text-white">Inbox Zero</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-sm mx-auto">
            {unreadOnly
              ? "All notifications have been marked as read. Switch to 'All Notifications' to view history."
              : "No notification events recorded yet. All telemetry is nominal."}
          </p>
          {unreadOnly && (
            <button
              onClick={() => setUnreadOnly(false)}
              className="mt-4 px-3.5 py-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 bg-cyan-950/60 border border-cyan-500/40 rounded-lg transition"
            >
              View All Notifications
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {notifications.map((notif) => (
            <div
              key={notif.id}
              className={`p-4 rounded-xl border transition-all flex items-start justify-between gap-4 ${
                notif.is_read
                  ? "bg-[#061226]/70 border-slate-800/80 text-slate-400"
                  : "cyber-panel border-cyan-500/50 shadow-lg shadow-cyan-950/40 ring-1 ring-cyan-500/30 text-slate-200"
              }`}
            >
              <div className="flex items-start gap-3.5">
                <div className="p-2 bg-[#020712] rounded-lg border border-slate-800 shrink-0 mt-0.5">
                  {getIcon(notif.notification_type)}
                </div>

                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-bold text-white">{notif.title}</p>
                    {!notif.is_read && (
                      <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
                    )}
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed max-w-2xl">
                    {notif.message}
                  </p>
                  <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-500 font-mono">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>{new Date(notif.sent_at).toLocaleString()}</span>
                    <span className="uppercase text-[9px] px-1.5 py-0.5 rounded bg-[#020712] border border-slate-800 text-slate-400">
                      {notif.notification_type}
                    </span>
                  </div>
                </div>
              </div>

              <div className="shrink-0 pt-0.5">
                {!notif.is_read ? (
                  <button
                    onClick={() => handleMarkRead(notif.id)}
                    className="px-2.5 py-1 text-xs font-bold text-cyan-300 bg-cyan-950/90 hover:bg-cyan-900 border border-cyan-500/50 rounded-lg transition shadow-md shadow-cyan-950/40 cursor-pointer"
                  >
                    Mark Read
                  </button>
                ) : (
                  <span className="flex items-center gap-1 text-[11px] font-semibold text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-2 py-0.5 rounded-lg">
                    <CheckCheck className="w-3 h-3 text-emerald-400" />
                    Read
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      </div>
    </div>
  );
};
