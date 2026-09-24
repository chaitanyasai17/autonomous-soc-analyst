import { useState, useEffect, useCallback } from "react";
import { api } from "../services/api";

export interface BadgeState {
  count: number | null;
  loading: boolean;
  error: boolean;
}

export interface NotificationBadges {
  alerts: BadgeState;
  incidents: BadgeState;
  refresh: () => Promise<void>;
}

export const notifyBadgeRefresh = () => {
  window.dispatchEvent(new CustomEvent("asoc:badges-refresh"));
};

export const useNotificationBadges = (): NotificationBadges => {
  const [alerts, setAlerts] = useState<BadgeState>({
    count: null,
    loading: true,
    error: false,
  });

  const [incidents, setIncidents] = useState<BadgeState>({
    count: null,
    loading: true,
    error: false,
  });

  const fetchBadges = useCallback(async () => {
    const token = localStorage.getItem("asoc_access_token");
    if (!token) {
      setAlerts({ count: null, loading: false, error: false });
      setIncidents({ count: null, loading: false, error: false });
      return;
    }

    try {
      const [alertRes, incRes] = await Promise.allSettled([
        api.get("/alerts/statistics"),
        api.get("/incidents/statistics"),
      ]);

      // 1. Process Alerts Badge: untriaged / open alerts
      if (alertRes.status === "fulfilled" && alertRes.value.data?.success) {
        const stats = alertRes.value.data.data;
        // Untriaged alerts currently requiring analyst attention are status 'open'
        const untriagedCount = stats?.by_status?.open ?? 0;
        setAlerts({
          count: untriagedCount,
          loading: false,
          error: false,
        });
      } else {
        setAlerts((prev) => ({
          count: prev.count,
          loading: false,
          error: true,
        }));
      }

      // 2. Process Incidents Badge: active / open / investigating incidents
      if (incRes.status === "fulfilled" && incRes.value.data?.success) {
        const stats = incRes.value.data.data;
        // Active incidents requiring attention: open + investigating (+ contained)
        const activeCount =
          stats?.open_active_incidents ??
          ((stats?.by_status?.open ?? 0) +
            (stats?.by_status?.investigating ?? 0) +
            (stats?.by_status?.contained ?? 0));
        setIncidents({
          count: activeCount,
          loading: false,
          error: false,
        });
      } else {
        setIncidents((prev) => ({
          count: prev.count,
          loading: false,
          error: true,
        }));
      }
    } catch {
      setAlerts((prev) => ({ ...prev, loading: false, error: true }));
      setIncidents((prev) => ({ ...prev, loading: false, error: true }));
    }
  }, []);

  useEffect(() => {
    fetchBadges();

    // 1. Listen for explicit application events (alert triage, status change, incident creation)
    const handleEvent = () => {
      fetchBadges();
    };
    window.addEventListener("asoc:badges-refresh", handleEvent);

    // 2. Refresh when browser tab regains focus
    const handleFocus = () => {
      fetchBadges();
    };
    window.addEventListener("focus", handleFocus);

    // 3. Periodic background refresh every 20 seconds
    const interval = setInterval(fetchBadges, 20000);

    return () => {
      window.removeEventListener("asoc:badges-refresh", handleEvent);
      window.removeEventListener("focus", handleFocus);
      clearInterval(interval);
    };
  }, [fetchBadges]);

  return {
    alerts,
    incidents,
    refresh: fetchBadges,
  };
};
