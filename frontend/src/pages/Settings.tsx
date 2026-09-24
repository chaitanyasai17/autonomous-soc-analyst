import React, { useEffect, useState } from "react";
import {
  Settings as SettingsIcon,
  Shield,
  KeyRound,
  User,
  Cpu,
  Database,
  CheckCircle2,
  Lock,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

export const Settings: React.FC = () => {
  const { user } = useAuth();
  const { success, error: toastError } = useToast();

  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isChangingPassword, setIsChangingPassword] = useState(false);

  const [aiStatus, setAiStatus] = useState<any>(null);

  useEffect(() => {
    api
      .get("/ai/status")
      .then((res) => {
        if (res.data?.data) setAiStatus(res.data.data);
      })
      .catch(() => {});
  }, []);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPassword !== confirmPassword) {
      toastError("New passwords do not match.");
      return;
    }
    if (newPassword.length < 8) {
      toastError("New password must be at least 8 characters long.");
      return;
    }

    setIsChangingPassword(true);
    try {
      const res = await api.post("/auth/change-password", {
        current_password: currentPassword,
        new_password: newPassword,
      });
      if (res.data?.success) {
        success("Password changed successfully.");
        setCurrentPassword("");
        setNewPassword("");
        setConfirmPassword("");
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "Failed to change password.");
    } finally {
      setIsChangingPassword(false);
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="settings" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 max-w-5xl mx-auto text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="System Settings"
        tagline="ENTERPRISE PLATFORM CONFIGURATION"
        subtitle="Platform configuration, account controls, and SOC engine settings."
        icon={SettingsIcon}
        badgeText="Security Configuration"
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Profile Card */}
        <div className="cyber-panel p-6 space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-12 h-12 rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-md shadow-cyan-950/40">
              <User className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100">{user?.username}</h2>
              <p className="text-xs text-slate-400">{user?.email}</p>
            </div>
          </div>

          <div className="space-y-3 pt-3 border-t border-slate-800 text-xs">
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Assigned Role:</span>
              <span className="font-mono font-bold uppercase px-2 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-800/40">
                {user?.role}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Account Status:</span>
              <span className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" /> Active
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400">Security Clearance:</span>
              <span className="text-slate-200 font-mono">SOC Tier 3 / Lead</span>
            </div>
          </div>
        </div>

        {/* Change Password Form */}
        <div className="lg:col-span-2 cyber-panel p-6">
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-1">
            <KeyRound className="w-5 h-5 text-cyan-400" />
            Update Access Credentials
          </h2>
          <p className="text-xs text-slate-400 mb-5">
            Maintain strong security standards. Passwords require 8+ characters including uppercase, digits, and symbols.
          </p>

          <form onSubmit={handleChangePassword} className="space-y-4 max-w-md">
            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                Current Password
              </label>
              <div className="relative">
                <input
                  type="password"
                  required
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  className="w-full bg-[#030a18]/90 border border-slate-700/80 rounded-xl px-3 py-2 pl-9 text-sm text-slate-100 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
                />
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                New Password
              </label>
              <div className="relative">
                <input
                  type="password"
                  required
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full bg-[#030a18]/90 border border-slate-700/80 rounded-xl px-3 py-2 pl-9 text-sm text-slate-100 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
                />
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              </div>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">
                Confirm New Password
              </label>
              <div className="relative">
                <input
                  type="password"
                  required
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full bg-[#030a18]/90 border border-slate-700/80 rounded-xl px-3 py-2 pl-9 text-sm text-slate-100 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
                />
                <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              </div>
            </div>

            <SOCButton
              type="submit"
              variant="primary"
              disabled={isChangingPassword}
              glow
            >
              {isChangingPassword ? "Updating..." : "Update Password"}
            </SOCButton>
          </form>
        </div>
      </div>

      {/* Engine Architecture & Diagnostics */}
      <div className="cyber-panel p-6">
        <h2 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-4">
          <Cpu className="w-5 h-5 text-cyan-400" />
          SOC Platform Engine Status & Architecture
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#030a18]/90 p-4 rounded-xl border border-slate-800">
            <p className="text-xs text-slate-400 font-semibold uppercase">AI Threat Hunter</p>
            <p className="text-base font-bold text-cyan-400 mt-1 capitalize font-mono">
              {aiStatus?.active_provider || "Heuristic / Hybrid"}
            </p>
            <p className="text-[11px] text-slate-500 mt-1">
              {aiStatus?.fallback_active ? "Offline Heuristic Fallback Guard" : "Direct Provider Online"}
            </p>
          </div>

          <div className="bg-[#030a18]/90 p-4 rounded-xl border border-slate-800">
            <p className="text-xs text-slate-400 font-semibold uppercase">Detection Engine</p>
            <p className="text-base font-bold text-emerald-400 mt-1 font-mono">
              Sigma Core v2.4
            </p>
            <p className="text-[11px] text-slate-500 mt-1">
              Active AST YAML rule compiler
            </p>
          </div>

          <div className="bg-[#030a18]/90 p-4 rounded-xl border border-slate-800">
            <p className="text-xs text-slate-400 font-semibold uppercase">Risk Scoring</p>
            <p className="text-base font-bold text-amber-400 mt-1 font-mono">
              Composite 0–100
            </p>
            <p className="text-[11px] text-slate-500 mt-1">
              Asset criticality + telemetry weights
            </p>
          </div>

          <div className="bg-[#030a18]/90 p-4 rounded-xl border border-slate-800">
            <p className="text-xs text-slate-400 font-semibold uppercase">Framework Matrix</p>
            <p className="text-base font-bold text-purple-400 mt-1 font-mono">
              MITRE ATT&CK Enterprise
            </p>
            <p className="text-[11px] text-slate-500 mt-1">
              Full 14 Tactics & seeded Techniques
            </p>
          </div>
        </div>
      </div>
      </div>
    </div>
  );
};
