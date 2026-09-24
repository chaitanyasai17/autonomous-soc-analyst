import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ShieldAlert, Lock, User, ArrowRight, AlertCircle, Radio } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCButton } from "../components/common/SOCButton";

export const Login: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const { success } = useToast();

  const [username, setUsername] = useState<string>("admin");
  const [password, setPassword] = useState<string>("Admin1234!");
  const [error, setError] = useState<string>("");
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setIsSubmitting(true);

    try {
      await login(username, password);
      success("Authenticated successfully. Welcome to Autonomous SOC Analyst.");
      navigate("/");
    } catch (err: any) {
      setError(
        err.response?.data?.message ||
          "Authentication failed. Please verify credentials."
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex items-center justify-center p-4 relative overflow-hidden bg-[#020617]">
      <CyberGridBackground variant="minimal" />

      <div className="w-full max-w-md cyber-panel p-8 relative z-10 shadow-2xl ring-1 ring-cyan-500/30">
        {/* Header */}
        <div className="flex flex-col items-center text-center">
          <div className="p-3.5 rounded-2xl bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 mb-4 shadow-lg shadow-cyan-500/20">
            <ShieldAlert className="w-8 h-8" />
          </div>
          <div className="flex items-center gap-1.5 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 font-bold">Autonomous Defense Grid</span>
          </div>
          <h1 className="text-2xl font-black tracking-tight text-white">
            Autonomous SOC Analyst
          </h1>
          <p className="mt-1 text-xs text-slate-400">
            Intelligent Threat Detection & Automated Incident Response
          </p>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="mt-6 p-3.5 rounded-lg bg-red-950/60 border border-red-500/50 flex items-start gap-2.5 text-xs text-red-300 shadow-md shadow-red-950/40">
            <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-red-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Username or Email
            </label>
            <div className="relative">
              <User className="absolute left-3.5 top-3 w-4 h-4 text-cyan-400/70" />
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="analyst or admin"
                className="w-full pl-10 pr-4 py-2.5 bg-[#030a18]/90 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40 transition-colors font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-3 w-4 h-4 text-cyan-400/70" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full pl-10 pr-4 py-2.5 bg-[#030a18]/90 border border-slate-700/80 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40 transition-colors font-mono"
              />
            </div>
          </div>

          {/* Preset Credentials Hint */}
          <div className="p-3 rounded-lg bg-[#030a18]/80 border border-cyan-900/30 text-[11px] text-slate-400 flex items-center justify-between">
            <span>Pre-seeded Super Admin:</span>
            <span className="font-mono text-cyan-300 font-bold">admin / Admin1234!</span>
          </div>

          <SOCButton
            type="submit"
            variant="primary"
            disabled={isSubmitting}
            className="w-full mt-2"
            icon={<ArrowRight className="w-4 h-4" />}
            glow
          >
            {isSubmitting ? "Authenticating..." : "Enter SOC Console"}
          </SOCButton>
        </form>

        {/* Footer Link */}
        <div className="mt-6 text-center text-xs text-slate-400">
          Need an analyst account?{" "}
          <Link to="/register" className="text-cyan-400 hover:text-cyan-300 hover:underline font-semibold">
            Register new user
          </Link>
        </div>
      </div>
    </div>
  );
};
