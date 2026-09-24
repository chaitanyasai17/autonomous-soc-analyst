import React, { useEffect, useState } from "react";
import {
  Sparkles,
  Bot,
  Brain,
  ShieldCheck,
  AlertTriangle,
  Send,
  Cpu,
  CheckCircle2,
  Terminal,
  Activity,
  ListOrdered,
  Layers,
} from "lucide-react";
import { api } from "../services/api";
import { AIThreatAnalysis, Detection } from "../types";
import { SeverityBadge } from "../components/common/Badge";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

export const AICopilot: React.FC = () => {
  const [providerStatus, setProviderStatus] = useState<any>(null);
  const [detections, setDetections] = useState<Detection[]>([]);
  const [selectedDetectionId, setSelectedDetectionId] = useState<string>("");
  const [analysis, setAnalysis] = useState<AIThreatAnalysis | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [completedSteps, setCompletedSteps] = useState<number[]>([]);

  // Interactive Questioning
  const [queryText, setQueryText] = useState<string>("");
  const [chatLog, setChatLog] = useState<Array<{ role: "user" | "copilot"; text: string }>>([]);

  const { success, error: toastError } = useToast();

  const fetchStatusAndDetections = async () => {
    try {
      const [statusRes, detRes] = await Promise.all([
        api.get("/ai/status"),
        api.get("/detections?limit=25"),
      ]);

      if (statusRes.data?.data) {
        setProviderStatus(statusRes.data.data);
      }
      if (detRes.data?.data) {
        setDetections(detRes.data.data);
        if (detRes.data.data.length > 0) {
          setSelectedDetectionId(detRes.data.data[0].id);
        }
      }
    } catch (err: any) {
      toastError("Failed to initialize AI Copilot session.");
    }
  };

  useEffect(() => {
    fetchStatusAndDetections();
  }, []);

  const handleRunAnalysis = async () => {
    if (!selectedDetectionId) return;
    setIsAnalyzing(true);
    setCompletedSteps([]);
    try {
      const res = await api.post(`/ai/analyze/detection/${selectedDetectionId}`);
      if (res.data?.data) {
        setAnalysis(res.data.data);
        success("AI threat intelligence assessment synthesized.");
      }
    } catch (err: any) {
      toastError(err.response?.data?.message || "AI threat analysis failed.");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSendMessage = (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryText.trim()) return;

    const userMessage = queryText;
    setChatLog((prev) => [...prev, { role: "user", text: userMessage }]);
    setQueryText("");

    // Simulated Copilot intelligence response based on current context
    setTimeout(() => {
      let response = "";
      const lower = userMessage.toLowerCase();
      if (lower.includes("contain") || lower.includes("isolate")) {
        response = `[COPILOT REMEDIATION RECOMMENDATION]: For the detected threat sequence, immediately isolate the endpoint from the network vLAN. Revoke active Kerberos/OAuth sessions and verify if child processes spawned from cmd.exe/powershell.exe have established outbound C2 sockets.`;
      } else if (lower.includes("mitre") || lower.includes("technique")) {
        response = `[MITRE MAPPING]: The current activity exhibits signs of T1059 (Command and Scripting Interpreter) and T1110 (Brute Force). Review Sigma rule telemetry and correlate with authentication logs for lateral movement attempts.`;
      } else if (lower.includes("false positive") || lower.includes("fp")) {
        response = `[FALSE POSITIVE TRIAGE]: Evaluate whether the source IP belongs to an internal scanning agent (e.g. Nessus, Qualys) or authorized administrative maintenance scripts. Check user-agent strings and scheduled cron jobs.`;
      } else {
        response = `[SOC ADVISOR]: Based on the telemetry analyzed, threat indicators demonstrate targeted activity. Review the IOC table below, verify persistence via Registry Run keys or systemd services, and escalate priority if production domain controllers are involved.`;
      }
      setChatLog((prev) => [...prev, { role: "copilot", text: response }]);
    }, 600);
  };

  const toggleStep = (idx: number) => {
    setCompletedSteps((prev) =>
      prev.includes(idx) ? prev.filter((i) => i !== idx) : [...prev, idx]
    );
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="copilot" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header & Provider Status */}
      <SOCPageHeader
        title="AI Threat Copilot"
        tagline="AUTONOMOUS SOC ASSISTANT"
        subtitle="Threat analysis, investigation assistance, and response guidance."
        icon={Sparkles}
        badgeText={providerStatus ? `Engine: ${providerStatus.active_provider?.toUpperCase()}` : "AI Copilot Online"}
        actions={
          providerStatus && (
            <div className="cyber-panel px-4 py-2 flex items-center gap-3">
              <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse shadow-md shadow-emerald-500/50" />
              <div className="text-xs">
                <span className="text-slate-400">Model: </span>
                <span className="font-mono font-bold text-cyan-300">
                  {providerStatus.model}
                </span>
              </div>
              {providerStatus.fallback_active && (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/40">
                  Fallback Guard
                </span>
              )}
            </div>
          )
        }
      />

      {/* Selector and Run bar */}
      <div className="cyber-panel p-5 flex flex-col md:flex-row items-center gap-4">
        <div className="flex-1 w-full">
          <label className="block text-xs font-bold uppercase tracking-wider text-cyan-300/80 mb-1.5">
            Select Security Detection for AI Investigation:
          </label>
          <select
            value={selectedDetectionId}
            onChange={(e) => setSelectedDetectionId(e.target.value)}
            className="w-full bg-[#030a18]/90 border border-slate-700/80 rounded-xl px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
          >
            {detections.map((det) => (
              <option key={det.id} value={det.id} className="bg-slate-900 text-slate-100">
                [{det.severity.toUpperCase()}] {det.rule_title} — Rule: {det.matched_rule}
              </option>
            ))}
          </select>
        </div>

        <div className="w-full md:w-auto mt-auto md:mt-5">
          <SOCButton
            variant="primary"
            onClick={handleRunAnalysis}
            disabled={isAnalyzing || !selectedDetectionId}
            icon={<Sparkles className={`w-4 h-4 ${isAnalyzing ? "animate-spin" : ""}`} />}
            glow
          >
            {isAnalyzing ? "Synthesizing AI Intelligence..." : "Run AI Threat Analysis"}
          </SOCButton>
        </div>
      </div>

      {/* Analysis Output Dossier */}
      {analysis && (
        <div className="space-y-6">
          {/* Top Assessment Overview */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="cyber-panel p-5">
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">
                AI Confidence Level
              </p>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl font-black text-cyan-400">
                  {Math.round(analysis.confidence * 100)}%
                </span>
                <span className="text-xs text-slate-400">Heuristic / LLM Consensus</span>
              </div>
              <div className="w-full bg-slate-800/80 h-1.5 rounded-full mt-3 overflow-hidden">
                <div
                  className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full rounded-full transition-all duration-700 shadow-md shadow-cyan-500/50"
                  style={{ width: `${Math.round(analysis.confidence * 100)}%` }}
                />
              </div>
            </div>

            <div className="cyber-panel p-5">
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">
                False Positive Likelihood
              </p>
              <div className="flex items-center gap-2 mt-1">
                <span
                  className={`px-2.5 py-1 rounded-md text-xs font-black uppercase tracking-wider ${
                    analysis.false_positive_likelihood === "low"
                      ? "bg-emerald-950/80 text-emerald-300 border border-emerald-500/40"
                      : analysis.false_positive_likelihood === "medium"
                      ? "bg-amber-950/80 text-amber-300 border border-amber-500/40"
                      : "bg-red-950/80 text-red-300 border border-red-500/40"
                  }`}
                >
                  {analysis.false_positive_likelihood} Probability
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2 line-clamp-2">
                {analysis.false_positive_rationale || "Evaluated by deterministic behavior baseline."}
              </p>
            </div>

            <div className="cyber-panel p-5">
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">
                Engine & Provider
              </p>
              <p className="text-base font-bold text-slate-200 mt-1 uppercase font-mono">
                {analysis.provider_used}
              </p>
              <div className="flex flex-wrap gap-1.5 mt-2">
                {analysis.mitre_alignment?.map((t) => (
                  <span
                    key={t}
                    className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950/80 text-cyan-300 border border-cyan-800/40"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Narrative & Remediation Playbook */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attack Narrative */}
            <div className="cyber-panel p-6 flex flex-col justify-between">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-3">
                  <Brain className="w-5 h-5 text-cyan-400" />
                  Tactical Attack Narrative
                </h3>
                <div className="p-4 bg-[#030a18]/90 rounded-xl border border-cyan-900/30 mb-4">
                  <p className="text-xs font-bold text-cyan-300 uppercase tracking-wider mb-1">
                    Executive Summary
                  </p>
                  <p className="text-sm text-slate-200 leading-relaxed font-medium">
                    {analysis.threat_summary}
                  </p>
                </div>
                <div className="text-xs text-slate-300 space-y-2 leading-relaxed whitespace-pre-line font-mono bg-[#020712]/90 p-4 rounded-xl border border-slate-800">
                  {analysis.attack_narrative}
                </div>
              </div>

              {/* IOCs extracted */}
              {analysis.indicators_of_compromise && analysis.indicators_of_compromise.length > 0 && (
                <div className="mt-6 pt-4 border-t border-slate-800">
                  <p className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                    Extracted Threat Indicators (IOCs)
                  </p>
                  <div className="space-y-1.5">
                    {analysis.indicators_of_compromise.map((ioc, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between text-xs font-mono bg-[#030a18] px-3 py-1.5 rounded-lg border border-slate-800"
                      >
                        <span className="text-amber-400 uppercase font-bold text-[10px]">
                          {ioc.type}
                        </span>
                        <span className="text-slate-200">{ioc.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Interactive Remediation Checklist */}
            <div className="cyber-panel p-6">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-2">
                <ListOrdered className="w-5 h-5 text-emerald-400" />
                Prescribed Containment & Remediation Playbook
              </h3>
              <p className="text-xs text-slate-400 mb-4">
                Execute and check off containment actions according to the Autonomous SOC playbook.
              </p>

              <div className="space-y-2.5">
                {(analysis.recommended_actions || []).map((act, idx) => {
                  const done = completedSteps.includes(idx);
                  return (
                    <div
                      key={idx}
                      onClick={() => toggleStep(idx)}
                      className={`p-3.5 rounded-xl border cursor-pointer transition-all flex items-start gap-3 ${
                        done
                          ? "bg-emerald-950/30 border-emerald-800/60 text-slate-400 line-through"
                          : "bg-[#030a18]/80 border-slate-800 hover:border-cyan-500/50 text-slate-200"
                      }`}
                    >
                      <div
                        className={`w-5 h-5 rounded-md flex items-center justify-center border mt-0.5 transition-all ${
                          done
                            ? "bg-emerald-600 border-emerald-500 text-white"
                            : "border-slate-700 bg-slate-900"
                        }`}
                      >
                        {done && <CheckCircle2 className="w-3.5 h-3.5" />}
                      </div>
                      <div className="text-xs leading-relaxed flex-1">
                        <span className="font-bold text-cyan-400 mr-2">Step {idx + 1}:</span>
                        {act}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Interactive AI Analyst Sandbox / Follow-up Chat */}
      <div className="cyber-panel p-6">
        <h3 className="text-base font-bold text-slate-100 flex items-center gap-2 mb-1">
          <Terminal className="w-5 h-5 text-cyan-400" />
          Interactive Threat Hunter Query Console
        </h3>
        <p className="text-xs text-slate-400 mb-4">
          Ask specific forensic questions, verify MITRE techniques, or request custom detection queries.
        </p>

        {/* Chat window */}
        <div className="space-y-3 min-h-[140px] max-h-72 overflow-y-auto mb-4 p-4 bg-[#020712]/90 rounded-xl border border-slate-800/80">
          {chatLog.length === 0 ? (
            <p className="text-xs text-slate-500 text-center py-6">
              Ask Copilot: "How to contain this host?", "Is this an internal scanner?", or "What MITRE technique matches this payload?"
            </p>
          ) : (
            chatLog.map((msg, i) => (
              <div
                key={i}
                className={`flex gap-2.5 text-xs ${
                  msg.role === "user" ? "justify-end" : "justify-start"
                }`}
              >
                {msg.role === "copilot" && (
                  <Bot className="w-4 h-4 text-cyan-400 shrink-0 mt-1" />
                )}
                <div
                  className={`p-3 rounded-xl max-w-xl leading-relaxed ${
                    msg.role === "user"
                      ? "bg-cyan-600 text-white rounded-br-none shadow-md shadow-cyan-900/40"
                      : "bg-[#030a18] text-slate-200 border border-slate-800 font-mono rounded-bl-none"
                  }`}
                >
                  {msg.text}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Input bar */}
        <form onSubmit={handleSendMessage} className="flex gap-2">
          <input
            type="text"
            value={queryText}
            onChange={(e) => setQueryText(e.target.value)}
            placeholder="Type your threat analysis question..."
            className="flex-1 bg-[#030a18]/90 border border-slate-700/80 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/40"
          />
          <SOCButton
            type="submit"
            variant="primary"
            disabled={!queryText.trim()}
            icon={<Send className="w-4 h-4" />}
          >
            Send
          </SOCButton>
        </form>
      </div>
      </div>
    </div>
  );
};
