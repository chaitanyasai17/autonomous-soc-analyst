import React, { useMemo } from "react";

export type CyberBackgroundVariant =
  | "dashboard"
  | "detections"
  | "analytics"
  | "sigma"
  | "mitre"
  | "risk"
  | "alerts"
  | "incidents"
  | "iocs"
  | "timeline"
  | "pipeline"
  | "web-security"
  | "simulator"
  | "copilot"
  | "health"
  | "reports"
  | "audit"
  | "settings"
  | "minimal";

interface CyberGridBackgroundProps {
  variant?: CyberBackgroundVariant;
  className?: string;
}

export const CyberGridBackground: React.FC<CyberGridBackgroundProps> = ({
  variant = "minimal",
  className = "",
}) => {
  // 24 lightweight background micro-particles with fixed randomized coordinates (strictly outside header safe zone)
  const particles = useMemo(() => {
    return [
      { id: 1, x: "12%", y: "26%", size: 2, delay: "0s", duration: "4s" },
      { id: 2, x: "28%", y: "32%", size: 1.5, delay: "1.2s", duration: "5s" },
      { id: 3, x: "45%", y: "30%", size: 2.5, delay: "0.5s", duration: "4.5s" },
      { id: 4, x: "62%", y: "28%", size: 1.5, delay: "2.1s", duration: "6s" },
      { id: 5, x: "78%", y: "25%", size: 2, delay: "1.8s", duration: "5.2s" },
      { id: 6, x: "90%", y: "35%", size: 3, delay: "0.9s", duration: "4.2s" },
      { id: 7, x: "18%", y: "65%", size: 1.5, delay: "2.5s", duration: "5.5s" },
      { id: 8, x: "35%", y: "78%", size: 2, delay: "1.1s", duration: "4.8s" },
      { id: 9, x: "55%", y: "62%", size: 2.5, delay: "3.2s", duration: "6.2s" },
      { id: 10, x: "72%", y: "75%", size: 1.5, delay: "0.7s", duration: "5.1s" },
      { id: 11, x: "85%", y: "82%", size: 2, delay: "2.8s", duration: "4.7s" },
      { id: 12, x: "22%", y: "42%", size: 1.5, delay: "1.5s", duration: "5.8s" },
      { id: 13, x: "48%", y: "85%", size: 2, delay: "2.2s", duration: "4.3s" },
      { id: 14, x: "68%", y: "48%", size: 1.5, delay: "3.5s", duration: "5.9s" },
      { id: 15, x: "82%", y: "24%", size: 2.5, delay: "0.4s", duration: "4.6s" },
      { id: 16, x: "94%", y: "68%", size: 1.5, delay: "1.9s", duration: "5.3s" },
      { id: 17, x: "8%", y: "85%", size: 2, delay: "3.1s", duration: "6.5s" },
      { id: 18, x: "38%", y: "45%", size: 1.5, delay: "2.7s", duration: "4.9s" },
      { id: 19, x: "58%", y: "26%", size: 2, delay: "1.3s", duration: "5.4s" },
      { id: 20, x: "88%", y: "52%", size: 1.5, delay: "0.8s", duration: "4.1s" },
      { id: 21, x: "15%", y: "25%", size: 2, delay: "2.4s", duration: "5.7s" },
      { id: 22, x: "65%", y: "88%", size: 1.5, delay: "3.0s", duration: "4.4s" },
      { id: 23, x: "25%", y: "92%", size: 2.5, delay: "1.6s", duration: "6.1s" },
      { id: 24, x: "75%", y: "38%", size: 1.5, delay: "0.2s", duration: "5.0s" },
    ];
  }, []);

  return (
    <div
      className={`absolute inset-0 pointer-events-none overflow-hidden select-none z-0 ${className}`}
    >
      {/* Layer 1: Base Deep Navy/Black Multi-Radial Glow */}
      <div
        className="absolute inset-0 bg-[#020617]"
        style={{
          background:
            "radial-gradient(circle at 82% 38%, rgba(0, 140, 255, 0.16) 0%, rgba(2, 6, 23, 0) 55%), radial-gradient(circle at 18% 45%, rgba(0, 100, 220, 0.10) 0%, rgba(2, 6, 23, 0) 50%), linear-gradient(180deg, #020617 0%, #030B1C 40%, #061226 75%, #020617 100%)",
        }}
      />

      {/* Layer 2: Subtle 40px Cyber Grid Mesh */}
      <svg
        className="absolute inset-0 w-full h-full opacity-[0.06]"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <pattern id="universalCyberGrid" width="40" height="40" patternUnits="userSpaceOnUse">
            <path d="M 40 0 L 0 0 0 40" fill="none" stroke="#00B7FF" strokeWidth="0.8" />
          </pattern>
        </defs>
        <rect width="100%" height="100%" fill="url(#universalCyberGrid)" />
      </svg>

      {/* Layer 3: Left Flank — Angular Tech Armor & Electric Cyan Slashes */}
      <svg
        className="absolute left-0 top-0 w-[420px] h-[580px] opacity-75 max-w-[35vw]"
        viewBox="0 0 420 580"
        fill="none"
      >
        <defs>
          <linearGradient id="bgArmorGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#081A33" stopOpacity="0.85" />
            <stop offset="60%" stopColor="#030B1C" stopOpacity="0.45" />
            <stop offset="100%" stopColor="#020617" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="bgNeonCyan" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0%" stopColor="#00D9FF" stopOpacity="0.9" />
            <stop offset="70%" stopColor="#008CFF" stopOpacity="0.5" />
            <stop offset="100%" stopColor="#155EEF" stopOpacity="0" />
          </linearGradient>
        </defs>

        <path
          d="M -40 200 L 90 320 L 70 460 L -40 380 Z"
          fill="url(#bgArmorGrad)"
          stroke="rgba(0, 183, 255, 0.22)"
          strokeWidth="1.2"
        />
        <path
          d="M -30 260 L 120 400 L 90 520 L -30 460 Z"
          fill="url(#bgArmorGrad)"
          stroke="rgba(0, 183, 255, 0.35)"
          strokeWidth="1.4"
        />

        <line
          x1="10"
          y1="230"
          x2="155"
          y2="375"
          stroke="url(#bgNeonCyan)"
          strokeWidth="3.5"
          strokeLinecap="round"
          filter="drop-shadow(0 0 8px #00D9FF)"
        />
        <line
          x1="-20"
          y1="340"
          x2="115"
          y2="475"
          stroke="#008CFF"
          strokeWidth="2"
          strokeOpacity="0.6"
        />

        <path
          d="M 120 400 L 190 400 L 230 440 L 320 440"
          stroke="rgba(0, 217, 255, 0.35)"
          strokeWidth="1.2"
          fill="none"
        />
        <circle cx="320" cy="440" r="3" fill="#00D9FF" className="animate-node-pulse-1" />
      </svg>

      {/* Layer 4: Variant-Specific Visual Graphics */}
      {/* 4A: Dashboard -> Global World Map & Rotating HUD Radar */}
      {variant === "dashboard" && (
        <>
          <div className="absolute right-0 top-0 w-[78%] h-[560px] opacity-85">
            <svg
              className="w-full h-full"
              viewBox="0 0 1000 520"
              preserveAspectRatio="xMidYMid meet"
              fill="none"
            >
              <defs>
                <linearGradient id="mapGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#0B254E" stopOpacity="0.45" />
                  <stop offset="100%" stopColor="#05142B" stopOpacity="0.15" />
                </linearGradient>
                <radialGradient id="nodeGlowRad" cx="50%" cy="50%" r="50%">
                  <stop offset="0%" stopColor="#00D9FF" stopOpacity="1" />
                  <stop offset="40%" stopColor="#008CFF" stopOpacity="0.6" />
                  <stop offset="100%" stopColor="#008CFF" stopOpacity="0" />
                </radialGradient>
              </defs>

              <g fill="url(#mapGrad)" stroke="rgba(0, 140, 255, 0.20)" strokeWidth="0.75">
                <path d="M 120 70 Q 180 50, 240 60 Q 280 80, 260 130 Q 240 170, 200 180 Q 180 210, 190 240 Q 150 210, 120 180 Q 100 120, 120 70 Z" />
                <path d="M 290 30 Q 330 25, 340 50 Q 320 80, 280 70 Z" />
                <path d="M 210 260 Q 250 270, 270 310 Q 280 370, 240 440 Q 210 400, 200 340 Q 190 290, 210 260 Z" />
                <path d="M 440 80 Q 490 70, 520 100 Q 510 140, 460 150 Q 420 130, 440 80 Z" />
                <path d="M 440 170 Q 520 170, 530 230 Q 520 310, 480 370 Q 440 330, 420 250 Q 410 200, 440 170 Z" />
                <path d="M 530 70 Q 640 40, 780 70 Q 820 110, 790 180 Q 720 220, 660 190 Q 620 210, 570 170 Q 530 130, 530 70 Z" />
                <path d="M 620 190 Q 650 200, 660 250 Q 630 280, 610 240 Z" />
                <path d="M 750 330 Q 830 330, 840 390 Q 800 440, 740 420 Q 730 370, 750 330 Z" />
              </g>

              <g stroke="rgba(0, 183, 255, 0.32)" strokeWidth="0.9" fill="none">
                <line x1="220" y1="120" x2="450" y2="110" />
                <line x1="220" y1="120" x2="210" y2="280" />
                <line x1="160" y1="140" x2="220" y2="120" />
                <line x1="450" y1="110" x2="480" y2="130" />
                <line x1="480" y1="130" x2="610" y2="120" />
                <line x1="610" y1="120" x2="740" y2="120" />
                <line x1="740" y1="120" x2="790" y2="210" />
                <line x1="640" y1="210" x2="760" y2="350" />
              </g>

              <circle cx="160" cy="140" r="4.5" fill="#00D9FF" className="animate-node-pulse-1" />
              <circle cx="220" cy="120" r="5" fill="#00D9FF" className="animate-node-pulse-2" />
              <circle cx="480" cy="130" r="5.5" fill="#00D9FF" className="animate-node-pulse-1" />
              <circle cx="740" cy="120" r="5" fill="#00D9FF" className="animate-node-pulse-1" />
              <circle cx="640" cy="210" r="4" fill="#00D9FF" className="animate-node-pulse-2" />
              <circle cx="760" cy="350" r="4.5" fill="#008CFF" className="animate-node-pulse-3" />
            </svg>
          </div>

          <div className="absolute right-4 sm:right-10 top-8 w-[280px] sm:w-[320px] h-[320px] pointer-events-none opacity-85">
            <svg className="w-full h-full" viewBox="0 0 320 320" fill="none">
              <g className="animate-radar-spin">
                <circle cx="160" cy="160" r="128" stroke="#008CFF" strokeWidth="1.2" strokeDasharray="4 8" opacity="0.45" />
                <path d="M 160 32 A 128 128 0 0 1 268 90" stroke="#00D9FF" strokeWidth="2.5" strokeLinecap="round" filter="drop-shadow(0 0 6px #00D9FF)" />
              </g>
              <g className="animate-radar-counter-spin">
                <circle cx="160" cy="160" r="98" stroke="#00D9FF" strokeWidth="1.4" strokeDasharray="16 6 4 6" opacity="0.65" />
              </g>
              <circle cx="160" cy="160" r="74" stroke="rgba(0, 140, 255, 0.4)" strokeWidth="1" />
              <g transform="translate(136, 134)">
                <path d="M 24 4 L 44 11 C 44 29, 36 41, 24 48 C 12 41, 4 29, 4 11 Z" fill="rgba(3, 16, 38, 0.75)" stroke="#00D9FF" strokeWidth="2" />
                <rect x="18" y="24" width="12" height="10" rx="1.5" fill="#00D9FF" />
              </g>
            </svg>
          </div>
        </>
      )}

      {/* 4B: Detections & Logs -> Threat Vector Constellation */}
      {(variant === "detections" || variant === "iocs") && (
        <div className="absolute right-0 top-0 w-[65%] h-[480px] opacity-70">
          <svg className="w-full h-full" viewBox="0 0 800 480" fill="none">
            <g stroke="rgba(0, 183, 255, 0.22)" strokeWidth="1" strokeDasharray="3 3">
              <line x1="100" y1="80" x2="350" y2="140" />
              <line x1="350" y1="140" x2="550" y2="90" />
              <line x1="350" y1="140" x2="300" y2="300" />
              <line x1="550" y1="90" x2="680" y2="220" />
              <line x1="300" y1="300" x2="520" y2="340" />
              <line x1="520" y1="340" x2="680" y2="220" />
            </g>
            <circle cx="350" cy="140" r="6" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="550" cy="90" r="5" fill="#008CFF" className="animate-node-pulse-2" />
            <circle cx="680" cy="220" r="6" fill="#EF4444" className="animate-node-pulse-1" />
            <circle cx="300" cy="300" r="4.5" fill="#00D9FF" className="animate-node-pulse-3" />
            <circle cx="520" cy="340" r="5" fill="#F59E0B" className="animate-node-pulse-2" />
          </svg>
        </div>
      )}

      {/* 4C: Analytics -> Analytical Mesh & Flowing Wave Splines */}
      {variant === "analytics" && (
        <div className="absolute right-0 top-0 w-[70%] h-[450px] opacity-60">
          <svg className="w-full h-full" viewBox="0 0 800 450" fill="none">
            <path
              d="M 50 280 Q 200 180, 400 240 T 750 140"
              stroke="#00D9FF"
              strokeWidth="1.8"
              fill="none"
              opacity="0.6"
            />
            <path
              d="M 50 320 Q 250 260, 480 300 T 780 200"
              stroke="#008CFF"
              strokeWidth="1.4"
              fill="none"
              opacity="0.4"
            />
            <circle cx="400" cy="240" r="5" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="600" cy="190" r="4" fill="#008CFF" className="animate-node-pulse-2" />
          </svg>
        </div>
      )}

      {/* 4D: Sigma Rules & Audit -> Circuit Board Trace Matrix */}
      {(variant === "sigma" || variant === "audit") && (
        <div className="absolute right-0 top-0 w-[60%] h-[500px] opacity-65">
          <svg className="w-full h-full" viewBox="0 0 700 500" fill="none">
            <path
              d="M 100 120 H 280 L 340 180 H 520 L 580 240 H 680"
              stroke="rgba(0, 217, 255, 0.35)"
              strokeWidth="1.5"
            />
            <path
              d="M 180 220 H 320 L 380 280 H 620"
              stroke="rgba(0, 140, 255, 0.25)"
              strokeWidth="1.2"
            />
            <circle cx="340" cy="180" r="4.5" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="580" cy="240" r="4.5" fill="#008CFF" className="animate-node-pulse-2" />
          </svg>
        </div>
      )}

      {/* 4E: MITRE ATT&CK -> Tactical Technique Node Grid */}
      {variant === "mitre" && (
        <div className="absolute right-0 top-0 w-[65%] h-[480px] opacity-65">
          <svg className="w-full h-full" viewBox="0 0 750 480" fill="none">
            <g stroke="rgba(0, 183, 255, 0.2)" strokeWidth="1">
              <line x1="120" y1="100" x2="680" y2="100" />
              <line x1="120" y1="220" x2="680" y2="220" />
              <line x1="120" y1="340" x2="680" y2="340" />
              <line x1="200" y1="60" x2="200" y2="380" />
              <line x1="380" y1="60" x2="380" y2="380" />
              <line x1="560" y1="60" x2="560" y2="380" />
            </g>
            <circle cx="200" cy="100" r="5" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="380" cy="220" r="5" fill="#008CFF" className="animate-node-pulse-2" />
            <circle cx="560" cy="100" r="5" fill="#EF4444" className="animate-node-pulse-1" />
            <circle cx="380" cy="340" r="4.5" fill="#00D9FF" className="animate-node-pulse-3" />
          </svg>
        </div>
      )}

      {/* 4F: Risk Analysis & Alerts -> Concentric HUD Radar Reticle */}
      {(variant === "risk" || variant === "alerts") && (
        <div className="absolute right-6 top-8 w-[320px] h-[320px] opacity-80">
          <svg className="w-full h-full" viewBox="0 0 320 320" fill="none">
            <g className="animate-radar-spin">
              <circle cx="160" cy="160" r="130" stroke="#008CFF" strokeWidth="1.2" strokeDasharray="6 6" opacity="0.45" />
              <circle cx="160" cy="160" r="90" stroke="#00D9FF" strokeWidth="1.5" strokeDasharray="12 4" opacity="0.6" />
            </g>
            <circle cx="160" cy="160" r="50" stroke="rgba(0, 217, 255, 0.4)" strokeWidth="1.2" />
            <line x1="160" y1="20" x2="160" y2="300" stroke="rgba(0, 183, 255, 0.25)" strokeWidth="1" strokeDasharray="4 4" />
            <line x1="20" y1="160" x2="300" y2="160" stroke="rgba(0, 183, 255, 0.25)" strokeWidth="1" strokeDasharray="4 4" />
          </svg>
        </div>
      )}

      {/* 4G: Incidents -> Investigation Command Web */}
      {variant === "incidents" && (
        <div className="absolute right-4 top-4 w-[60%] h-[460px] opacity-70">
          <svg className="w-full h-full" viewBox="0 0 700 460" fill="none">
            <g stroke="rgba(0, 183, 255, 0.25)" strokeWidth="1.2">
              <line x1="450" y1="220" x2="280" y2="120" />
              <line x1="450" y1="220" x2="320" y2="340" />
              <line x1="450" y1="220" x2="620" y2="140" />
              <line x1="450" y1="220" x2="580" y2="330" />
            </g>
            <circle cx="450" cy="220" r="10" fill="rgba(239, 68, 68, 0.2)" stroke="#EF4444" strokeWidth="2" className="animate-pulse" />
            <circle cx="280" cy="120" r="5" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="320" cy="340" r="5" fill="#008CFF" className="animate-node-pulse-2" />
            <circle cx="620" cy="140" r="5" fill="#F59E0B" className="animate-node-pulse-3" />
            <circle cx="580" cy="330" r="5" fill="#00D9FF" className="animate-node-pulse-1" />
          </svg>
        </div>
      )}

      {/* 4H: Evidence Timeline -> Vertical Chronological Circuit Bus */}
      {variant === "timeline" && (
        <div className="absolute right-12 top-0 w-[400px] h-[550px] opacity-65">
          <svg className="w-full h-full" viewBox="0 0 400 550" fill="none">
            <line x1="200" y1="40" x2="200" y2="500" stroke="rgba(0, 183, 255, 0.3)" strokeWidth="2" />
            <circle cx="200" cy="100" r="6" fill="#00D9FF" className="animate-node-pulse-1" />
            <line x1="200" y1="100" x2="280" y2="100" stroke="rgba(0, 217, 255, 0.3)" strokeWidth="1.2" />
            <circle cx="200" cy="220" r="6" fill="#F59E0B" className="animate-node-pulse-2" />
            <line x1="120" y1="220" x2="200" y2="220" stroke="rgba(245, 158, 11, 0.3)" strokeWidth="1.2" />
            <circle cx="200" cy="360" r="6" fill="#EF4444" className="animate-node-pulse-1" />
            <line x1="200" y1="360" x2="290" y2="360" stroke="rgba(239, 68, 68, 0.3)" strokeWidth="1.2" />
          </svg>
        </div>
      )}

      {/* 4I: Pipeline Trace -> Flowing Pipeline Data Streams */}
      {variant === "pipeline" && (
        <div className="absolute right-0 top-8 w-[70%] h-[400px] opacity-75">
          <svg className="w-full h-full" viewBox="0 0 800 400" fill="none">
            <path
              d="M 50 160 H 220 L 280 220 H 480 L 540 160 H 750"
              stroke="#00D9FF"
              strokeWidth="2"
              className="animate-pipeline-flow"
            />
            <path
              d="M 50 240 H 180 L 240 180 H 420 L 480 240 H 750"
              stroke="#008CFF"
              strokeWidth="1.5"
              className="animate-pipeline-flow"
              opacity="0.6"
            />
            <circle cx="220" cy="160" r="5" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="480" cy="220" r="5" fill="#008CFF" className="animate-node-pulse-2" />
            <circle cx="540" cy="160" r="5" fill="#00D9FF" className="animate-node-pulse-3" />
          </svg>
        </div>
      )}

      {/* 4J: SOC Health -> Heartbeat ECG Telemetry Pulse */}
      {variant === "health" && (
        <div className="absolute right-4 top-12 w-[65%] h-[350px] opacity-75">
          <svg className="w-full h-full" viewBox="0 0 700 350" fill="none">
            <path
              d="M 50 180 H 240 L 260 120 L 285 240 L 310 90 L 330 210 L 350 180 H 680"
              stroke="#22C55E"
              strokeWidth="2"
              fill="none"
              filter="drop-shadow(0 0 8px rgba(34, 197, 94, 0.6))"
            />
            <circle cx="310" cy="90" r="5" fill="#22C55E" className="animate-heartbeat" />
          </svg>
        </div>
      )}

      {/* 4K: AI Threat Copilot -> Neural Network Synapses */}
      {variant === "copilot" && (
        <div className="absolute right-0 top-4 w-[60%] h-[480px] opacity-65">
          <svg className="w-full h-full" viewBox="0 0 650 480" fill="none">
            <g stroke="rgba(0, 217, 255, 0.25)" strokeWidth="1.2">
              <line x1="150" y1="120" x2="320" y2="180" />
              <line x1="150" y1="280" x2="320" y2="180" />
              <line x1="320" y1="180" x2="480" y2="140" />
              <line x1="320" y1="180" x2="480" y2="280" />
              <line x1="480" y1="140" x2="600" y2="200" />
              <line x1="480" y1="280" x2="600" y2="200" />
            </g>
            <circle cx="320" cy="180" r="7" fill="#00D9FF" className="animate-node-pulse-1" />
            <circle cx="480" cy="140" r="5" fill="#008CFF" className="animate-node-pulse-2" />
            <circle cx="480" cy="280" r="5" fill="#008CFF" className="animate-node-pulse-3" />
            <circle cx="600" cy="200" r="6" fill="#00D9FF" className="animate-node-pulse-1" />
          </svg>
        </div>
      )}

      {/* Layer 5: Ambient Floating Micro-Particles */}
      {particles.map((p) => (
        <span
          key={p.id}
          className="absolute rounded-full bg-[#00D9FF] pointer-events-none"
          style={{
            left: p.x,
            top: p.y,
            width: `${p.size}px`,
            height: `${p.size}px`,
            opacity: 0.45,
            boxShadow: "0 0 6px #00D9FF",
            animation: `nodeGlowPulse ${p.duration} ease-in-out ${p.delay} infinite`,
          }}
        />
      ))}

      {/* Layer 6: Dark Edge Vignette Mask for 100% Foreground Legibility */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse at 50% 45%, rgba(2, 6, 23, 0.15) 30%, rgba(2, 6, 23, 0.75) 85%, #020617 100%)",
        }}
      />

      {/* Layer 7: Top Header Safe Zone Ambient Mask — Eliminates any visual line/glow interference behind page headings */}
      <div
        className="absolute top-0 left-0 right-0 h-44 pointer-events-none"
        style={{
          background:
            "linear-gradient(180deg, rgba(2, 6, 23, 0.96) 0%, rgba(2, 6, 23, 0.75) 60%, rgba(2, 6, 23, 0) 100%)",
        }}
      />
    </div>
  );
};
