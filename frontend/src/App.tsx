import React from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { ToastProvider } from "./components/common/Toast";
import { AppLayout } from "./layouts/AppLayout";
import { ErrorBoundary } from "./components/common/ErrorBoundary";

// Auth Pages
import { Login } from "./pages/Login";
import { Register } from "./pages/Register";

// Operational Pages
import { Dashboard } from "./pages/Dashboard";
import { Endpoints } from "./pages/Endpoints";
import { EndpointDetail } from "./pages/EndpointDetail";
import { LogManagement } from "./pages/LogManagement";
import { LogDetail } from "./pages/LogDetail";
import { Detections } from "./pages/Detections";
import { DetectionAnalytics } from "./pages/DetectionAnalytics";
import { SigmaRules } from "./pages/SigmaRules";
import { MitreExplorer } from "./pages/MitreExplorer";
import { RiskAnalysis } from "./pages/RiskAnalysis";
import { AlertManagement } from "./pages/AlertManagement";
import { IncidentManagement } from "./pages/IncidentManagement";
import { IncidentDetail } from "./pages/IncidentDetail";
import { AICopilot } from "./pages/AICopilot";
import { Reports } from "./pages/Reports";
import { Notifications } from "./pages/Notifications";
import { Settings } from "./pages/Settings";
import { AttackSimulator } from "./pages/AttackSimulator";
import { WebSecurityLab } from "./pages/WebSecurityLab";
import { IOCExplorer } from "./pages/IOCExplorer";
import { SOCHealth } from "./pages/SOCHealth";
import { EvidenceTimeline } from "./pages/EvidenceTimeline";
import { PipelineTrace } from "./pages/PipelineTrace";
import { AuditTrail } from "./pages/AuditTrail";

// Protected Route Guard
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-[#090d16] text-cyan-400">
        <div className="flex flex-col items-center gap-3">
          <div className="w-10 h-10 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
          <p className="text-xs font-mono uppercase tracking-widest text-slate-400">
            Verifying SOC Analyst Session...
          </p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

// Public Route Guard (redirects already authenticated users to dashboard)
const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return null;
  }

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <ToastProvider>
        <AuthProvider>
          <ErrorBoundary moduleName="Autonomous SOC Platform">
            <Routes>
              {/* Public Auth Routes */}
              <Route
                path="/login"
                element={
                  <PublicRoute>
                    <Login />
                  </PublicRoute>
                }
              />
              <Route
                path="/register"
                element={
                  <PublicRoute>
                    <Register />
                  </PublicRoute>
                }
              />

              {/* Protected SOC Workspace Routes */}
              <Route
                element={
                  <ProtectedRoute>
                    <AppLayout />
                  </ProtectedRoute>
                }
              >
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/endpoints" element={<Endpoints />} />
                <Route path="/endpoints/:id" element={<EndpointDetail />} />
                <Route path="/logs" element={<LogManagement />} />
                <Route path="/logs/:id" element={<LogDetail />} />
                <Route path="/detections" element={<Detections />} />
                <Route path="/detection-analytics" element={<DetectionAnalytics />} />
                <Route path="/detections/analytics" element={<Navigate to="/detection-analytics" replace />} />
                <Route path="/rules" element={<SigmaRules />} />
                <Route path="/sigma" element={<SigmaRules />} />
                <Route path="/mitre" element={<MitreExplorer />} />
                <Route path="/risk" element={<RiskAnalysis />} />
                <Route path="/alerts" element={<AlertManagement />} />
                <Route path="/incidents" element={<IncidentManagement />} />
                <Route path="/incidents/:id" element={<IncidentDetail />} />
                <Route path="/copilot" element={<AICopilot />} />
                <Route path="/ai" element={<AICopilot />} />
                <Route path="/ai-threat-copilot" element={<AICopilot />} />
                <Route path="/simulator" element={<AttackSimulator />} />
                <Route path="/range" element={<AttackSimulator />} />
                <Route path="/attack-simulator" element={<AttackSimulator />} />
                <Route path="/web-security" element={<WebSecurityLab />} />
                <Route path="/iocs" element={<IOCExplorer />} />
                <Route path="/ioc-explorer" element={<IOCExplorer />} />
                <Route path="/evidence-timeline" element={<EvidenceTimeline />} />
                <Route path="/timeline" element={<Navigate to="/evidence-timeline" replace />} />
                <Route path="/pipeline" element={<PipelineTrace />} />
                <Route path="/pipeline-trace" element={<PipelineTrace />} />
                <Route path="/soc-health" element={<SOCHealth />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/notifications" element={<Notifications />} />
                <Route path="/audit" element={<AuditTrail />} />
                <Route path="/audit-trail" element={<AuditTrail />} />
                <Route path="/settings" element={<Settings />} />
              </Route>

              {/* Fallback */}
              <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
          </ErrorBoundary>
        </AuthProvider>
      </ToastProvider>
    </BrowserRouter>
  );
};

export default App;
