import React, { Component, ErrorInfo, ReactNode } from "react";
import { AlertOctagon, RefreshCw, Home, ChevronDown, ChevronRight, Terminal } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
  moduleName?: string;
  onReset?: () => void;
}

interface State {
  hasError: boolean;
  error: Error | null;
  errorInfo: ErrorInfo | null;
  showDiagnostics: boolean;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
    errorInfo: null,
    showDiagnostics: false,
  };

  public static getDerivedStateFromError(error: Error): Partial<State> {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error("[ASOC ErrorBoundary] Caught uncaught component error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  public handleReset = () => {
    if (this.props.onReset) {
      this.props.onReset();
    }
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      showDiagnostics: false,
    });
  };

  public handleGoDashboard = () => {
    this.handleReset();
    window.location.href = "/dashboard";
  };

  public render() {
    if (this.state.hasError) {
      if (this.props.fallback) {
        return this.props.fallback;
      }

      const moduleTitle = this.props.moduleName || "SOC Module";

      return (
        <div className="w-full my-6 p-6 md:p-8 rounded-2xl bg-[#030B1C]/90 border border-red-500/40 shadow-cyber-glow-red backdrop-blur-xl">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-6 pb-6 border-b border-[rgba(0,183,255,0.15)]">
            <div className="flex items-center gap-4">
              <div className="p-3.5 rounded-xl bg-red-950/80 border border-red-500/40 text-red-400 shrink-0">
                <AlertOctagon className="w-7 h-7" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/30">
                    Component Fault Caught
                  </span>
                  <span className="text-xs text-slate-500 font-mono">
                    ASOC-ERR-SHIELD
                  </span>
                </div>
                <h2 className="text-lg md:text-xl font-bold text-white mt-1">
                  Unable to Render {moduleTitle}
                </h2>
                <p className="text-xs text-slate-400 mt-1 max-w-xl">
                  An isolated runtime exception occurred within this module. The application shell
                  and underlying security engines remain fully operational.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3 w-full md:w-auto">
              <button
                onClick={this.handleReset}
                className="flex-1 md:flex-initial flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-gradient-to-r from-[#008CFF] to-[#00D9FF] hover:from-[#0070CC] hover:to-[#00B7FF] text-slate-950 font-bold text-xs transition-colors shadow-cyber-glow-sm"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Retry Loading</span>
              </button>

              <button
                onClick={this.handleGoDashboard}
                className="flex-1 md:flex-initial flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-[rgba(7,20,42,0.85)] hover:bg-[rgba(14,35,70,0.95)] text-slate-200 border border-[rgba(0,183,255,0.25)] font-medium text-xs transition-colors"
              >
                <Home className="w-3.5 h-3.5 text-[#00D9FF]" />
                <span>Return to Dashboard</span>
              </button>
            </div>
          </div>

          {/* Technical Diagnostics Accordion */}
          <div className="mt-4">
            <button
              onClick={() => this.setState((prev) => ({ showDiagnostics: !prev.showDiagnostics }))}
              className="flex items-center gap-2 text-xs font-mono text-slate-400 hover:text-slate-200 transition-colors"
            >
              {this.state.showDiagnostics ? (
                <ChevronDown className="w-4 h-4 text-cyan-400" />
              ) : (
                <ChevronRight className="w-4 h-4 text-cyan-400" />
              )}
              <Terminal className="w-3.5 h-3.5 text-slate-500" />
              <span>Technical Diagnostics & Stack Trace</span>
            </button>

            {this.state.showDiagnostics && (
              <div className="mt-3 p-4 rounded-xl bg-slate-950/90 border border-slate-800 font-mono text-xs space-y-2 text-slate-300 overflow-x-auto">
                <div>
                  <span className="text-red-400 font-bold">Error: </span>
                  <span className="text-slate-200">
                    {this.state.error?.message || "Unknown rendering exception"}
                  </span>
                </div>
                {this.state.error?.stack && (
                  <div className="mt-2">
                    <span className="text-slate-500 text-[11px] block uppercase mb-1">
                      Stack Trace:
                    </span>
                    <pre className="text-[11px] text-slate-400 leading-relaxed whitespace-pre-wrap max-h-48 overflow-y-auto">
                      {this.state.error.stack}
                    </pre>
                  </div>
                )}
                {this.state.errorInfo?.componentStack && (
                  <div className="mt-2 pt-2 border-t border-slate-800/80">
                    <span className="text-slate-500 text-[11px] block uppercase mb-1">
                      Component Stack:
                    </span>
                    <pre className="text-[11px] text-cyan-300/70 leading-relaxed whitespace-pre-wrap max-h-36 overflow-y-auto">
                      {this.state.errorInfo.componentStack}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
