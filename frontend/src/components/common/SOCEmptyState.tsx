import React from "react";
import { AlertCircle, AlertTriangle, RefreshCw } from "lucide-react";
import { GlassCard } from "./GlassCard";
import { SOCButton } from "./SOCButton";

interface SOCEmptyStateProps {
  title?: string;
  description: string;
  icon?: React.ReactNode;
  action?: {
    label: string;
    onClick: () => void;
  };
  className?: string;
}

export const SOCEmptyState: React.FC<SOCEmptyStateProps> = ({
  title = "No Data Found",
  description,
  icon,
  action,
  className = "",
}) => {
  return (
    <GlassCard className={`text-center py-12 px-6 ${className}`}>
      <div className="w-12 h-12 rounded-xl bg-blue-500/10 border border-blue-500/20 text-[#00D9FF] flex items-center justify-center mx-auto mb-3 shadow-cyber-glow-sm">
        {icon || <AlertCircle className="w-6 h-6 text-[#00D9FF]" />}
      </div>
      <h3 className="text-sm font-bold text-white uppercase tracking-wider">{title}</h3>
      <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto leading-relaxed">
        {description}
      </p>
      {action && (
        <div className="mt-4">
          <SOCButton variant="secondary" size="sm" onClick={action.onClick}>
            {action.label}
          </SOCButton>
        </div>
      )}
    </GlassCard>
  );
};

interface SOCErrorStateProps {
  title?: string;
  error?: string;
  onRetry?: () => void;
  className?: string;
}

export const SOCErrorState: React.FC<SOCErrorStateProps> = ({
  title = "Failed to Load SOC Data",
  error = "An error occurred while communicating with the Autonomous SOC engine.",
  onRetry,
  className = "",
}) => {
  return (
    <GlassCard variant="critical" className={`text-center py-10 px-6 ${className}`}>
      <div className="w-12 h-12 rounded-xl bg-red-950/80 border border-red-500/40 text-red-400 flex items-center justify-center mx-auto mb-3 shadow-cyber-glow-red">
        <AlertTriangle className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-bold text-white uppercase tracking-wider">{title}</h3>
      <p className="text-xs text-red-300/80 mt-1 max-w-md mx-auto leading-relaxed">{error}</p>
      {onRetry && (
        <div className="mt-4">
          <SOCButton variant="secondary" size="sm" icon={<RefreshCw className="w-3.5 h-3.5" />} onClick={onRetry}>
            Retry Request
          </SOCButton>
        </div>
      )}
    </GlassCard>
  );
};
