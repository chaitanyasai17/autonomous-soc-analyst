import React from "react";

interface SOCButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost" | "warning";
  size?: "sm" | "md" | "lg";
  icon?: React.ReactNode | React.ComponentType<{ className?: string }>;
  loading?: boolean;
  glow?: boolean;
}

export const SOCButton: React.FC<SOCButtonProps> = ({
  children,
  variant = "primary",
  size = "md",
  icon,
  loading = false,
  glow = false,
  className = "",
  disabled,
  ...props
}) => {
  const variantStyles = {
    primary:
      "bg-gradient-to-r from-[#008CFF] to-[#00D9FF] hover:from-[#0070CC] hover:to-[#00B7FF] text-slate-950 font-bold shadow-cyber-glow-sm border border-cyan-300/40",
    secondary:
      "bg-[rgba(7,20,42,0.85)] hover:bg-[rgba(14,35,70,0.95)] text-slate-200 border border-[rgba(0,183,255,0.25)] hover:border-[rgba(0,183,255,0.5)] font-semibold",
    danger:
      "bg-red-950/60 hover:bg-red-900/80 text-red-300 border border-red-500/40 hover:border-red-500 font-semibold shadow-cyber-glow-red",
    warning:
      "bg-amber-950/60 hover:bg-amber-900/80 text-amber-300 border border-amber-500/40 hover:border-amber-500 font-semibold",
    ghost:
      "bg-transparent hover:bg-white/5 text-slate-300 hover:text-white border border-transparent font-medium",
  };

  const sizeStyles = {
    sm: "px-2.5 py-1 text-xs rounded-lg gap-1.5",
    md: "px-3.5 py-2 text-xs font-semibold rounded-xl gap-2",
    lg: "px-5 py-2.5 text-sm font-bold rounded-xl gap-2.5",
  };

  const glowStyle = glow ? "shadow-cyber-glow" : "";

  const renderIcon = () => {
    if (!icon) return null;
    if (typeof icon === "function" || (typeof icon === "object" && "$$typeof" in icon && !React.isValidElement(icon))) {
      const IconComponent = icon as React.ComponentType<{ className?: string }>;
      return <IconComponent className="w-3.5 h-3.5 shrink-0" />;
    }
    if (React.isValidElement(icon)) {
      return <span className="shrink-0">{icon}</span>;
    }
    if (typeof icon === "object") {
      const IconComponent = icon as any;
      return <IconComponent className="w-3.5 h-3.5 shrink-0" />;
    }
    return <span className="shrink-0">{icon as React.ReactNode}</span>;
  };

  return (
    <button
      className={`inline-flex items-center justify-center transition-all duration-150 active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none ${variantStyles[variant]} ${sizeStyles[size]} ${glowStyle} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading ? (
        <span className="w-3.5 h-3.5 border-2 border-current border-t-transparent rounded-full animate-spin shrink-0" />
      ) : (
        renderIcon()
      )}
      <span>{children}</span>
    </button>
  );
};
