import React from "react";

interface GlassCardProps extends React.HTMLAttributes<HTMLDivElement> {
  children: React.ReactNode;
  variant?: "default" | "subtle" | "glow" | "critical";
  className?: string;
  hoverEffect?: boolean;
}

export const GlassCard: React.FC<GlassCardProps> = ({
  children,
  variant = "default",
  className = "",
  hoverEffect = true,
  ...props
}) => {
  const variantClasses = {
    default: "cyber-panel rounded-xl",
    subtle: "cyber-panel-subtle rounded-xl",
    glow: "cyber-panel rounded-xl border-[#00B7FF]/40 shadow-cyber-glow-sm",
    critical: "rounded-xl bg-[#140b17]/90 border border-red-500/40 shadow-cyber-glow-red backdrop-blur-md",
  };

  const hoverClass = hoverEffect
    ? "transition-all duration-200 hover:border-[#00B7FF]/40 hover:-translate-y-0.5"
    : "";

  return (
    <div
      className={`${variantClasses[variant]} ${hoverClass} p-4 sm:p-5 ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};
