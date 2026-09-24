import React from "react";
import { Shield } from "lucide-react";
import { SOCBadge } from "./SOCBadge";

export interface BadgeObject {
  label: string;
  variant?: "primary" | "secondary" | "success" | "warning" | "danger" | "neutral" | "default" | string;
  pulse?: boolean;
}

export interface SOCPageHeaderProps {
  title: string;
  subtitle?: string;
  icon?: React.ReactNode | React.ComponentType<{ className?: string }>;
  tagline?: string;
  badge?: React.ReactNode | BadgeObject;
  badgeText?: string;
  actions?: React.ReactNode;
  className?: string;
}

export const SOCPageHeader: React.FC<SOCPageHeaderProps> = ({
  title,
  subtitle,
  icon,
  tagline,
  badge,
  badgeText,
  actions,
  className = "",
}) => {
  const renderIcon = () => {
    if (React.isValidElement(icon)) {
      return icon;
    }
    if (
      typeof icon === "function" ||
      (typeof icon === "object" && icon !== null && "$$typeof" in icon)
    ) {
      const IconComp = icon as React.ComponentType<{ className?: string }>;
      return <IconComp className="w-5 h-5 sm:w-6 sm:h-6 text-[#00D9FF]" />;
    }
    if (typeof icon === "object" && icon !== null) {
      const IconComp = icon as any;
      return <IconComp className="w-5 h-5 sm:w-6 sm:h-6 text-[#00D9FF]" />;
    }
    return <Shield className="w-5 h-5 sm:w-6 sm:h-6 text-[#00D9FF]" />;
  };

  const renderBadge = () => {
    if (badgeText) {
      return (
        <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase tracking-wider bg-cyan-950/80 text-cyan-300 border border-cyan-700/50 shadow-cyber-glow-sm">
          {badgeText}
        </span>
      );
    }
    if (badge) {
      if (typeof badge === "object" && badge !== null && "label" in badge) {
        const b = badge as BadgeObject;
        return (
          <SOCBadge
            variant={b.variant || "primary"}
            pulse={b.pulse}
            className="uppercase tracking-wider font-mono text-[10px]"
          >
            {b.label}
          </SOCBadge>
        );
      }
      return badge as React.ReactNode;
    }
    return null;
  };

  return (
    <header
      role="banner"
      className={`relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-4 px-4 py-3.5 sm:px-6 sm:py-4.5 rounded-xl border-b border-[rgba(0,183,255,0.15)] shadow-[0_4px_24px_-4px_rgba(2,6,23,0.8)] ${className}`}
      style={{
        background:
          "linear-gradient(90deg, rgba(2, 15, 35, 0.92) 0%, rgba(2, 15, 35, 0.65) 60%, rgba(2, 15, 35, 0) 100%)",
        backdropFilter: "blur(12px)",
        WebkitBackdropFilter: "blur(12px)",
      }}
    >
      <div className="flex items-start sm:items-center gap-3.5 sm:gap-4 min-w-0">
        {/* 44-48px Heading Icon Container with Cyan Glow */}
        <div className="w-11 h-11 sm:w-12 sm:h-12 rounded-xl bg-[rgba(0,183,255,0.08)] border border-[rgba(0,183,255,0.30)] text-[#00D9FF] flex items-center justify-center shrink-0 shadow-[0_0_15px_rgba(0,217,255,0.12)]">
          {renderIcon()}
        </div>

        {/* Title, Subtitle, Tagline & Badges */}
        <div className="min-w-0 flex-1">
          {tagline && (
            <div className="text-[#00D9FF] font-mono text-[11px] sm:text-xs font-bold tracking-[0.12em] uppercase mb-1 flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-[#00D9FF] shadow-[0_0_6px_#00D9FF] animate-pulse" />
              <span>{tagline}</span>
            </div>
          )}

          <div className="flex items-center gap-2.5 sm:gap-3 flex-wrap">
            <h1 className="text-2xl sm:text-[28px] lg:text-[32px] font-extrabold sm:font-black text-[#F8FAFC] tracking-[-0.02em] leading-[1.15] uppercase select-text drop-shadow-[0_2px_8px_rgba(0,0,0,0.8)]">
              {title}
            </h1>
            {renderBadge()}
          </div>

          {subtitle && (
            <p className="text-[13px] sm:text-[14px] text-[#94A3B8] leading-relaxed max-w-4xl mt-1 select-text">
              {subtitle}
            </p>
          )}
        </div>
      </div>

      {/* Action Buttons Row */}
      {actions && (
        <div className="flex items-center gap-2.5 sm:gap-3 flex-wrap shrink-0 md:self-center">
          {actions}
        </div>
      )}
    </header>
  );
};
