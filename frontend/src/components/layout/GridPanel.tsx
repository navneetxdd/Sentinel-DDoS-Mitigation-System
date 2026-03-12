import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface GridLayoutProps {
  children: ReactNode;
  cols?: number;
  gap?: "sm" | "md" | "lg";
  className?: string;
}

/**
 * Consistent responsive grid for dashboard layouts
 * Automatically handles mobile, tablet, and desktop breakpoints
 */
export function GridLayout({
  children,
  cols = 1,
  gap = "md",
  className,
}: GridLayoutProps) {
  const colsMap = {
    1: "grid-cols-1",
    2: "md:grid-cols-2",
    3: "lg:grid-cols-3",
    4: "lg:grid-cols-4",
  };

  const gapMap = {
    sm: "gap-3",
    md: "gap-4",
    lg: "gap-6",
  };

  return (
    <div
      className={cn(
        "grid",
        colsMap[cols as keyof typeof colsMap] || colsMap[1],
        gapMap[gap],
        className
      )}
    >
      {children}
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string | number;
  unit?: string;
  icon?: ReactNode;
  trend?: {
    value: number;
    isPositive: boolean;
  };
  variant?: "default" | "success" | "warning" | "danger";
  className?: string;
}

/**
 * Unified stat card with consistent styling
 * Replaces duplicate KPICard implementations across pages
 */
export function StatCard({
  label,
  value,
  unit,
  icon,
  trend,
  variant = "default",
  className,
}: StatCardProps) {
  const variantMap = {
    default: "bg-secondary/50 text-foreground",
    success: "bg-status-success/10 text-status-success",
    warning: "bg-status-warning/10 text-status-warning",
    danger: "bg-status-danger/10 text-status-danger",
  };

  return (
    <div
      className={cn(
        "cyber-card glow-border p-6 rounded-lg flex flex-col gap-4",
        className
      )}
      role="status"
      aria-label={`${label}: ${value} ${unit || ''}`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
            {label}
          </p>
          <div className="flex items-baseline gap-2">
            <p className="text-3xl font-bold font-mono tracking-tight">{value}</p>
            {unit && (
              <p className="text-sm text-muted-foreground">{unit}</p>
            )}
          </div>
        </div>
        {icon && (
          <div 
            className={cn("p-2 rounded-lg", variantMap[variant])}
            aria-label={`${label} status indicator`}
          >
            {icon}
          </div>
        )}
      </div>

      {trend && (
        <div className="text-xs text-muted-foreground">
          <span className={trend.isPositive ? "text-status-success" : "text-status-danger"}>
            {trend.isPositive ? "+" : "-"}{Math.abs(trend.value)}%
          </span>
          &nbsp;from previous period
        </div>
      )}
    </div>
  );
}

interface PanelProps {
  title?: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
  variant?: "default" | "highlight" | "minimal";
  className?: string;
}

/**
 * Unified panel/card component to replace scattered card implementations
 * Provides consistent border, padding, and layout
 */
export function Panel({
  title,
  description,
  children,
  footer,
  variant = "default",
  className,
}: PanelProps) {
  const variantMap = {
    default: "cyber-card glow-border border border-border",
    highlight: "cyber-card glow-border border-2 border-accent",
    minimal: "border border-border/50",
  };

  return (
    <div
      className={cn(
        variantMap[variant],
        "rounded-lg overflow-hidden",
        className
      )}
      role="region"
      aria-label={title}
    >
      {(title || description) && (
        <div className="px-6 py-4 border-b border-border/50">
          {title && <h3 className="font-semibold text-foreground">{title}</h3>}
          {description && (
            <p className="text-sm text-muted-foreground mt-1">{description}</p>
          )}
        </div>
      )}

      <div className="p-6">{children}</div>

      {footer && <div className="px-6 py-4 border-t border-border/50 bg-secondary/30">{footer}</div>}
    </div>
  );
}
