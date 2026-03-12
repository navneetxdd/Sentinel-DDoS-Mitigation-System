import { cn } from "@/lib/utils";

function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("animate-pulse rounded-md bg-muted", className)} {...props} />;
}

/**
 * Skeleton loader for StatCard components
 * Mimics the layout of a fully loaded StatCard
 */
export function StatCardSkeleton() {
  return (
    <div className="cyber-card glow-border p-6 rounded-lg flex flex-col gap-4">
      <div className="flex items-start justify-between">
        <div className="space-y-1 flex-1">
          <Skeleton className="h-3 w-24 mb-2" />
          <div className="flex items-baseline gap-2">
            <Skeleton className="h-8 w-20" />
            <Skeleton className="h-4 w-12" />
          </div>
        </div>
        <Skeleton className="w-10 h-10 rounded-lg" />
      </div>
      <Skeleton className="h-4 w-full" />
    </div>
  );
}

/**
 * Skeleton loader for table rows
 * Provides row structure with column placeholders
 */
interface TableSkeletonProps {
  rows?: number;
  cols?: number;
}

export function TableSkeleton({ rows = 5, cols = 4 }: TableSkeletonProps) {
  return (
    <div className="space-y-3">
      {/* Header row */}
      <div className="flex gap-4 pb-3 border-b border-border">
        {Array.from({ length: cols }).map((_, i) => (
          <Skeleton key={`header-${i}`} className="h-4 flex-1" />
        ))}
      </div>
      {/* Body rows */}
      {Array.from({ length: rows }).map((_, rowIdx) => (
        <div key={`row-${rowIdx}`} className="flex gap-4">
          {Array.from({ length: cols }).map((_, colIdx) => (
            <Skeleton
              key={`cell-${rowIdx}-${colIdx}`}
              className="h-4 flex-1"
            />
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * Skeleton loader for charts
 * Provides rectangular placeholder for chart area
 */
export function ChartSkeleton() {
  return (
    <div className="cyber-card glow-border p-6 rounded-lg">
      <div className="space-y-4">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="h-64 w-full" />
      </div>
    </div>
  );
}

/**
 * Skeleton loader for panels
 * Provides header and content placeholders
 */
export function PanelSkeleton() {
  return (
    <div className="cyber-card glow-border border border-border rounded-lg p-6 space-y-4">
      <div>
        <Skeleton className="h-6 w-40 mb-2" />
        <Skeleton className="h-4 w-64" />
      </div>
      <div className="space-y-3">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={`skeleton-line-${i}`} className="h-4 w-full" />
        ))}
      </div>
    </div>
  );
}

/**
 * Loading state wrapper for graceful degradation
 * Shows skeleton while loading, then content when ready
 */
interface SkeletonWrapperProps {
  isLoading: boolean;
  children: React.ReactNode;
  skeleton?: React.ReactNode;
}

export function SkeletonWrapper({
  isLoading,
  children,
  skeleton,
}: SkeletonWrapperProps) {
  if (isLoading && skeleton) {
    return <>{skeleton}</>;
  }
  return <>{children}</>;
}

export { Skeleton };
