import { useEffect, useState } from "react";
import {
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Area,
  AreaChart,
} from "recharts";
import { cn } from "@/lib/utils";
import type { TrafficDataPoint } from "@/hooks/useSentinelWebSocket";

interface TrafficChartProps {
  className?: string;
  isAttack?: boolean;
  data?: TrafficDataPoint[];
}

interface TrafficTooltipProps {
  active?: boolean;
  payload?: Array<{ value: number }>;
  label?: string;
}

export function TrafficChart({ className, isAttack = false, data }: TrafficChartProps) {
  /* Use live data from WebSocket when available, otherwise show empty chart */
  const chartData = data && data.length > 0 ? data : [];

  const CustomTooltip = ({ active, payload, label }: TrafficTooltipProps) => {
    if (active && payload && payload.length) {
      return (
        <div className="chart-tooltip">
          <p className="text-xs text-muted-foreground mb-1">{label}</p>
          <p className="font-mono font-bold text-primary">
            {payload[0].value.toLocaleString()} pps
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-xl", className)}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="font-semibold">Traffic Rate</h3>
          <p className="text-xs text-muted-foreground">Packets per second</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={cn(
            "w-2 h-2 rounded-full",
            isAttack ? "bg-cyber-red animate-pulse-glow" : "bg-cyber-green"
          )} />
          <span className={cn(
            "text-xs font-medium",
            isAttack ? "text-cyber-red" : "text-cyber-green"
          )}>
            {isAttack ? "Elevated" : "Normal"}
          </span>
        </div>
      </div>

      <div className="h-64">
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop
                    offset="0%"
                    stopColor={isAttack ? "hsl(0, 72%, 51%)" : "hsl(var(--primary))"}
                    stopOpacity={0.3}
                  />
                  <stop
                    offset="100%"
                    stopColor={isAttack ? "hsl(0, 72%, 51%)" : "hsl(var(--primary))"}
                    stopOpacity={0}
                  />
                </linearGradient>
              </defs>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
                vertical={false}
              />
              <XAxis
                dataKey="time"
                tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                axisLine={{ stroke: "hsl(var(--border))" }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                axisLine={{ stroke: "hsl(var(--border))" }}
                tickLine={false}
                tickFormatter={(val) => val >= 1000 ? `${(val / 1000).toFixed(0)}k` : `${val}`}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area
                type="monotone"
                dataKey="packets"
                stroke={isAttack ? "hsl(0, 72%, 51%)" : "hsl(var(--primary))"}
                strokeWidth={2}
                fill="url(#trafficGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full">
            <p className="text-muted-foreground text-sm">Waiting for traffic data...</p>
          </div>
        )}
      </div>
    </div>
  );
}
