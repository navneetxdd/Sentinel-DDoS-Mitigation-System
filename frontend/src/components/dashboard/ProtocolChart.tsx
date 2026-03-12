import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { cn } from "@/lib/utils";
import type { SentinelProtocolDist } from "@/hooks/useSentinelWebSocket";

interface ProtocolChartProps {
  className?: string;
  isAttack?: boolean;
  data?: SentinelProtocolDist | null;
}

interface ProtocolChartDatum {
  protocol: string;
  count: number;
  color: string;
}

interface ProtocolTooltipProps {
  active?: boolean;
  payload?: Array<{ payload: ProtocolChartDatum; value: number }>;
  label?: string;
}

/* Same color mapping as original */
const COLORS = {
  TCP: "hsl(0, 0%, 72%)",
  UDP: "hsl(142, 50%, 45%)",
  ICMP: "hsl(0, 62%, 50%)",
  Other: "hsl(38, 90%, 50%)",
};

export function ProtocolChart({ className, isAttack = false, data }: ProtocolChartProps) {
  /* Build chart data from real backend protocol_distribution stream */
  const chartData: ProtocolChartDatum[] = data
    ? [
        { protocol: "TCP", count: data.tcp_bytes, color: COLORS.TCP },
        { protocol: "UDP", count: data.udp_bytes, color: COLORS.UDP },
        { protocol: "ICMP", count: data.icmp_bytes, color: isAttack ? "hsl(0, 62%, 50%)" : COLORS.ICMP },
        { protocol: "Other", count: data.other_bytes, color: COLORS.Other },
      ]
    : [];

  const CustomTooltip = ({ active, payload, label }: ProtocolTooltipProps) => {
    if (active && payload && payload.length) {
      return (
        <div className="chart-tooltip">
          <p className="text-xs text-muted-foreground mb-1">{label}</p>
          <p className="font-mono font-bold" style={{ color: payload[0].payload.color }}>
            {payload[0].value.toLocaleString()} requests
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <div className="mb-4">
        <h3 className="font-semibold">Protocol Distribution</h3>
        <p className="text-xs text-muted-foreground">Request count by protocol</p>
      </div>

      <div className="h-64">
        {chartData.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} layout="vertical">
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="hsl(var(--border))"
                horizontal={false}
              />
              <XAxis
                type="number"
                tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 10 }}
                axisLine={{ stroke: "hsl(var(--border))" }}
                tickLine={false}
                tickFormatter={(val) => `${(val / 1000).toFixed(0)}k`}
              />
              <YAxis
                type="category"
                dataKey="protocol"
                tick={{ fill: "hsl(var(--muted-foreground))", fontSize: 11 }}
                axisLine={{ stroke: "hsl(var(--border))" }}
                tickLine={false}
                width={50}
              />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: "hsl(var(--muted) / 0.3)" }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {chartData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="flex items-center justify-center h-full">
            <p className="text-muted-foreground text-sm">Waiting for protocol data...</p>
          </div>
        )}
      </div>
    </div>
  );
}
