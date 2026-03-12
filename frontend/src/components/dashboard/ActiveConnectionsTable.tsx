import { cn } from "@/lib/utils";
import type { SentinelConnection } from "@/hooks/useSentinelWebSocket";

interface ActiveConnectionsTableProps {
  className?: string;
  connections?: SentinelConnection[];
}

const protoName = (n: number) => {
  if (n === 6) return "TCP";
  if (n === 17) return "UDP";
  if (n === 1) return "ICMP";
  return `${n}`;
};

export function ActiveConnectionsTable({ className, connections = [] }: ActiveConnectionsTableProps) {
  return (
    <div className={cn("cyber-card glow-border p-5 rounded-lg", className)}>
      <div className="mb-4">
        <h3 className="font-semibold">Active Connections</h3>
        <p className="text-xs text-muted-foreground">Top flows by packet count</p>
      </div>
      <div className="overflow-x-auto max-h-48 overflow-y-auto">
        {connections.length > 0 ? (
          <table className="w-full text-sm" role="table" aria-label="Active connections">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Source</th>
                <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Destination</th>
                <th className="text-left text-xs font-medium text-muted-foreground py-2" scope="col">Proto</th>
                <th className="text-right text-xs font-medium text-muted-foreground py-2" scope="col">Packets</th>
                <th className="text-right text-xs font-medium text-muted-foreground py-2" scope="col">Bytes</th>
              </tr>
            </thead>
            <tbody>
              {connections.slice(0, 20).map((conn, idx) => (
                <tr key={idx} className="border-b border-border/50 hover:bg-secondary/30 transition-colors">
                  <td className="py-2 font-mono text-xs">{conn.src}</td>
                  <td className="py-2 font-mono text-xs">{conn.dst}</td>
                  <td className="py-2">{protoName(conn.proto)}</td>
                  <td className="py-2 font-mono text-right">{conn.packets.toLocaleString()}</td>
                  <td className="py-2 font-mono text-right">{conn.bytes.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-muted-foreground py-4">Waiting for connection data...</p>
        )}
      </div>
    </div>
  );
}
