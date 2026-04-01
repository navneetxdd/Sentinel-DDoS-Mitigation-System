import type { SentinelPacketEvent } from "@/hooks/useSentinelWebSocket";

interface PacketEvidenceTableProps {
  events: SentinelPacketEvent[];
}

function protocolLabel(proto: number): string {
  if (proto === 6) return "TCP";
  if (proto === 17) return "UDP";
  if (proto === 1) return "ICMP";
  if (proto === 58) return "ICMPv6";
  return `Proto ${proto}`;
}

export function PacketEvidenceTable({ events }: PacketEvidenceTableProps) {
  return (
    <div className="rounded-lg border border-border/50 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-muted/30">
            <tr>
              <th className="text-left px-3 py-2">Time</th>
              <th className="text-left px-3 py-2">Family</th>
              <th className="text-left px-3 py-2">Source</th>
              <th className="text-left px-3 py-2">Destination</th>
              <th className="text-left px-3 py-2">Protocol</th>
              <th className="text-left px-3 py-2">Length</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, idx) => (
              <tr key={`${event.timestamp}-${idx}`} className="border-t border-border/40">
                <td className="px-3 py-2">{new Date(event.timestamp * 1000).toLocaleTimeString()}</td>
                <td className="px-3 py-2">{event.ip_family}</td>
                <td className="px-3 py-2 font-mono">{`${event.src_ip}:${event.src_port}`}</td>
                <td className="px-3 py-2 font-mono">{`${event.dst_ip}:${event.dst_port}`}</td>
                <td className="px-3 py-2">{protocolLabel(event.protocol)}</td>
                <td className="px-3 py-2">{event.packet_len}</td>
              </tr>
            ))}
            {events.length === 0 && (
              <tr>
                <td className="px-3 py-4 text-muted-foreground" colSpan={6}>
                  Waiting for packet evidence stream...
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
