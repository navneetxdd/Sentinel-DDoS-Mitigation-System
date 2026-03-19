import { Target, Clock, Shield } from "lucide-react";

const TARGET_DETECT_SEC = 20;
const TARGET_MITIGATE_SEC = 120;

export function SLOPanel() {
  return (
    <div className="rounded-md border border-border bg-card/50 px-3 py-2 text-xs">
      <div className="flex items-center gap-2 text-muted-foreground font-medium mb-1">
        <Target className="w-3.5 h-3.5" />
        Detection &amp; mitigation SLO
      </div>
      <ul className="space-y-0.5 text-muted-foreground">
        <li className="flex items-center gap-2">
          <Clock className="w-3 h-3 flex-shrink-0" />
          Target: &lt;{TARGET_DETECT_SEC}s to detect
        </li>
        <li className="flex items-center gap-2">
          <Shield className="w-3 h-3 flex-shrink-0" />
          Target: &lt;{TARGET_MITIGATE_SEC / 60}min to mitigate
        </li>
      </ul>
    </div>
  );
}
