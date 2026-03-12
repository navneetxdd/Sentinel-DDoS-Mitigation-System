import { useState } from "react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Plus, Trash2, Shield, Ban } from "lucide-react";
import { cn } from "@/lib/utils";
import { toast } from "@/hooks/use-toast";

interface IPListManagerProps {
  title: string;
  description?: string;
  items: string[];
  onAdd: (ip: string) => void;
  onRemove: (ip: string) => void;
  variant: "whitelist" | "blacklist";
}

export function IPListManager({
  title,
  description,
  items,
  onAdd,
  onRemove,
  variant,
}: IPListManagerProps) {
  const [newIP, setNewIP] = useState("");

  const isValidIP = (ip: string) => {
    const [addr, prefix] = ip.split("/");
    const octets = addr.split(".");
    if (octets.length !== 4) return false;
    const validOctets = octets.every((octet) => {
      if (!/^\d+$/.test(octet)) return false;
      const value = Number(octet);
      return value >= 0 && value <= 255;
    });
    if (!validOctets) return false;
    if (prefix === undefined) return true;
    if (!/^\d+$/.test(prefix)) return false;
    const prefixNum = Number(prefix);
    return prefixNum >= 0 && prefixNum <= 32;
  };

  const handleAdd = () => {
    if (!newIP.trim()) return;
    
    if (!isValidIP(newIP.trim())) {
      toast({
        title: "Invalid IP Format",
        description: "Please enter a valid IPv4 address or CIDR notation (e.g., 192.168.1.1 or 10.0.0.0/8)",
        variant: "destructive",
      });
      return;
    }

    if (items.includes(newIP.trim())) {
      toast({
        title: "Duplicate Entry",
        description: "This IP is already in the list",
        variant: "destructive",
      });
      return;
    }

    onAdd(newIP.trim());
    setNewIP("");
    toast({
      title: `Added to ${variant}`,
      description: `${newIP.trim()} has been added`,
    });
  };

  const isWhitelist = variant === "whitelist";

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        {isWhitelist ? (
          <Shield className="w-4 h-4 text-status-success" />
        ) : (
          <Ban className="w-4 h-4 text-status-danger" />
        )}
        <div>
          <h4 className="font-medium text-sm">{title}</h4>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
      </div>

      <div className="flex gap-2">
        <Input
          placeholder="Enter IP or CIDR (e.g., 192.168.1.1 or 10.0.0.0/8)"
          value={newIP}
          onChange={(e) => setNewIP(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleAdd()}
          className="flex-1 font-mono text-sm bg-secondary border-border"
        />
        <Button
          onClick={handleAdd}
          size="icon"
          className={cn(
            "shrink-0",
            isWhitelist
              ? "bg-status-success/10 text-status-success hover:bg-status-success/15 border border-status-success/20"
              : "bg-status-danger/10 text-status-danger hover:bg-status-danger/15 border border-status-danger/20"
          )}
        >
          <Plus className="w-4 h-4" />
        </Button>
      </div>

      <div className="max-h-48 overflow-y-auto space-y-2">
        {items.length === 0 ? (
          <p className="text-xs text-muted-foreground text-center py-4">
            No entries in {variant}
          </p>
        ) : (
          items.map((ip) => (
            <div
              key={ip}
              className={cn(
                "flex items-center justify-between px-3 py-2 rounded-md border",
                isWhitelist
                  ? "bg-status-success/5 border-status-success/20"
                  : "bg-status-danger/5 border-status-danger/20"
              )}
            >
              <span className="font-mono text-sm">{ip}</span>
              <button
                onClick={() => onRemove(ip)}
                className="p-1 hover:bg-destructive/20 rounded transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5 text-muted-foreground hover:text-destructive" />
              </button>
            </div>
          ))
        )}
      </div>

      <p className="text-xs text-muted-foreground">
        {items.length} {items.length === 1 ? "entry" : "entries"}
      </p>
    </div>
  );
}
