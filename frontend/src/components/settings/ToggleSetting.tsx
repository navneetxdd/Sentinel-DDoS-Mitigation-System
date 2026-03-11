import { Switch } from "@/components/ui/switch";
import { cn } from "@/lib/utils";

interface ToggleSettingProps {
  label: string;
  description?: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  variant?: "default" | "success" | "warning" | "danger";
}

export function ToggleSetting({
  label,
  description,
  checked,
  onCheckedChange,
  variant = "default",
}: ToggleSettingProps) {
  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex-1">
        <p className="text-sm font-medium">{label}</p>
        {description && (
          <p className="text-xs text-muted-foreground">{description}</p>
        )}
      </div>
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
        className={cn(
          checked && variant === "success" && "data-[state=checked]:bg-cyber-green",
          checked && variant === "warning" && "data-[state=checked]:bg-cyber-yellow",
          checked && variant === "danger" && "data-[state=checked]:bg-cyber-red"
        )}
      />
    </div>
  );
}
