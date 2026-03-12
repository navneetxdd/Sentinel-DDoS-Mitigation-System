import { Slider } from "@/components/ui/slider";
import { cn } from "@/lib/utils";

interface SliderSettingProps {
  label: string;
  value: number;
  onChange: (value: number) => void;
  min?: number;
  max?: number;
  step?: number;
  unit?: string;
  description?: string;
  variant?: "default" | "warning" | "danger";
}

export function SliderSetting({
  label,
  value,
  onChange,
  min = 0,
  max = 100,
  step = 1,
  unit = "",
  description,
  variant = "default",
}: SliderSettingProps) {
  const getValueColor = () => {
    if (variant === "danger") return "text-cyber-red";
    if (variant === "warning") return "text-cyber-yellow";
    return "text-primary";
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium">{label}</p>
          {description && (
            <p className="text-xs text-muted-foreground">{description}</p>
          )}
        </div>
        <span className={cn("font-mono font-bold text-lg", getValueColor())}>
          {value}{unit}
        </span>
      </div>
      <Slider
        value={[value]}
        onValueChange={([v]) => onChange(v)}
        min={min}
        max={max}
        step={step}
        className="w-full"
      />
      <div className="flex justify-between text-xs text-muted-foreground">
        <span>{min}{unit}</span>
        <span>{max}{unit}</span>
      </div>
    </div>
  );
}
