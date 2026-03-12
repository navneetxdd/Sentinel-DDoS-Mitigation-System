import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface SettingsCardProps {
  title: string;
  description?: string;
  icon?: LucideIcon;
  children: React.ReactNode;
  className?: string;
}

export function SettingsCard({ title, description, icon: Icon, children, className }: SettingsCardProps) {
  return (
    <div className={cn("cyber-card glow-border p-6 rounded-lg", className)}>
      <div className="flex items-start gap-3 mb-4">
        {Icon && (
          <div className="p-2 rounded-md bg-secondary">
            <Icon className="w-5 h-5 text-foreground" />
          </div>
        )}
        <div>
          <h3 className="font-semibold">{title}</h3>
          {description && (
            <p className="text-sm text-muted-foreground mt-0.5">{description}</p>
          )}
        </div>
      </div>
      <div className="space-y-4">
        {children}
      </div>
    </div>
  );
}
