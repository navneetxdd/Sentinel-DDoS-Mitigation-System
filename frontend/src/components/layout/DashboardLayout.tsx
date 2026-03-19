import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Activity,
  Brain,
  Hexagon,
  LayoutDashboard,
  Menu,
  Settings,
  Shield,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { HealthSummaryBar } from "@/components/dashboard/HealthSummaryBar";

interface DashboardLayoutProps {
  children: React.ReactNode;
  connected?: boolean;
}

const navItems = [
  { path: "/", label: "Overview", icon: LayoutDashboard },
  { path: "/traffic", label: "Traffic Analysis", icon: Activity },
  { path: "/decision", label: "Decision Engine", icon: Brain },
  { path: "/mitigation", label: "Mitigation Control", icon: Shield },
  { path: "/settings", label: "Settings", icon: Settings },
];

export function DashboardLayout({ children, connected = false }: DashboardLayoutProps) {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);

  return (
    <div className="min-h-screen bg-background grid-pattern">
      <header className="lg:hidden fixed top-0 left-0 right-0 h-14 bg-card/95 backdrop-blur-sm border-b border-border z-50 flex items-center px-4">
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="p-2 hover:bg-secondary rounded-md transition-colors"
          aria-label="Toggle navigation"
        >
          {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
        <div className="flex items-center gap-2 ml-4">
          <Hexagon className="w-5 h-5 text-foreground" />
          <span className="font-semibold tracking-tight">Sentinel</span>
        </div>
      </header>

      <aside
        className={cn(
          "fixed left-0 top-0 h-full bg-sidebar border-r border-sidebar-border z-40 transition-all duration-200",
          sidebarOpen ? "w-56" : "w-0 lg:w-16",
          "lg:translate-x-0",
          !sidebarOpen && "-translate-x-full lg:translate-x-0",
        )}
      >
        <div className="flex flex-col h-full">
          <div className="h-14 flex items-center gap-3 px-4 border-b border-sidebar-border">
            <Hexagon className="w-6 h-6 text-foreground flex-shrink-0" />
            {sidebarOpen && (
              <div className="animate-fade-in">
                <h1 className="font-semibold tracking-tight">Sentinel</h1>
                <p className="text-[10px] text-muted-foreground uppercase tracking-wider">DDoS Defense</p>
              </div>
            )}
          </div>

          <nav className="flex-1 p-2 space-y-0.5">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2 rounded-md transition-colors duration-150",
                    isActive
                      ? "bg-accent text-foreground"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary",
                  )}
                >
                  <item.icon className="w-4 h-4 flex-shrink-0" />
                  {sidebarOpen && <span className="text-sm font-medium">{item.label}</span>}
                </Link>
              );
            })}
          </nav>

          {sidebarOpen && (
            <div className="p-3 border-t border-sidebar-border space-y-2">
              <div className="p-3 rounded-md bg-secondary/50">
                <div className="flex items-center gap-2 mb-1">
                  <div className={cn("w-1.5 h-1.5 rounded-full", connected ? "bg-status-success" : "bg-status-danger")} />
                  <span className="text-xs font-medium text-muted-foreground">
                    {connected ? "Pipeline online" : "Pipeline offline"}
                  </span>
                </div>
                <p className="text-[10px] text-muted-foreground">
                  {connected ? "Receiving live telemetry" : "Waiting for backend reconnect"}
                </p>
              </div>
              <HealthSummaryBar />
            </div>
          )}
        </div>
      </aside>

      <main
        className={cn(
          "transition-all duration-200 min-h-screen",
          sidebarOpen ? "lg:ml-56" : "lg:ml-16",
          "pt-14 lg:pt-0",
        )}
      >
        <div className="p-4 lg:p-6">{children}</div>
      </main>

      {sidebarOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-background/80 backdrop-blur-sm z-30"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
}
