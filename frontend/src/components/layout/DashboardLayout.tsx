import { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Activity,
  Brain,
  Shield,
  Menu,
  X,
  Hexagon,
  Settings
} from "lucide-react";
import { cn } from "@/lib/utils";

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
      {/* Mobile Header */}
      <header className="lg:hidden fixed top-0 left-0 right-0 h-16 bg-card/95 backdrop-blur-sm border-b border-border z-50 flex items-center px-4">
        <button
          onClick={() => setSidebarOpen(!sidebarOpen)}
          className="p-2 hover:bg-secondary rounded-lg transition-colors"
        >
          {sidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
        <div className="flex items-center gap-2 ml-4">
          <Hexagon className="w-6 h-6 text-primary" />
          <span className="font-bold text-lg tracking-tight">BAW2M</span>
        </div>
      </header>

      {/* Sidebar */}
      <aside
        className={cn(
          "fixed left-0 top-0 h-full bg-sidebar border-r border-sidebar-border z-40 transition-all duration-300",
          sidebarOpen ? "w-64" : "w-0 lg:w-20",
          "lg:translate-x-0",
          !sidebarOpen && "-translate-x-full lg:translate-x-0"
        )}
      >
        <div className="flex flex-col h-full">
          {/* Logo */}
          <div className="h-16 flex items-center gap-3 px-4 border-b border-sidebar-border">
            <div className="relative">
              <Hexagon className="w-8 h-8 text-primary" />
              <div className="absolute inset-0 w-8 h-8 text-primary blur-sm opacity-50">
                <Hexagon className="w-8 h-8" />
              </div>
            </div>
            {sidebarOpen && (
              <div className="animate-fade-in">
                <h1 className="font-bold text-lg tracking-tight neon-text">BAW2M</h1>
                <p className="text-[10px] text-muted-foreground uppercase tracking-widest">DDoS Defense</p>
              </div>
            )}
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-3 space-y-1">
            {navItems.map((item) => {
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={cn(
                    "flex items-center gap-3 px-3 py-2.5 rounded-lg transition-all duration-200 group",
                    isActive
                      ? "bg-primary/10 text-primary border border-primary/20"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                  )}
                >
                  <item.icon className={cn(
                    "w-5 h-5 flex-shrink-0 transition-colors",
                    isActive && "drop-shadow-[0_0_8px_hsl(var(--primary))]"
                  )} />
                  {sidebarOpen && (
                    <span className="font-medium text-sm">{item.label}</span>
                  )}
                  {isActive && sidebarOpen && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-primary animate-pulse-glow" />
                  )}
                </Link>
              );
            })}
          </nav>

          {/* System Status — shows live WebSocket connection state */}
          {sidebarOpen && (
            <div className="p-4 border-t border-sidebar-border">
              <div className="cyber-card p-3 rounded-lg">
                <div className="flex items-center gap-2 mb-2">
                  <div className={cn(
                    "w-2 h-2 rounded-full animate-pulse-glow",
                    connected ? "bg-cyber-green" : "bg-cyber-red"
                  )} />
                  <span className={cn(
                    "text-xs font-medium",
                    connected ? "text-cyber-green" : "text-cyber-red"
                  )}>
                    {connected ? "Pipeline Connected" : "Pipeline Disconnected"}
                  </span>
                </div>
                <p className="text-[10px] text-muted-foreground">
                  {connected ? "Receiving live data" : "Attempting reconnection..."}
                </p>
              </div>
            </div>
          )}
        </div>
      </aside>

      {/* Main Content */}
      <main
        className={cn(
          "transition-all duration-300 min-h-screen",
          sidebarOpen ? "lg:ml-64" : "lg:ml-20",
          "pt-16 lg:pt-0"
        )}
      >
        <div className="p-4 lg:p-6">
          {children}
        </div>
      </main>

      {/* Mobile Overlay */}
      {sidebarOpen && (
        <div
          className="lg:hidden fixed inset-0 bg-background/80 backdrop-blur-sm z-30"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
}
