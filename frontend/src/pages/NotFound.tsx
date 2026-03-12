import { Link, useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Compass, ShieldAlert } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error("404 Error: User attempted to access non-existent route:", location.pathname);
  }, [location.pathname]);

  return (
    <div className="min-h-screen bg-background grid-pattern flex items-center justify-center p-6">
      <div className="cyber-card glow-border p-8 rounded-lg max-w-xl w-full text-center space-y-5">
        <div className="inline-flex items-center justify-center p-3 rounded-md bg-status-warning/10">
          <ShieldAlert className="w-10 h-10 text-status-warning" />
        </div>
        <div>
          <p className="text-xs uppercase tracking-[0.28em] text-muted-foreground mb-2">Route not found</p>
          <h1 className="mb-3 text-5xl font-semibold tracking-tight">404</h1>
          <p className="text-base text-muted-foreground">
            No route is registered for <span className="font-mono text-foreground/90">{location.pathname}</span>.
          </p>
        </div>
        <div className="flex justify-center">
          <Link to="/" className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-secondary hover:bg-accent transition-colors text-sm font-medium">
            <Compass className="w-4 h-4" />
            Return to dashboard
          </Link>
        </div>
      </div>
    </div>
  );
};

export default NotFound;
