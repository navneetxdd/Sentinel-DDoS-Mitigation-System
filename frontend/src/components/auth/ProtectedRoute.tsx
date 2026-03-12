import { Lock, RefreshCw, ShieldCheck } from "lucide-react";
import { useAuthSession } from "@/hooks/useAuthSession";
import { Button } from "@/components/ui/button";

export function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { loading, session, refresh } = useAuthSession();

  if (loading) {
    return (
      <div className="min-h-screen bg-background grid-pattern flex items-center justify-center p-6">
        <div className="cyber-card glow-border p-8 rounded-lg max-w-lg w-full text-center space-y-4">
          <RefreshCw className="w-10 h-10 mx-auto text-foreground/70 animate-spin" />
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Validating session</h1>
            <p className="text-sm text-muted-foreground mt-1">Checking reverse-proxy authentication headers.</p>
          </div>
        </div>
      </div>
    );
  }

  if (!session.authenticated) {
    return (
      <div className="min-h-screen bg-background grid-pattern flex items-center justify-center p-6">
        <div className="cyber-card glow-border p-8 rounded-lg max-w-xl w-full text-center space-y-5">
          <div className="p-3 rounded-md bg-status-danger/10 inline-flex mx-auto">
            <Lock className="w-8 h-8 text-status-danger" />
          </div>
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Authentication Required</h1>
            <p className="text-sm text-muted-foreground mt-2">
              This deployment is protected by reverse-proxy OIDC. Sign in through the configured identity provider to continue.
            </p>
            {session.reason ? (
              <p className="text-xs text-muted-foreground mt-3 font-mono">Reason: {session.reason}</p>
            ) : null}
          </div>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Button asChild>
              <a href={session.login_url || "/oauth2/start"}>Sign in</a>
            </Button>
            <Button variant="outline" onClick={() => void refresh()}>
              Retry session check
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <>
      {session.user?.email ? (
        <div className="sr-only" aria-label={`Authenticated as ${session.user.email}`}>
          <ShieldCheck className="w-4 h-4" />
        </div>
      ) : null}
      {children}
    </>
  );
}
