import { useEffect, useMemo, useState } from "react";
import { isAuthRequired, loginUrl, sessionApiUrl } from "@/lib/authConfig";
import { AuthSessionContext, defaultSession, type AuthSession } from "@/lib/authSessionContext";

export function AuthSessionProvider({ children }: { children: React.ReactNode }) {
  const [loading, setLoading] = useState(isAuthRequired);
  const [session, setSession] = useState<AuthSession>(defaultSession);

  useEffect(() => {
    const refresh = async () => {
      if (!isAuthRequired) {
        setSession(defaultSession);
        setLoading(false);
        return;
      }

      setLoading(true);
      try {
        const response = await fetch(sessionApiUrl, {
          credentials: "include",
          headers: { Accept: "application/json" },
        });
        const json = (await response.json()) as Partial<AuthSession>;
        setSession({
          required: Boolean(json.required ?? true),
          authenticated: Boolean(json.authenticated),
          mode: String(json.mode ?? "proxy-header"),
          reason: json.reason,
          login_url: json.login_url ?? loginUrl,
          user: json.user ?? null,
        });
      } catch {
        setSession({
          required: true,
          authenticated: false,
          mode: "proxy-header",
          reason: "session-endpoint-unreachable",
          login_url: loginUrl,
          user: null,
        });
      } finally {
        setLoading(false);
      }
    };

    void refresh();
  }, []);

  const refresh = async () => {
    if (!isAuthRequired) {
      setSession(defaultSession);
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const response = await fetch(sessionApiUrl, {
        credentials: "include",
        headers: { Accept: "application/json" },
      });
      const json = (await response.json()) as Partial<AuthSession>;
      setSession({
        required: Boolean(json.required ?? true),
        authenticated: Boolean(json.authenticated),
        mode: String(json.mode ?? "proxy-header"),
        reason: json.reason,
        login_url: json.login_url ?? loginUrl,
        user: json.user ?? null,
      });
    } catch {
      setSession({
        required: true,
        authenticated: false,
        mode: "proxy-header",
        reason: "session-endpoint-unreachable",
        login_url: loginUrl,
        user: null,
      });
    } finally {
      setLoading(false);
    }
  };

  const value = useMemo(() => ({ loading, session, refresh }), [loading, session]);

  return <AuthSessionContext.Provider value={value}>{children}</AuthSessionContext.Provider>;
}