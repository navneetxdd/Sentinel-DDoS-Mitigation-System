import { createContext } from "react";

export type AuthUser = {
  username?: string | null;
  email?: string | null;
  groups?: string[];
};

export type AuthSession = {
  required: boolean;
  authenticated: boolean;
  mode: string;
  reason?: string;
  login_url?: string | null;
  user?: AuthUser | null;
};

export type AuthContextValue = {
  loading: boolean;
  session: AuthSession;
  refresh: () => Promise<void>;
};

export const defaultSession: AuthSession = {
  required: false,
  authenticated: true,
  mode: "disabled",
  user: null,
  login_url: null,
};

export const AuthSessionContext = createContext<AuthContextValue | null>(null);