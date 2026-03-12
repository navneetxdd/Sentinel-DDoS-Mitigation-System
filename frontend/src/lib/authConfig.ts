import { EXPLAIN_API_URL } from "@/lib/apiConfig";

const rawRequireAuth = import.meta.env.VITE_REQUIRE_AUTH?.trim().toLowerCase() ?? "false";
const rawLoginUrl = import.meta.env.VITE_LOGIN_URL?.trim() ?? "/oauth2/start";
const rawSessionUrl = import.meta.env.VITE_AUTH_SESSION_URL?.trim() ?? "";

export const isAuthRequired = rawRequireAuth === "true" || rawRequireAuth === "1" || rawRequireAuth === "yes";
export const loginUrl = rawLoginUrl;
export const sessionApiUrl = rawSessionUrl
  ? rawSessionUrl.replace(/\/+$/, "")
  : EXPLAIN_API_URL
    ? `${EXPLAIN_API_URL}/session`
    : "/session";
