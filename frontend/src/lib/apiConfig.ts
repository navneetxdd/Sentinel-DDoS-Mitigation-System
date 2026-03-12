const explainApiUrl = import.meta.env.VITE_EXPLAIN_API_URL?.trim() ?? "";

export const EXPLAIN_API_URL = explainApiUrl.replace(/\/+$/, "");
export const isExplainApiConfigured = EXPLAIN_API_URL.length > 0;
