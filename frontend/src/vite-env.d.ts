/// <reference types="vite/client" />

interface ImportMetaEnv {
	readonly VITE_EXPLAIN_API_URL?: string;
	readonly VITE_WS_URL?: string;
	readonly VITE_REQUIRE_AUTH?: string;
	readonly VITE_AUTH_SESSION_URL?: string;
	readonly VITE_LOGIN_URL?: string;
}

interface ImportMeta {
	readonly env: ImportMetaEnv;
}
