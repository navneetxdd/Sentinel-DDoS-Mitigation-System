const trimTrailingSlash = (value: string) => value.replace(/\/+$/, "");

const makeUnique = (values: string[]) => {
	const seen = new Set<string>();
	return values.filter((value) => {
		if (!value || seen.has(value)) return false;
		seen.add(value);
		return true;
	});
};

const browserLocation = typeof window !== "undefined" ? window.location : null;
const browserHost = browserLocation?.hostname ?? "";
const browserHostWithPort = browserLocation?.host ?? "";
const browserOrigin = browserLocation?.origin ?? "";
const browserPort = browserLocation?.port ?? "";
const httpProtocol = browserLocation?.protocol === "https:" ? "https:" : "http:";
const wsProtocol = browserLocation?.protocol === "https:" ? "wss:" : "ws:";
const numericBrowserPort = browserPort ? Number(browserPort) : NaN;
const isDirectFrontendDevPort =
	Number.isFinite(numericBrowserPort) &&
	(numericBrowserPort === 5173 || (numericBrowserPort >= 5200 && numericBrowserPort <= 5220));

const explainApiUrl = import.meta.env.VITE_EXPLAIN_API_URL?.trim() ?? "";
const wsUrl = import.meta.env.VITE_WS_URL?.trim() ?? "";
export const WS_API_KEY = import.meta.env.VITE_WS_API_KEY?.trim() ?? "";
const sameOriginExplainApiUrl = browserOrigin ? `${trimTrailingSlash(browserOrigin)}/api` : "";
const sameOriginWsUrl = browserHostWithPort ? `${wsProtocol}//${browserHostWithPort}/ws` : "";

export const EXPLAIN_API_CANDIDATES = makeUnique([
	explainApiUrl ? trimTrailingSlash(explainApiUrl) : "",
	!isDirectFrontendDevPort ? sameOriginExplainApiUrl : "",
	browserHost ? `${httpProtocol}//${browserHost}:5001` : "",
	"http://localhost:5001",
	"http://127.0.0.1:5001",
]);

export const WS_URL_CANDIDATES = makeUnique([
	wsUrl,
	!isDirectFrontendDevPort ? sameOriginWsUrl : "",
	browserHost ? `${wsProtocol}//${browserHost}:8765` : "",
	"ws://localhost:8765",
	"ws://127.0.0.1:8765",
]);

export const EXPLAIN_API_URL = EXPLAIN_API_CANDIDATES[0] ?? "";
export const isExplainApiConfigured = EXPLAIN_API_CANDIDATES.length > 0;

export async function fetchExplainApi(path: string, init?: RequestInit): Promise<Response> {
	const normalizedPath = path.startsWith("/") ? path : `/${path}`;
	let lastError: unknown = null;

	for (const baseUrl of EXPLAIN_API_CANDIDATES) {
		try {
			const headers = new Headers(init?.headers);
			if (WS_API_KEY) {
				headers.set("X-Sentinel-API-Key", WS_API_KEY);
			}
			return await fetch(`${baseUrl}${normalizedPath}`, { ...init, headers });
		} catch (error) {
			lastError = error;
		}
	}

	throw lastError instanceof Error
		? lastError
		: new Error("Explain API is unreachable on all configured local endpoints.");
}
