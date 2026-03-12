const trimTrailingSlash = (value: string) => value.replace(/\/+$/, "");

const makeUnique = (values: string[]) => {
	const seen = new Set<string>();
	return values.filter((value) => {
		if (!value || seen.has(value)) return false;
		seen.add(value);
		return true;
	});
};

const browserHost = typeof window !== "undefined" ? window.location.hostname : "";
const httpProtocol = typeof window !== "undefined" && window.location.protocol === "https:" ? "https:" : "http:";
const wsProtocol = typeof window !== "undefined" && window.location.protocol === "https:" ? "wss:" : "ws:";

const explainApiUrl = import.meta.env.VITE_EXPLAIN_API_URL?.trim() ?? "";
const wsUrl = import.meta.env.VITE_WS_URL?.trim() ?? "";

export const EXPLAIN_API_CANDIDATES = makeUnique([
	explainApiUrl ? trimTrailingSlash(explainApiUrl) : "",
	browserHost ? `${httpProtocol}//${browserHost}:5001` : "",
	"http://localhost:5001",
	"http://127.0.0.1:5001",
]);

export const WS_URL_CANDIDATES = makeUnique([
	wsUrl,
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
			return await fetch(`${baseUrl}${normalizedPath}`, init);
		} catch (error) {
			lastError = error;
		}
	}

	throw lastError instanceof Error
		? lastError
		: new Error("Explain API is unreachable on all configured local endpoints.");
}
