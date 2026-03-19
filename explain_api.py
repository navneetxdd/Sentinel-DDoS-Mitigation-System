#!/usr/bin/env python3
"""
Sentinel DDoS Core - Off-path SHAP Explainability API

Optional HTTP service for per-feature SHAP contributions and Gemini threat analysis.
Runs independently of the C pipeline. Loads the joblib model from benchmarks/.

Usage:
  python explain_api.py [--port 5001] [--cors-origin http://localhost:5173]

Endpoints:
    POST /shap
        Body: {"samples": [[f1, f2, ..., f21], ...]}  # raw 21-feature vectors
    Returns: {"contributions": [[{name, value}, ...], ...], "base_value": float}

  POST /analyze
    Body: ThreatTelemetry JSON (timestamp, sourceIp, packetsPerSecond, ...)
    Returns: {"analysis": "..."}  (uses GEMINI_API_KEY env var)

  GET /health
    Returns: {"status": "ok", "model_loaded": bool}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sqlite3
import sys
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

try:
    import joblib
    import numpy as np
except ImportError:
    print("explain_api requires: pip install joblib numpy")
    sys.exit(1)

try:
    import shap
except ImportError:
    shap = None

NUM_FEATURES = 21
FEATURE_NAMES = [
    "packets_per_second",
    "bytes_per_second",
    "syn_ratio",
    "rst_ratio",
    "dst_port_entropy",
    "payload_byte_entropy",
    "unique_dst_ports",
    "avg_packet_size",
    "stddev_packet_size",
    "http_request_count",
    "fin_ratio",
    "src_port_entropy",
    "unique_src_ports",
    "avg_ttl",
    "stddev_ttl",
    "avg_iat_us",
    "stddev_iat_us",
    "src_total_flows",
    "src_packets_per_second",
    "dns_query_count",
    "chi_square_score",
]


def compute_feature_schema_hash(feature_names: List[str]) -> str:
    normalized = "|".join(str(name).strip().lower() for name in feature_names)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

# NOTE: These scaling constants MUST match the MinMax ranges used in train_ml.py.
# If train_ml.py is updated, update these values accordingly.
ML_MINMAX_LOW = np.zeros(NUM_FEATURES, dtype=np.float64)
ML_MINMAX_HIGH = np.array(
    [
        1e6, 1e9, 1.0, 1.0, 8.0, 8.0, 65535.0, 1500.0, 1000.0, 100.0,
        1.0, 8.0, 65535.0, 64.0, 16.0, 1e6, 1e6, 10000.0, 1e6, 1000.0,
        1.0,
    ],
    dtype=np.float64,
)
ML_MINMAX_RANGE = ML_MINMAX_HIGH - ML_MINMAX_LOW


def scale_features(X: np.ndarray) -> np.ndarray:
    feature_count = int(X.shape[1])
    low = ML_MINMAX_LOW[:feature_count]
    rng = ML_MINMAX_RANGE[:feature_count]
    scaled = np.asarray(X, dtype=np.float64).copy()
    np.subtract(scaled, low, out=scaled)
    np.divide(scaled, rng, out=scaled, where=rng > 0)
    np.clip(scaled, 0.0, 1.0, out=scaled)
    return scaled


class ExplainHandler(BaseHTTPRequestHandler):
    model: Optional[Dict[str, Any]] = None
    # TreeExplainer cached once at startup (set in main() after model load)
    _explainer: Optional[Any] = None
    _base_value: Optional[float] = None
    _cors_origin: str = "http://localhost:5173"
    _db_path: str = ""
    _db_lock: Lock = Lock()
    _api_key: str = ""
    _require_proxy_auth: bool = False
    _trusted_proxy_ips: set[str] = {"127.0.0.1", "::1"}
    _login_url: str = "/oauth2/start"
    _feature_names: List[str] = FEATURE_NAMES
    _feature_schema_hash: str = compute_feature_schema_hash(FEATURE_NAMES)
    _feature_count: int = NUM_FEATURES
    _trainer_version: str = "unknown"

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[explain_api] {args[0]}\n")

    def _json_response(self, status: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", ExplainHandler._cors_origin)
        self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    # Maximum accepted request body size (1 MiB). Prevents a trivial DoS via
    # a single HTTP request with an enormous Content-Length.
    _MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB

    def _parse_body(self) -> Optional[Dict[str, Any]]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return None
        raw = self.rfile.read(content_length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return None

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ExplainHandler._cors_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            loaded = ExplainHandler.model is not None and ExplainHandler._explainer is not None
            self._json_response(
                200,
                {
                    "status": "ok",
                    "model_loaded": loaded,
                    "shap_available": shap is not None,
                    "feature_count": ExplainHandler._feature_count,
                    "feature_schema_hash": ExplainHandler._feature_schema_hash,
                    "feature_names": ExplainHandler._feature_names,
                    "trainer_version": ExplainHandler._trainer_version,
                },
            )
            return
        if parsed.path == "/session":
            self._json_response(200, self._build_session_payload())
            return
        if parsed.path == "/events":
            if not self._ensure_authenticated_session():
                return
            self._handle_events_get(parsed)
            return
        self._json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        # Reject oversized bodies before routing — prevents memory DoS.
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > self._MAX_BODY_BYTES:
            self._json_response(413, {"error": "Request body too large (max 1 MiB)"})
            return

        parsed = urlparse(self.path)

        if parsed.path == "/analyze":
            if not self._ensure_authenticated_session():
                return
            self._handle_analyze()
            return

        if parsed.path == "/events":
            if not self._ensure_authenticated_session():
                return
            self._handle_events_post()
            return

        if parsed.path != "/shap":
            self._json_response(404, {"error": "Not found"})
            return

        if not self._ensure_authenticated_session():
            return

        if ExplainHandler.model is None:
            self._json_response(503, {"error": "Model not loaded. Run train_ml.py first."})
            return

        if shap is None:
            self._json_response(503, {"error": "SHAP not installed. pip install shap"})
            return

        if ExplainHandler._explainer is None:
            self._json_response(503, {"error": "SHAP explainer not initialized."})
            return

        body = self._parse_body()
        if body is None:
            self._json_response(400, {"error": "Invalid JSON body"})
            return

        samples = body.get("samples")
        if not isinstance(samples, list) or len(samples) == 0:
            self._json_response(400, {"error": "Expected non-empty 'samples' array of 21-feature vectors"})
            return

        request_schema_hash = str(body.get("feature_schema_hash") or "").strip()
        if request_schema_hash and request_schema_hash != ExplainHandler._feature_schema_hash:
            self._json_response(
                409,
                {
                    "error": "feature schema hash mismatch",
                    "expected_feature_schema_hash": ExplainHandler._feature_schema_hash,
                    "got_feature_schema_hash": request_schema_hash,
                },
            )
            return

        request_feature_count = body.get("feature_count")
        if isinstance(request_feature_count, int) and request_feature_count != ExplainHandler._feature_count:
            self._json_response(
                409,
                {
                    "error": "feature count mismatch",
                    "expected_feature_count": ExplainHandler._feature_count,
                    "got_feature_count": request_feature_count,
                },
            )
            return

        # Cap to 512 samples per request — prevents CPU/memory DoS via SHAP.
        MAX_SAMPLES = 512
        if len(samples) > MAX_SAMPLES:
            self._json_response(
                400,
                {"error": f"Too many samples (max {MAX_SAMPLES} per request)"},
            )
            return

        X = np.asarray(samples, dtype=np.float64)
        if X.ndim != 2:
            self._json_response(
                400,
                {"error": f"Each sample must have {NUM_FEATURES} features", "got": X.shape},
            )
            return

        # Compatibility: adapt between 20/21 features while enforcing model schema.
        expected_feature_count = ExplainHandler._feature_count
        if X.shape[1] == expected_feature_count:
            pass
        elif X.shape[1] == expected_feature_count - 1:
            X = np.pad(X, ((0, 0), (0, 1)), mode="constant", constant_values=0.0)
        elif X.shape[1] == expected_feature_count + 1:
            X = X[:, :expected_feature_count]
        elif expected_feature_count == NUM_FEATURES and X.shape[1] == NUM_FEATURES - 1:
            X = np.pad(X, ((0, 0), (0, 1)), mode="constant", constant_values=0.0)
        elif expected_feature_count == NUM_FEATURES - 1 and X.shape[1] == NUM_FEATURES:
            X = X[:, :expected_feature_count]
        else:
            self._json_response(
                400,
                {
                    "error": f"Each sample must have {expected_feature_count} features (or nearby compatible shape)",
                    "got": X.shape,
                },
            )
            return

        X_scaled = scale_features(X)

        try:
            shap_values = ExplainHandler._explainer.shap_values(X_scaled)
        except Exception as e:
            self._json_response(500, {"error": f"SHAP computation failed: {e}"})
            return

        if isinstance(shap_values, list):
            shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]

        feature_names = ExplainHandler._feature_names[: X_scaled.shape[1]]
        contributions: List[List[Dict[str, Any]]] = []
        for i in range(len(X_scaled)):
            row: List[Dict[str, Any]] = []
            for j in range(len(feature_names)):
                raw_val = float(shap_values[i, j]) if shap_values.ndim >= 2 else float(shap_values[i])
                # Guard against NaN/Inf which would break JSON serialization
                val = 0.0 if math.isnan(raw_val) or math.isinf(raw_val) else raw_val
                row.append({"name": feature_names[j], "value": val})
            contributions.append(row)

        self._json_response(
            200,
            {
                "contributions": contributions,
                "base_value": ExplainHandler._base_value,
                "num_samples": len(samples),
                "feature_schema_hash": ExplainHandler._feature_schema_hash,
                "feature_count": ExplainHandler._feature_count,
            },
        )

    # ------------------------------------------------------------------
    # Reverse-proxy auth helpers
    # ------------------------------------------------------------------

    def _client_ip(self) -> str:
        return self.client_address[0] if self.client_address else ""

    def _build_session_payload(self) -> Dict[str, Any]:
        if not ExplainHandler._require_proxy_auth:
            return {
                "required": False,
                "authenticated": True,
                "mode": "disabled",
                "user": None,
                "login_url": None,
            }

        if self._client_ip() not in ExplainHandler._trusted_proxy_ips:
            return {
                "required": True,
                "authenticated": False,
                "mode": "proxy-header",
                "reason": "untrusted-proxy",
                "user": None,
                "login_url": ExplainHandler._login_url,
            }

        username = (
            self.headers.get("X-Forwarded-User")
            or self.headers.get("X-Auth-Request-User")
            or self.headers.get("X-Forwarded-Preferred-Username")
            or ""
        ).strip()
        email = (
            self.headers.get("X-Forwarded-Email")
            or self.headers.get("X-Auth-Request-Email")
            or ""
        ).strip()
        groups_raw = (
            self.headers.get("X-Forwarded-Groups")
            or self.headers.get("X-Auth-Request-Groups")
            or ""
        ).strip()

        if not username and not email:
            return {
                "required": True,
                "authenticated": False,
                "mode": "proxy-header",
                "reason": "missing-identity-headers",
                "user": None,
                "login_url": ExplainHandler._login_url,
            }

        groups = [part.strip() for part in groups_raw.split(",") if part.strip()]
        return {
            "required": True,
            "authenticated": True,
            "mode": "proxy-header",
            "login_url": ExplainHandler._login_url,
            "user": {
                "username": username or email,
                "email": email or None,
                "groups": groups,
            },
        }

    def _ensure_authenticated_session(self) -> bool:
        # 1. Check for Sentinel API Key in headers (Mandatory if configured)
        if ExplainHandler._api_key:
            provided_key = self.headers.get("X-Sentinel-API-Key", "").strip()
            if not provided_key:
                # Fallback: check query parameters for browser-initiated GETs if needed
                parsed = urlparse(self.path)
                qs = parse_qs(parsed.query)
                provided_key = qs.get("api_key", [""])[0]

            if provided_key != ExplainHandler._api_key:
                self.log_message("[AUTH] Request failed: invalid or missing X-Sentinel-API-Key")
                self._json_response(401, {"error": "Unauthorized: Invalid X-Sentinel-API-Key required."})
                return False

        # 2. Check for Proxy Auth if enabled
        session = self._build_session_payload()
        if session.get("authenticated"):
            return True
        self._json_response(401, session)
        return False

    # ------------------------------------------------------------------
    # SQLite-backed event log
    # ------------------------------------------------------------------

    @classmethod
    def _init_db(cls, db_path: str) -> None:
        """Initialise the SQLite event log and cache the path on the class."""
        cls._db_path = db_path
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sentinel_events (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_ts  REAL    NOT NULL,
                    logged_at TEXT    NOT NULL,
                    payload   TEXT    NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_event_ts ON sentinel_events (event_ts DESC)"
            )
            conn.commit()
        print(f"[*] Event log database: {db_path}")

    def _handle_events_get(self, parsed: Any) -> None:
        """Return recent persisted activity events (newest-first)."""
        if not ExplainHandler._db_path:
            self._json_response(503, {"error": "Event database not initialised"})
            return
        qs = parse_qs(parsed.query)
        try:
            limit = min(int(qs.get("limit", ["200"])[0]), 1000)
        except (ValueError, IndexError):
            limit = 200
        with ExplainHandler._db_lock:
            try:
                with sqlite3.connect(ExplainHandler._db_path) as conn:
                    rows = conn.execute(
                        "SELECT payload FROM sentinel_events ORDER BY event_ts DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
            except sqlite3.Error as e:
                self._json_response(500, {"error": f"Database error: {e}"})
                return
        events: List[Any] = []
        for (payload_str,) in rows:
            try:
                events.append(json.loads(payload_str))
            except json.JSONDecodeError:
                pass
        self._json_response(200, {"events": events, "count": len(events)})

    def _handle_events_post(self) -> None:
        """Persist a SentinelActivity event sent by the frontend."""
        if not ExplainHandler._db_path:
            self._json_response(503, {"error": "Event database not initialised"})
            return
        body = self._parse_body()
        if body is None:
            self._json_response(400, {"error": "Invalid JSON body"})
            return
        event_ts = body.get("timestamp")
        if not isinstance(event_ts, (int, float)):
            self._json_response(
                400,
                {"error": "Missing or invalid 'timestamp' field (must be Unix epoch number)"},
            )
            return
        logged_at = datetime.now(timezone.utc).isoformat()
        payload_str = json.dumps(body)
        with ExplainHandler._db_lock:
            try:
                with sqlite3.connect(ExplainHandler._db_path) as conn:
                    conn.execute(
                        "INSERT INTO sentinel_events (event_ts, logged_at, payload) VALUES (?, ?, ?)",
                        (float(event_ts), logged_at, payload_str),
                    )
                    # Keep at most 10 000 events; prune oldest on every write.
                    conn.execute(
                        """
                        DELETE FROM sentinel_events WHERE id NOT IN (
                            SELECT id FROM sentinel_events ORDER BY event_ts DESC LIMIT 10000
                        )
                        """
                    )
                    conn.commit()
            except sqlite3.Error as e:
                self._json_response(500, {"error": f"Database error: {e}"})
                return
        self._json_response(201, {"status": "ok"})

    @staticmethod
    def _sanitize_str(value: Any, max_len: int = 80) -> str:
        """Return a safe, printable version of a telemetry string field.

        Strips newlines and control characters so a crafted sourceIp or
        topProtocol value cannot inject extra prompt lines or escape the
        structured telemetry block.
        """
        text = str(value) if value is not None else "N/A"
        # Strip control characters (including newlines/tabs)
        text = "".join(ch for ch in text if ch.isprintable())
        # Truncate to a safe length so no field can bloat the prompt
        return text[:max_len]

    @staticmethod
    def _sanitize_number(value: Any, default: float = 0.0) -> float:
        """Coerce a telemetry numeric field to float, rejecting non-finite values."""
        try:
            v = float(value)
            return v if math.isfinite(v) else default
        except (TypeError, ValueError):
            return default

    def _handle_analyze(self) -> None:
        """Proxy Gemini API call server-side to avoid exposing API key to the frontend."""
        body = self._parse_body()
        if body is None:
            self._json_response(400, {"error": "Invalid JSON body"})
            return

        api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        if not api_key:
            self._json_response(
                503,
                {"error": "Gemini API key not configured. Set GEMINI_API_KEY environment variable for /analyze."},
            )
            return

        # Sanitize all user-supplied fields before embedding them in the prompt
        # to prevent prompt injection via crafted telemetry values.
        ts         = self._sanitize_str(body.get("timestamp"), max_len=40)
        src_ip     = self._sanitize_str(body.get("sourceIp"), max_len=45)   # max IPv6 len
        pps        = self._sanitize_number(body.get("packetsPerSecond"))
        bps        = self._sanitize_number(body.get("bytesPerSecond"))
        score      = self._sanitize_number(body.get("threatScore"))
        flows      = self._sanitize_number(body.get("activeFlows"))
        protocol   = self._sanitize_str(body.get("topProtocol"), max_len=20)

        prompt = (
            "You are an expert Security Operations Center (SOC) AI Analyst. "
            "A DDoS mitigation system (Sentinel) has just detected an anomaly. "
            "Review the following real-time telemetry and write a concise, 2-3 sentence explanation "
            "of what is likely happening and why the system flagged it. Be direct and analytical.\n\n"
            "Telemetry Data:\n"
            f"- Timestamp: {ts}\n"
            f"- Attacker IP: {src_ip}\n"
            f"- Peak Packets/Sec: {pps:.0f}\n"
            f"- Peak Bytes/Sec: {bps:.0f}\n"
            f"- Threat Score: {score:.4f}\n"
            f"- Active Concurrent Flows: {flows:.0f}\n"
            f"- Dominant Protocol: {protocol}\n\n"
            "Provide only the analysis and conclusion without extra pleasantries."
        )

        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}]
        }).encode("utf-8")

        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"gemini-2.5-flash:generateContent?key={api_key}"
        )
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                result = json.loads(resp.read().decode("utf-8"))
            text = result["candidates"][0]["content"]["parts"][0]["text"]
            self._json_response(200, {"analysis": text})
        except Exception as e:
            self._json_response(200, {"analysis": f"AI Analysis temporarily unavailable: {e}"})


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel SHAP explainability API")
    parser.add_argument("--port", type=int, default=5001, help="Listen port")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Listen host")
    parser.add_argument("--model", type=str, default=None, help="Path to sentinel_model.joblib")
    parser.add_argument(
        "--cors-origin",
        type=str,
        default="http://localhost:5173",
        help="Allowed CORS origin (default: http://localhost:5173 for Vite dev server)",
    )
    args = parser.parse_args()

    ExplainHandler._cors_origin = args.cors_origin
    ExplainHandler._api_key = os.environ.get("SENTINEL_WS_API_KEY", "").strip()
    ExplainHandler._require_proxy_auth = os.environ.get("SENTINEL_REQUIRE_PROXY_AUTH", "0") in {"1", "true", "TRUE", "yes", "YES"}
    ExplainHandler._trusted_proxy_ips = {
        ip.strip() for ip in os.environ.get("SENTINEL_TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if ip.strip()
    } or {"127.0.0.1", "::1"}
    ExplainHandler._login_url = os.environ.get("SENTINEL_PROXY_LOGIN_URL", "/oauth2/start")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = args.model or os.path.join(script_dir, "benchmarks", "sentinel_model.joblib")

    if os.path.isfile(model_path):
        try:
            ExplainHandler.model = joblib.load(model_path)
            print(f"[*] Loaded model from {model_path}")
            if isinstance(ExplainHandler.model, dict):
                feature_names = ExplainHandler.model.get("feature_names")
                if isinstance(feature_names, list) and feature_names:
                    ExplainHandler._feature_names = [str(name) for name in feature_names]
                    ExplainHandler._feature_count = len(ExplainHandler._feature_names)
                else:
                    ExplainHandler._feature_names = list(FEATURE_NAMES)
                    ExplainHandler._feature_count = len(ExplainHandler._feature_names)

                metadata_hash = ExplainHandler.model.get("feature_schema_hash")
                if isinstance(metadata_hash, str) and metadata_hash.strip():
                    ExplainHandler._feature_schema_hash = metadata_hash.strip()
                else:
                    ExplainHandler._feature_schema_hash = compute_feature_schema_hash(ExplainHandler._feature_names)

                trainer_version = ExplainHandler.model.get("trainer_version")
                if isinstance(trainer_version, str) and trainer_version.strip():
                    ExplainHandler._trainer_version = trainer_version.strip()
        except Exception as e:
            print(f"[!] Failed to load model: {e}", file=sys.stderr)
    else:
        print(f"[!] Model not found: {model_path}", file=sys.stderr)
        print("[!] Run train_ml.py first to generate the model.", file=sys.stderr)

    # Cache the SHAP TreeExplainer once at startup (avoids expensive re-creation per request)
    if shap is None:
        print("[!] SHAP not installed. /shap endpoint will return 503.", file=sys.stderr)
        print("[!] pip install shap", file=sys.stderr)
    elif ExplainHandler.model is not None:
        try:
            estimator = ExplainHandler.model["estimator"]
            ExplainHandler._explainer = shap.TreeExplainer(estimator)
            base = ExplainHandler._explainer.expected_value
            if isinstance(base, (list, np.ndarray)):
                base = float(base[1]) if len(base) > 1 else float(base[0])
            ExplainHandler._base_value = float(base)
            print("[*] SHAP TreeExplainer cached at startup.")
        except Exception as e:
            print(f"[!] Failed to initialize SHAP explainer: {e}", file=sys.stderr)

    db_path = os.path.join(script_dir, "sentinel_events.db")
    ExplainHandler._init_db(db_path)

    if (args.host == "0.0.0.0" and not ExplainHandler._api_key and not ExplainHandler._require_proxy_auth):
        print("[!] WARNING: Listening on 0.0.0.0 with no API key and no proxy auth. Do not expose to the internet.")

    server = ThreadingHTTPServer((args.host, args.port), ExplainHandler)
    print(f"[*] Explain API listening on http://{args.host}:{args.port}")
    print(f"[*] CORS origin: {args.cors_origin}")
    print(f"[*] Proxy auth required: {ExplainHandler._require_proxy_auth}")
    print("[*] GET /health  GET /events  POST /shap  POST /analyze  POST /events")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()

