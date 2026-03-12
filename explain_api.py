#!/usr/bin/env python3
"""
Sentinel DDoS Core - Off-path SHAP Explainability API

Optional HTTP service for per-feature SHAP contributions and Gemini threat analysis.
Runs independently of the C pipeline. Loads the joblib model from benchmarks/.

Usage:
  python explain_api.py [--port 5001] [--cors-origin http://localhost:5173]

Endpoints:
  POST /shap
    Body: {"samples": [[f1, f2, ..., f20], ...]}  # raw 20-feature vectors
    Returns: {"contributions": [[{name, value}, ...], ...], "base_value": float}

  POST /analyze
    Body: ThreatTelemetry JSON (timestamp, sourceIp, packetsPerSecond, ...)
    Returns: {"analysis": "..."}  (uses GEMINI_API_KEY env var)

  GET /health
    Returns: {"status": "ok", "model_loaded": bool}
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

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

NUM_FEATURES = 20
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
]

# NOTE: These scaling constants MUST match the MinMax ranges used in train_ml.py.
# If train_ml.py is updated, update these values accordingly.
ML_MINMAX_LOW = np.zeros(NUM_FEATURES, dtype=np.float64)
ML_MINMAX_HIGH = np.array(
    [
        1e6, 1e9, 1.0, 1.0, 8.0, 8.0, 65535.0, 1500.0, 1000.0, 100.0,
        1.0, 8.0, 65535.0, 64.0, 16.0, 1e6, 1e6, 10000.0, 1e6, 1000.0,
    ],
    dtype=np.float64,
)
ML_MINMAX_RANGE = ML_MINMAX_HIGH - ML_MINMAX_LOW


def scale_features(X: np.ndarray) -> np.ndarray:
    scaled = np.asarray(X, dtype=np.float64).copy()
    np.subtract(scaled, ML_MINMAX_LOW, out=scaled)
    np.divide(scaled, ML_MINMAX_RANGE, out=scaled, where=ML_MINMAX_RANGE > 0)
    np.clip(scaled, 0.0, 1.0, out=scaled)
    return scaled


class ExplainHandler(BaseHTTPRequestHandler):
    model: Optional[Dict[str, Any]] = None
    # TreeExplainer cached once at startup (set in main() after model load)
    _explainer: Optional[Any] = None
    _base_value: Optional[float] = None
    _cors_origin: str = "http://localhost:5173"

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[explain_api] {args[0]}\n")

    def _json_response(self, status: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", ExplainHandler._cors_origin)
        self.end_headers()
        self.wfile.write(body)

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
            self._json_response(200, {"status": "ok", "model_loaded": loaded, "shap_available": shap is not None})
            return
        self._json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/analyze":
            self._handle_analyze()
            return

        if parsed.path != "/shap":
            self._json_response(404, {"error": "Not found"})
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
            self._json_response(400, {"error": "Expected non-empty 'samples' array of 20-feature vectors"})
            return

        X = np.asarray(samples, dtype=np.float64)
        if X.ndim != 2 or X.shape[1] != NUM_FEATURES:
            self._json_response(
                400,
                {"error": f"Each sample must have {NUM_FEATURES} features", "got": X.shape},
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

        contributions: List[List[Dict[str, Any]]] = []
        for i in range(len(X_scaled)):
            row: List[Dict[str, Any]] = []
            for j in range(NUM_FEATURES):
                raw_val = float(shap_values[i, j]) if shap_values.ndim >= 2 else float(shap_values[i])
                # Guard against NaN/Inf which would break JSON serialization
                val = 0.0 if math.isnan(raw_val) or math.isinf(raw_val) else raw_val
                row.append({"name": FEATURE_NAMES[j], "value": val})
            contributions.append(row)

        self._json_response(
            200,
            {
                "contributions": contributions,
                "base_value": ExplainHandler._base_value,
                "num_samples": len(samples),
            },
        )

    def _handle_analyze(self) -> None:
        """Proxy Gemini API call server-side to avoid exposing API key to the frontend."""
        body = self._parse_body()
        if body is None:
            self._json_response(400, {"error": "Invalid JSON body"})
            return

        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key:
            self._json_response(
                200,
                {"analysis": "Gemini API key not configured. Set GEMINI_API_KEY environment variable."},
            )
            return

        prompt = (
            "You are an expert Security Operations Center (SOC) AI Analyst. "
            "A DDoS mitigation system (Sentinel) has just detected an anomaly. "
            "Review the following real-time telemetry and write a concise, 2-3 sentence explanation "
            "of what is likely happening and why the system flagged it. Be direct and analytical.\n\n"
            f"Telemetry Data:\n"
            f"- Timestamp: {body.get('timestamp', 'N/A')}\n"
            f"- Attacker IP: {body.get('sourceIp', 'N/A')}\n"
            f"- Peak Packets/Sec: {body.get('packetsPerSecond', 0)}\n"
            f"- Peak Bytes/Sec: {body.get('bytesPerSecond', 0)}\n"
            f"- Threat Score: {body.get('threatScore', 0)}\n"
            f"- Active Concurrent Flows: {body.get('activeFlows', 0)}\n"
            f"- Dominant Protocol: {body.get('topProtocol', 'Unknown')}\n\n"
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

    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = args.model or os.path.join(script_dir, "benchmarks", "sentinel_model.joblib")

    if os.path.isfile(model_path):
        try:
            ExplainHandler.model = joblib.load(model_path)
            print(f"[*] Loaded model from {model_path}")
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

    server = ThreadingHTTPServer((args.host, args.port), ExplainHandler)
    print(f"[*] Explain API listening on http://{args.host}:{args.port}")
    print(f"[*] CORS origin: {args.cors_origin}")
    print("[*] GET /health  POST /shap  POST /analyze")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()

