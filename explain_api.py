#!/usr/bin/env python3
"""
Sentinel DDoS Core - Off-path SHAP Explainability API

Optional HTTP service for per-feature SHAP contributions.
Runs independently of the C pipeline. Loads the joblib model from benchmarks/.

Usage:
  python explain_api.py [--port 5001]

Endpoints:
  POST /shap
    Body: {"samples": [[f1, f2, ..., f20], ...]}  # raw 20-feature vectors
    Returns: {"contributions": [[{name, value}, ...], ...], "base_value": float}

  GET /health
    Returns: {"status": "ok", "model_loaded": bool}
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
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
    explainer: Optional[Any] = None

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write(f"[explain_api] {args[0]}\n")

    def _json_response(self, status: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            loaded = ExplainHandler.model is not None and ExplainHandler.explainer is not None
            self._json_response(200, {"status": "ok", "model_loaded": loaded, "shap_available": shap is not None})
            return
        self._json_response(404, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/shap":
            self._json_response(404, {"error": "Not found"})
            return

        if ExplainHandler.model is None:
            self._json_response(503, {"error": "Model not loaded. Run train_ml.py first."})
            return

        if shap is None:
            self._json_response(503, {"error": "SHAP not installed. pip install shap"})
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
        estimator = ExplainHandler.model["estimator"]

        try:
            if hasattr(estimator, "tree_") or (
                hasattr(estimator, "estimators_") and len(estimator.estimators_) > 0
            ):
                explainer = shap.TreeExplainer(estimator)
            else:
                explainer = shap.Explainer(estimator, X_scaled[: min(100, len(X_scaled))])
            shap_values = explainer.shap_values(X_scaled)
        except Exception as e:
            self._json_response(500, {"error": f"SHAP computation failed: {e}"})
            return

        if isinstance(shap_values, list):
            shap_values = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        base_value = float(explainer.expected_value)
        if isinstance(base_value, (list, np.ndarray)):
            base_value = float(base_value[1]) if len(base_value) > 1 else float(base_value[0])

        contributions: List[List[Dict[str, Any]]] = []
        for i in range(len(X_scaled)):
            row: List[Dict[str, Any]] = []
            for j in range(NUM_FEATURES):
                val = float(shap_values[i, j]) if shap_values.ndim >= 2 else float(shap_values[i])
                row.append({"name": FEATURE_NAMES[j], "value": val})
            contributions.append(row)

        self._json_response(
            200,
            {
                "contributions": contributions,
                "base_value": base_value,
                "num_samples": len(samples),
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel SHAP explainability API")
    parser.add_argument("--port", type=int, default=5001, help="Listen port")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Listen host")
    parser.add_argument("--model", type=str, default=None, help="Path to sentinel_model.joblib")
    args = parser.parse_args()

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

    if shap is None:
        print("[!] SHAP not installed. /shap endpoint will return 503.", file=sys.stderr)
        print("[!] pip install shap", file=sys.stderr)

    server = HTTPServer((args.host, args.port), ExplainHandler)
    print(f"[*] Explain API listening on http://{args.host}:{args.port}")
    print("[*] GET /health  POST /shap (body: {\"samples\": [[...20 floats...], ...]})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
