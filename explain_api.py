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

Environment:
  SENTINEL_SQLCIPHER_PASSPHRASE   Optional. Full-file SQLCipher encryption for sentinel_events.db (pip install sqlcipher3).
  SENTINEL_SQLCIPHER_AUTO_MIGRATE Optional. Default 1. If 1 and passphrase is set, plain SQLite at startup is backed up and migrated in-place.
                                  Manual one-off: python scripts/migrate_sentinel_events_to_sqlcipher.py --help
  SENTINEL_EVENTS_ENCRYPTION_KEY  Optional. Fernet key for payload column only; ignored when SQLCipher is enabled.
  SENTINEL_EVENT_RETENTION_LIMIT  Max rows (default 10000).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import ipaddress
import json
import math
import os
import shutil
import sqlite3
import sys
import time
from contextlib import contextmanager
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Any, Dict, List, Optional, cast
from urllib.parse import parse_qs, urlparse

# Fernet-encrypted JSON payloads in sentinel_events.payload when SENTINEL_EVENTS_ENCRYPTION_KEY is set.
EVENT_PAYLOAD_ENC_PREFIX = "sentinel_enc:v1:"


def _sqlcipher_enabled() -> bool:
    return bool(os.environ.get("SENTINEL_SQLCIPHER_PASSPHRASE", "").strip())


@contextmanager
def _db_connect(db_path: str):
    """Open SQLite or SQLCipher (full-file encryption) depending on SENTINEL_SQLCIPHER_PASSPHRASE."""
    passphrase = os.environ.get("SENTINEL_SQLCIPHER_PASSPHRASE", "").strip()
    if passphrase:
        try:
            import sqlcipher3.dbapi2 as sc
        except ImportError:
            print(
                "[FATAL] SENTINEL_SQLCIPHER_PASSPHRASE is set but sqlcipher3 is not installed. "
                "pip install sqlcipher3 (requires SQLCipher development libraries on the host).",
                file=sys.stderr,
            )
            sys.exit(1)
        conn = sc.connect(db_path, check_same_thread=False, timeout=30.0)
        esc = passphrase.replace("'", "''")
        conn.execute(f"PRAGMA key = '{esc}'")
        try:
            yield conn
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        try:
            yield conn
        finally:
            conn.close()


def _fernet_from_env() -> Optional[Any]:
    if _sqlcipher_enabled():
        return None
    key = os.environ.get("SENTINEL_EVENTS_ENCRYPTION_KEY", "").strip()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet

        return Fernet(key.encode("utf-8"))
    except Exception as e:
        print(
            f"[FATAL] SENTINEL_EVENTS_ENCRYPTION_KEY must be a valid Fernet key: {e}",
            file=sys.stderr,
        )
        sys.exit(1)


def _encrypt_event_payload(fernet: Optional[Any], payload: str) -> str:
    if _sqlcipher_enabled():
        return payload
    if fernet is None:
        return payload
    return EVENT_PAYLOAD_ENC_PREFIX + fernet.encrypt(payload.encode("utf-8")).decode("ascii")


def _decrypt_event_payload(fernet: Optional[Any], stored: str) -> Optional[str]:
    if not stored.startswith(EVENT_PAYLOAD_ENC_PREFIX):
        return stored
    if fernet is None:
        return None
    try:
        return fernet.decrypt(stored[len(EVENT_PAYLOAD_ENC_PREFIX) :].encode("ascii")).decode("utf-8")
    except Exception:
        return None


def _ipv4_overlay_context_hint(src_ip: str) -> str:
    """Tailscale / CGNAT context for Gemini (reduces bogus 'external threat actor' narratives)."""
    s = src_ip.strip()
    if not s or s.lower() == "unknown":
        return ""
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return ""
    if ip.version != 4:
        return ""
    if ip in ipaddress.ip_network("100.64.0.0/10", strict=False):
        return (
            "IPv4 sits in 100.64.0.0/10 (RFC 6598 shared CGNAT). Common for carrier NAT or overlay meshes; "
            "not a public routable endpoint by itself."
        )
    parts = str(ip).split(".")
    if len(parts) == 4 and parts[0] == "100":
        return (
            "IPv4 is in 100.0.0.0/8; Tailscale and similar overlays often use 100.x.x.x. "
            "Treat as virtual mesh / tunnel context unless edge routing corroborates a public path."
        )
    return ""


def _maybe_auto_migrate_event_db(db_path: str) -> None:
    """If SQLCipher is enabled but the DB file is still plain SQLite, migrate in-place with a timestamped backup."""
    if not _sqlcipher_enabled():
        return
    if os.environ.get("SENTINEL_SQLCIPHER_AUTO_MIGRATE", "1").strip().lower() in {"0", "false", "no", "off"}:
        return
    if not os.path.isfile(db_path):
        return
    from sentinel_db_migrate import is_plain_sqlite, migrate_plain_to_sqlcipher_file

    if not is_plain_sqlite(db_path):
        return
    passphrase = os.environ.get("SENTINEL_SQLCIPHER_PASSPHRASE", "").strip()
    if not passphrase:
        return
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = f"{db_path}.pre_sqlcipher.{ts}.bak"
    tmp = f"{db_path}.tmp_sqlcipher_migrate"
    if os.path.isfile(tmp):
        try:
            os.remove(tmp)
        except OSError:
            pass
    shutil.copy2(db_path, backup)
    try:
        n = migrate_plain_to_sqlcipher_file(db_path, tmp, passphrase)
        os.replace(tmp, db_path)
        print(f"[*] Auto-migrated event database to SQLCipher ({n} rows). Plain backup: {backup}")
    except Exception:
        if os.path.isfile(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        raise


def _import_required(module_name: str) -> Any:
    try:
        return importlib.import_module(module_name)
    except ImportError:
        print(f"explain_api requires: pip install {module_name}")
        sys.exit(1)


joblib = _import_required("joblib")
np = cast(Any, _import_required("numpy"))
shap: Optional[Any] = None
_SHAP_IMPORT_LOCK: Lock = Lock()
_SHAP_IMPORT_ATTEMPTED = False
_SHAP_IMPORT_ERROR: Optional[str] = None


def _ensure_shap_module() -> Optional[Any]:
    global shap, _SHAP_IMPORT_ATTEMPTED, _SHAP_IMPORT_ERROR

    if shap is not None:
        return shap
    if _SHAP_IMPORT_ATTEMPTED and _SHAP_IMPORT_ERROR:
        return None

    with _SHAP_IMPORT_LOCK:
        if shap is not None:
            return shap
        if _SHAP_IMPORT_ATTEMPTED and _SHAP_IMPORT_ERROR:
            return None

        _SHAP_IMPORT_ATTEMPTED = True
        try:
            shap = importlib.import_module("shap")
            _SHAP_IMPORT_ERROR = None
        except Exception as exc:
            shap = None
            _SHAP_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"
        return shap

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


def compute_feature_schema_hash(feature_names: List[str]) -> str:
    normalized = "|".join(str(name).strip().lower() for name in feature_names)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

# NOTE: These scaling constants MUST match the MinMax ranges used in train_ml.py.
# If train_ml.py is updated, update these values accordingly.
DEFAULT_MINMAX_LOW = np.zeros(NUM_FEATURES, dtype=np.float64)
DEFAULT_MINMAX_HIGH = np.array(
    [
        1e6, 1e9, 1.0, 1.0, 8.0, 8.0, 65535.0, 1500.0, 1000.0, 100.0,
        1.0, 8.0, 65535.0, 64.0, 16.0, 1e6, 1e6, 10000.0, 1e6, 1000.0,
    ],
    dtype=np.float64,
)
ML_MINMAX_LOW = DEFAULT_MINMAX_LOW.copy()
ML_MINMAX_HIGH = DEFAULT_MINMAX_HIGH.copy()
ML_MINMAX_RANGE = ML_MINMAX_HIGH - ML_MINMAX_LOW


def scale_features(X: Any) -> Any:
    feature_count = int(X.shape[1])
    low = ML_MINMAX_LOW[:feature_count]
    rng = ML_MINMAX_RANGE[:feature_count]
    scaled = np.asarray(X, dtype=np.float64).copy()
    np.subtract(scaled, low, out=scaled)
    np.divide(scaled, rng, out=scaled, where=rng > 0)
    np.clip(scaled, 0.0, 1.0, out=scaled)
    return scaled


def apply_model_scale_metadata(model_obj: Any) -> None:
    """Apply model-provided min/max ranges when available."""
    global ML_MINMAX_LOW, ML_MINMAX_HIGH, ML_MINMAX_RANGE

    if not isinstance(model_obj, dict):
        return

    scale = model_obj.get("scale")
    if not isinstance(scale, (tuple, list)) or len(scale) != 2:
        return

    try:
        low = np.asarray(scale[0], dtype=np.float64).reshape(-1)
        high = np.asarray(scale[1], dtype=np.float64).reshape(-1)
    except (TypeError, ValueError):
        return

    if low.size < NUM_FEATURES or high.size < NUM_FEATURES:
        return

    low = low[:NUM_FEATURES]
    high = high[:NUM_FEATURES]
    if np.any(~np.isfinite(low)) or np.any(~np.isfinite(high)):
        return

    rng = high - low
    if np.any(rng <= 0):
        return

    ML_MINMAX_LOW = low
    ML_MINMAX_HIGH = high
    ML_MINMAX_RANGE = rng


class ExplainHandler(BaseHTTPRequestHandler):
    model: Optional[Dict[str, Any]] = None
    _model_lock: Lock = Lock()
    _model_status: str = "uninitialized"
    _model_error: Optional[str] = None
    _model_path: str = ""
    _model_load_started: bool = False
    # TreeExplainer is initialized lazily so HTTP bind is not blocked by SHAP startup.
    _explainer: Optional[Any] = None
    _base_value: Optional[float] = None
    _explainer_lock: Lock = Lock()
    _shap_status: str = "lazy"
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
    _event_retention_limit: int = 10000
    _event_prune_interval: int = 100
    _event_write_count: int = 0
    _events_fernet: Optional[Any] = None

    # Rate limiting: 60 requests per minute per IP
    _rate_limit_lock: Lock = Lock()
    _rate_limits: Dict[str, List[float]] = {}
    _MAX_REQ_PER_MIN: int = 60

    # Gemini upstream protection: short cooldown on 429 + tiny prompt cache.
    _gemini_lock: Lock = Lock()
    _gemini_cooldown_until: float = 0.0
    _gemini_retry_after: int = 0
    _gemini_cache_ttl_sec: int = 30
    _gemini_prompt_cache: Dict[str, tuple[float, str]] = {}

    @classmethod
    def _apply_loaded_model_metadata(cls, model_obj: Any) -> None:
        apply_model_scale_metadata(model_obj)

        cls._feature_names = list(FEATURE_NAMES)
        cls._feature_count = len(cls._feature_names)
        cls._feature_schema_hash = compute_feature_schema_hash(cls._feature_names)
        cls._trainer_version = "unknown"

        if not isinstance(model_obj, dict):
            return

        feature_names = model_obj.get("feature_names")
        if isinstance(feature_names, list) and feature_names:
            cls._feature_names = [str(name) for name in feature_names]
            cls._feature_count = len(cls._feature_names)

        metadata_hash = model_obj.get("feature_schema_hash")
        if isinstance(metadata_hash, str) and metadata_hash.strip():
            cls._feature_schema_hash = metadata_hash.strip()
        else:
            cls._feature_schema_hash = compute_feature_schema_hash(cls._feature_names)

        trainer_version = model_obj.get("trainer_version")
        if isinstance(trainer_version, str) and trainer_version.strip():
            cls._trainer_version = trainer_version.strip()

    @classmethod
    def _load_model_sync(cls, model_path: str) -> None:
        with cls._model_lock:
            cls._model_path = model_path
            cls._model_load_started = True
            cls._model_status = "loading"
            cls._model_error = None

        try:
            model_obj = joblib.load(model_path)  # nosec B301
            cls._apply_loaded_model_metadata(model_obj)
            with cls._model_lock:
                cls.model = model_obj
                cls._model_status = "ready"
                cls._model_error = None
            print(f"[*] Loaded model from {model_path}")
        except Exception as exc:
            error_text = f"{type(exc).__name__}: {exc}"
            with cls._model_lock:
                cls.model = None
                cls._model_status = "error"
                cls._model_error = error_text
            print(f"[!] Failed to load model from {model_path}: {error_text}", file=sys.stderr)

    @classmethod
    def _start_model_loader(cls, model_path: str) -> None:
        with cls._model_lock:
            already_started = cls._model_load_started and cls._model_path == model_path

        if already_started:
            return

        loader = Thread(target=cls._load_model_sync, args=(model_path,), daemon=True, name="sentinel-model-loader")
        loader.start()

    @classmethod
    def _ensure_explainer_ready(cls) -> Optional[str]:
        if cls._explainer is not None:
            return None
        if cls.model is None:
            if cls._model_status == "loading":
                return "Model is still loading."
            if cls._model_status == "error":
                return f"Model failed to load: {cls._model_error or 'unknown error'}"
            return "Model not loaded. Run train_ml.py first."

        shap_module = _ensure_shap_module()
        if shap_module is None:
            cls._shap_status = f"unavailable: {_SHAP_IMPORT_ERROR or 'SHAP import failed'}"
            return f"SHAP unavailable: {_SHAP_IMPORT_ERROR or 'pip install shap'}"

        with cls._explainer_lock:
            if cls._explainer is not None:
                return None
            try:
                estimator = cls.model["estimator"]
                cls._explainer = shap_module.TreeExplainer(estimator)
                base = cls._explainer.expected_value
                if isinstance(base, (list, np.ndarray)):
                    base = float(base[1]) if len(base) > 1 else float(base[0])
                cls._base_value = float(base)
                cls._shap_status = "ready"
                print("[*] SHAP TreeExplainer cached on first use.")
                return None
            except Exception as exc:
                cls._shap_status = f"init_failed: {exc}"
                return f"SHAP explainer init failed: {exc}"

    @staticmethod
    def _parse_retry_after_seconds(header_value: Optional[str], default_seconds: int = 15) -> int:
        if not header_value:
            return default_seconds
        value = header_value.strip()
        if not value:
            return default_seconds
        if value.isdigit():
            return max(1, min(int(value), 300))
        return default_seconds

    def log_message(self, format: str, *args: Any) -> None:
        try:
            msg = format % args if args else format
        except Exception:
            msg = format
        sys.stderr.write(f"[explain_api] {msg}\n")

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

    def _check_rate_limit(self) -> bool:
        """Simple sliding-window rate limiter per client IP."""
        client_ip = self.client_address[0]
        now = datetime.now(timezone.utc).timestamp()
        with ExplainHandler._rate_limit_lock:
            history = ExplainHandler._rate_limits.get(client_ip, [])
            # Filter for requests in the last 60 seconds
            history = [ts for ts in history if now - ts < 60]
            if len(history) >= ExplainHandler._MAX_REQ_PER_MIN:
                self.log_message(f"[RATE-LIMIT] IP {client_ip} exceeded quota ({len(history)} req/min)")
                return False
            history.append(now)
            ExplainHandler._rate_limits[client_ip] = history
            # Periodic cleanup of stale IPs (every 100th request or similar)
            if len(ExplainHandler._rate_limits) > 1000:
                # Naive cleanup: remove any IP whose last request was > 5 mins ago
                to_delete = [
                    ip for ip, h in ExplainHandler._rate_limits.items()
                    if not h or now - h[-1] > 300
                ]
                for ip in to_delete:
                    del ExplainHandler._rate_limits[ip]
        return True

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", ExplainHandler._cors_origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Sentinel-API-Key, x-sentinel-api-key")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._json_response(
                200,
                {
                    "status": "ok",
                    "model_loaded": ExplainHandler.model is not None,
                    "model_status": ExplainHandler._model_status,
                    "model_error": ExplainHandler._model_error,
                    "explainer_loaded": ExplainHandler._explainer is not None,
                    "shap_available": bool(shap is not None or not _SHAP_IMPORT_ATTEMPTED),
                    "shap_status": ExplainHandler._shap_status,
                    "shap_import_error": _SHAP_IMPORT_ERROR,
                    "feature_count": ExplainHandler._feature_count,
                    "feature_schema_hash": ExplainHandler._feature_schema_hash,
                    "feature_names": ExplainHandler._feature_names,
                    "trainer_version": ExplainHandler._trainer_version,
                    "events_db_sqlcipher": _sqlcipher_enabled(),
                    "events_db_fernet_payloads": ExplainHandler._events_fernet is not None,
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
        # 1. Rate limiting (global per-IP check)
        if not self._check_rate_limit():
            self._json_response(429, {"error": "Too many requests. Limit is 60/min."})
            return

        # 2. Reject oversized bodies — prevents memory DoS.
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

        explainer_error = ExplainHandler._ensure_explainer_ready()
        if explainer_error:
            self._json_response(503, {"error": explainer_error})
            return

        body = self._parse_body()
        if body is None:
            self._json_response(400, {"error": "Invalid JSON body"})
            return

        samples = body.get("samples")
        if not isinstance(samples, list) or len(samples) == 0:
            self._json_response(400, {"error": f"Expected non-empty 'samples' array of {NUM_FEATURES}-feature vectors"})
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
            
            # TreeExplainer output shape varies across SHAP versions/model types.
            # Normalize to a 2D float array: [num_samples, num_features].
            shap_values = np.asarray(shap_values)
            if shap_values.ndim == 3:
                # Multi-output/multiclass: use positive class when available.
                out_idx = 1 if shap_values.shape[2] > 1 else 0
                shap_values = shap_values[:, :, out_idx]
            elif shap_values.ndim == 1:
                shap_values = shap_values.reshape(1, -1)
            elif shap_values.ndim != 2:
                self._json_response(
                    500,
                    {
                        "error": "Unexpected SHAP output shape",
                        "shape": list(shap_values.shape),
                    },
                )
                return
            shap_values = shap_values.astype(np.float64, copy=False)
        except Exception as e:
            self._json_response(500, {"error": f"Invalid SHAP output format or computation failed: {e}"})
            return

        feature_names = ExplainHandler._feature_names[: X_scaled.shape[1]]
        contributions: List[List[Dict[str, Any]]] = []
        for i in range(len(X_scaled)):
            row: List[Dict[str, Any]] = []
            for j in range(len(feature_names)):
                # shap_values is now guaranteed 2D: [num_samples, num_features]
                raw_val = float(shap_values[i, j])
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
        with _db_connect(db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
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
            row = conn.execute("SELECT COUNT(1) FROM sentinel_events").fetchone()
            total = int(row[0]) if row else 0
            if total > cls._event_retention_limit:
                excess = total - cls._event_retention_limit
                conn.execute(
                    """
                    DELETE FROM sentinel_events WHERE id IN (
                        SELECT id FROM sentinel_events ORDER BY event_ts ASC LIMIT ?
                    )
                    """,
                    (excess,),
                )
            conn.commit()
        enc = "SQLCipher file" if _sqlcipher_enabled() else "SQLite"
        print(f"[*] Event log database: {db_path} ({enc}, retention cap: {cls._event_retention_limit} rows)")

    def _handle_events_get(self, parsed: Any) -> None:
        """Return recent persisted activity events (newest-first)."""
        if not ExplainHandler._db_path:
            self._json_response(503, {"error": "Event database not initialised"})
            return
        qs = parse_qs(parsed.query)
        try:
            limit = int(qs.get("limit", ["200"])[0])
        except (ValueError, IndexError):
            limit = 200
        limit = max(1, min(limit, 1000))
        with ExplainHandler._db_lock:
            try:
                with _db_connect(ExplainHandler._db_path) as conn:
                    rows = conn.execute(
                        "SELECT payload FROM sentinel_events ORDER BY event_ts DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
            except sqlite3.Error as e:
                self._json_response(500, {"error": f"Database error: {e}"})
                return
        events: List[Any] = []
        for (payload_str,) in rows:
            raw = _decrypt_event_payload(ExplainHandler._events_fernet, payload_str)
            if raw is None:
                continue
            try:
                events.append(json.loads(raw))
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

        incoming_events: List[Dict[str, Any]] = []
        batched = body.get("events")
        if isinstance(batched, list):
            for item in batched:
                if isinstance(item, dict):
                    incoming_events.append(item)
        elif isinstance(body, dict):
            incoming_events.append(body)

        if not incoming_events:
            self._json_response(400, {"error": "Expected event object or non-empty 'events' array"})
            return

        max_batch = 200
        if len(incoming_events) > max_batch:
            self._json_response(400, {"error": f"Too many events in one request (max {max_batch})"})
            return

        rows: List[tuple[float, str, str]] = []
        for ev in incoming_events:
            event_ts = ev.get("timestamp")
            if not isinstance(event_ts, (int, float)):
                self._json_response(
                    400,
                    {"error": "Each event requires numeric 'timestamp' (Unix epoch)"},
                )
                return
            try:
                payload = json.dumps(ev, separators=(",", ":"))
            except (TypeError, ValueError):
                self._json_response(400, {"error": "Event payload must be JSON-serializable"})
                return
            payload = _encrypt_event_payload(ExplainHandler._events_fernet, payload)
            rows.append(
                (
                    float(event_ts),
                    datetime.now(timezone.utc).isoformat(),
                    payload,
                )
            )

        with ExplainHandler._db_lock:
            try:
                with _db_connect(ExplainHandler._db_path) as conn:
                    conn.executemany(
                        "INSERT INTO sentinel_events (event_ts, logged_at, payload) VALUES (?, ?, ?)",
                        rows,
                    )
                    ExplainHandler._event_write_count += len(rows)

                    if ExplainHandler._event_write_count >= ExplainHandler._event_prune_interval:
                        ExplainHandler._event_write_count = 0
                        row_count = conn.execute(
                            "SELECT COUNT(1) FROM sentinel_events"
                        ).fetchone()
                        total = int(row_count[0]) if row_count else 0
                        if total > ExplainHandler._event_retention_limit:
                            conn.execute(
                                """
                                DELETE FROM sentinel_events WHERE id NOT IN (
                                    SELECT id FROM sentinel_events ORDER BY event_ts DESC LIMIT ?
                                )
                                """,
                                (ExplainHandler._event_retention_limit,),
                            )
                    conn.commit()
            except sqlite3.Error as e:
                self._json_response(500, {"error": f"Database error: {e}"})
                return
        self._json_response(201, {"status": "ok", "accepted": len(rows)})

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

    @staticmethod
    def _build_local_analysis_fallback(
        src_ip: str,
        pps: float,
        bps: float,
        score: float,
        flows: float,
        protocol: str,
        reason: str,
    ) -> str:
        """Return a deterministic local analysis when Gemini is unavailable."""
        risk_pct = max(0.0, min(100.0, score * 100.0))
        protocol_name = protocol.strip() if protocol else ""
        protocol_desc = (
            f"{protocol_name} traffic"
            if protocol_name and protocol_name.lower() not in {"unknown", "n/a", "none", "-"}
            else "no stable dominant protocol"
        )
        if pps <= 5.0 and bps <= 1024.0 and score <= 0.1:
            return (
                f"Local telemetry assessment only: current traffic looks low-signal. "
                f"{flows:.0f} concurrent flows are open from {src_ip}, but throughput is near zero at "
                f"{pps:.0f} packets/sec and {bps:.0f} bytes/sec, with a threat score of {risk_pct:.1f}%. "
                f"This is more consistent with idle or long-lived connections than an active attack ({reason})."
            )
        if score > 0.5:
            return (
                f"Local telemetry assessment only: Sentinel detected elevated risk from {src_ip} with approximately "
                f"{pps:.0f} packets/sec and {bps:.0f} bytes/sec dominated by {protocol_desc}. "
                f"Threat score is {risk_pct:.1f}% across about {flows:.0f} concurrent flows; "
                f"Gemini analysis is unavailable, so this local assessment is based on live telemetry only ({reason})."
            )
        return (
            f"Local telemetry assessment only: traffic from {src_ip} is not showing a confirmed attack pattern. "
            f"Current load is about {pps:.0f} packets/sec, {bps:.0f} bytes/sec, and {flows:.0f} concurrent flows "
            f"with {protocol_desc}; threat score is {risk_pct:.1f}%. "
            f"Treat this as observation-level activity unless other telemetry strengthens the signal ({reason})."
        )

    def _handle_analyze(self) -> None:
        """Proxy Gemini API call server-side to avoid exposing API key to the frontend."""
        body = self._parse_body()
        if body is None:
            self._json_response(400, {"error": "Invalid JSON body"})
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

        def respond_with_local_fallback(reason: str) -> None:
            self._json_response(
                200,
                {
                    "analysis": self._build_local_analysis_fallback(
                        src_ip=src_ip,
                        pps=pps,
                        bps=bps,
                        score=score,
                        flows=flows,
                        protocol=protocol,
                        reason=reason,
                    ),
                    "degraded": True,
                    "source": "local_fallback",
                    "reason": reason,
                },
            )

        if pps <= 5.0 and bps <= 1024.0 and score <= 0.1:
            self._json_response(
                200,
                {
                    "analysis": self._build_local_analysis_fallback(
                        src_ip=src_ip,
                        pps=pps,
                        bps=bps,
                        score=score,
                        flows=flows,
                        protocol=protocol,
                        reason="low-signal telemetry; Gemini skipped",
                    ),
                    "degraded": False,
                    "source": "telemetry_baseline",
                    "reason": "low-signal telemetry",
                },
            )
            return

        now_ts = time.time()
        with ExplainHandler._gemini_lock:
            if now_ts < ExplainHandler._gemini_cooldown_until:
                retry_after = max(1, int(ExplainHandler._gemini_cooldown_until - now_ts))
                respond_with_local_fallback(f"Gemini rate limited, retry after {retry_after}s")
                return

        header_key = (self.headers.get("X-Gemini-Api-Key") or "").strip()
        api_key = header_key or os.environ.get("GEMINI_API_KEY", "").strip()
        if not api_key:
            respond_with_local_fallback("Gemini API key not configured")
            return

        overlay_hint = _ipv4_overlay_context_hint(src_ip)
        overlay_block = f"\n- Overlay / addressing context: {overlay_hint}\n" if overlay_hint else ""

        prompt = (
            "Role: Senior SOC analyst for Sentinel (enterprise NDR). Output a concise incident-style briefing.\n"
            "Rules: Use only the telemetry below. Do not invent infrastructure, threat actors, APT names, nation-state groups, "
            "or malware families. Never fabricate geolocation or 'whois' details. "
            "If evidence is weak or ambiguous, state uncertainty and recommend what additional data would help. "
            "Tie conclusions to PPS/BPS, flow count, protocol mix, and threat score. "
            "Tone: professional, neutral, actionable (2–4 short sentences; no bullet lists unless severity is high).\n\n"
            "Telemetry snapshot:\n"
            f"- Time (UTC context as provided): {ts}\n"
            f"- Source IP: {src_ip}\n"
            f"- Packets/sec: {pps:.0f}\n"
            f"- Bytes/sec: {bps:.0f}\n"
            f"- Threat score (0–1): {score:.4f}\n"
            f"- Active concurrent flows: {flows:.0f}\n"
            f"- Dominant protocol: {protocol}"
            f"{overlay_block}\n"
            "Classify the observation (e.g., likely benign noise, possible volumetric anomaly, or consistent with attack-like load) "
            "only as far as these numbers justify."
        )

        prompt_key = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        with ExplainHandler._gemini_lock:
            cached = ExplainHandler._gemini_prompt_cache.get(prompt_key)
            if cached is not None:
                cached_ts, cached_text = cached
                if (now_ts - cached_ts) <= ExplainHandler._gemini_cache_ttl_sec:
                    self._json_response(200, {"analysis": cached_text, "cached": True, "degraded": False, "source": "gemini"})
                    return

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
            with ExplainHandler._gemini_lock:
                ExplainHandler._gemini_prompt_cache[prompt_key] = (time.time(), text)
                # Keep cache bounded.
                if len(ExplainHandler._gemini_prompt_cache) > 128:
                    oldest_key = min(
                        ExplainHandler._gemini_prompt_cache,
                        key=lambda k: ExplainHandler._gemini_prompt_cache[k][0],
                    )
                    del ExplainHandler._gemini_prompt_cache[oldest_key]
            self._json_response(200, {"analysis": text, "degraded": False, "source": "gemini"})
        except urllib.error.HTTPError as e:
            if e.code == 429:
                retry_after = ExplainHandler._parse_retry_after_seconds(e.headers.get("Retry-After"), default_seconds=20)
                with ExplainHandler._gemini_lock:
                    ExplainHandler._gemini_retry_after = retry_after
                    ExplainHandler._gemini_cooldown_until = max(
                        ExplainHandler._gemini_cooldown_until,
                        time.time() + retry_after,
                    )
                respond_with_local_fallback(f"Gemini rate limit reached, retry after {retry_after}s")
                return
            respond_with_local_fallback(f"Gemini upstream HTTP {e.code}")
        except Exception as e:
            respond_with_local_fallback(f"Gemini unavailable: {e}")


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
    parser.add_argument(
        "--allow-insecure-public-bind",
        action="store_true",
        help="Allow non-loopback binding without API key or proxy auth. Not recommended.",
    )
    parser.add_argument(
        "--event-retention",
        type=int,
        default=None,
        metavar="N",
        help="Max rows to keep in sentinel_events.db (default: 10000 or SENTINEL_EVENT_RETENTION_LIMIT)",
    )
    args = parser.parse_args()

    ExplainHandler._cors_origin = args.cors_origin
    _ret_env = os.environ.get("SENTINEL_EVENT_RETENTION_LIMIT", "").strip()
    if args.event_retention is not None:
        ExplainHandler._event_retention_limit = max(100, min(int(args.event_retention), 1_000_000))
    elif _ret_env.isdigit():
        ExplainHandler._event_retention_limit = max(100, min(int(_ret_env), 1_000_000))
    ExplainHandler._api_key = os.environ.get("SENTINEL_WS_API_KEY", "").strip()
    ExplainHandler._require_proxy_auth = os.environ.get("SENTINEL_REQUIRE_PROXY_AUTH", "0") in {"1", "true", "TRUE", "yes", "YES"}
    ExplainHandler._trusted_proxy_ips = {
        ip.strip() for ip in os.environ.get("SENTINEL_TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if ip.strip()
    } or {"127.0.0.1", "::1"}
    ExplainHandler._login_url = os.environ.get("SENTINEL_PROXY_LOGIN_URL", "/oauth2/start")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = args.model or os.path.join(script_dir, "benchmarks", "sentinel_model.joblib")

    ExplainHandler._model_path = model_path
    ExplainHandler._events_fernet = _fernet_from_env()
    if ExplainHandler._events_fernet:
        print("[*] Event log payload encryption: Fernet (SENTINEL_EVENTS_ENCRYPTION_KEY)")

    if os.path.isfile(model_path):
        ExplainHandler._model_status = "loading"
        ExplainHandler._start_model_loader(model_path)
    else:
        ExplainHandler._model_status = "missing"
        ExplainHandler._model_error = f"Model not found: {model_path}"
        print(f"[!] Model not found: {model_path}", file=sys.stderr)
        print("[!] Run train_ml.py first to generate the model.", file=sys.stderr)

    # SHAP is initialized lazily on the first /shap request so the HTTP server can
    # start even if SHAP/numba import is slow or unavailable in the current runtime.
    ExplainHandler._shap_status = "lazy"

    db_path = os.path.join(script_dir, "sentinel_events.db")
    _maybe_auto_migrate_event_db(db_path)
    ExplainHandler._init_db(db_path)

    try:
        is_loopback_host = ipaddress.ip_address(args.host).is_loopback
    except ValueError:
        is_loopback_host = args.host.lower() == "localhost"

    if (not is_loopback_host and not ExplainHandler._api_key and not ExplainHandler._require_proxy_auth):  # nosec B104
        if not args.allow_insecure_public_bind:
            print(
                "[!] Refusing to bind Explain API on a non-loopback host without API key or proxy auth. "
                "Set SENTINEL_WS_API_KEY, enable proxy auth, or pass --allow-insecure-public-bind to override.",
                file=sys.stderr,
            )
            raise SystemExit(2)
        print("[!] WARNING: Listening publicly with no API key and no proxy auth because --allow-insecure-public-bind was set.")

    server = ThreadingHTTPServer((args.host, args.port), ExplainHandler)
    print(f"[*] Explain API listening on http://{args.host}:{args.port}")
    print(f"[*] CORS origin: {args.cors_origin}")
    print(f"[*] Proxy auth required: {ExplainHandler._require_proxy_auth}")
    print(f"[*] Model initialization mode: {ExplainHandler._model_status}")
    print("[*] SHAP initialization mode: lazy")
    print("[*] GET /health  GET /events  POST /shap  POST /analyze  POST /events")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()

