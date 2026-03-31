"""
Sentinel DDoS Core - real-dataset ML training pipeline.

Supported inputs:
- CICIoT2023 CSV exports
- NF-UNSW-NB15-v2 CSV exports
- UNSW-NB15 CSV exports
- CICDDoS2019-style CSV exports
- Pre-engineered Sentinel 20-feature CSV/JSON files

The trainer only accepts real labeled data. It refuses to train when the
accepted corpus collapses to a single class, when labels are missing, or when
the input schema cannot be mapped with enough grounded features.

DATASET SOURCING:
To generate 'sentinel_model.joblib' for the Explain API:
1. Download CIC-DDoS2019 or CIC-IoT-2023 (CSV versions).
2. Place CSVs in a './data' directory.
3. Run: python3 train_ml.py --dataset-dir ./data --export-joblib sentinel_model.joblib
"""

from __future__ import annotations

import argparse
import csv
import glob
import importlib
import hashlib
import json
import math
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

if os.name == "nt":
    os.environ.setdefault("LOKY_MAX_CPU_COUNT", str(max(1, os.cpu_count() or 1)))

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.neighbors import KNeighborsClassifier
    from sklearn.tree import DecisionTreeClassifier
    from sklearn.metrics import (
        accuracy_score,
        balanced_accuracy_score,
        confusion_matrix,
        f1_score,
        matthews_corrcoef,
        precision_score,
        precision_recall_fscore_support,
        recall_score,
        roc_auc_score,
        make_scorer,
    )
    from sklearn.model_selection import train_test_split
    from sklearn.inspection import permutation_importance
except ImportError:
    print("WARNING: Required libraries missing. Run: pip install scikit-learn numpy")
    sys.exit(1)

try:
    m2c = importlib.import_module("m2cgen")
except Exception:
    m2c = None

try:
    import joblib
except ImportError:
    joblib = None

try:
    pq = importlib.import_module("pyarrow.parquet")
except Exception:
    pq = None

try:
    XGBClassifier = getattr(importlib.import_module("xgboost"), "XGBClassifier", None)
except Exception:
    XGBClassifier = None


NUM_FEATURES = 20
RANDOM_STATE = 42
MIN_MAPPED_FEATURES = 6
DEFAULT_REQUIRED_DATASET_TYPES = ("ciciot2023", "nf_unsw_nb15_v2")
TRAINER_VERSION = "2026-03-11-mixed-dataset-v7"
BENCHMARK_ARTIFACT_NAME = "model_benchmark_report.json"
BENCHMARK_ARTIFACT_DIRS = ("benchmarks", ("frontend", "public"))
AUTO_DATA_DIR_CANDIDATES = (
    "data",
)
SPLIT_PRIORITY = {
    "train": 0,
    "validation": 1,
    "test": 2,
    "unspecified": 3,
}

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

SHAP_FEATURE_NAMES = FEATURE_NAMES + ["chi_square_score"]


def compute_feature_schema_hash(feature_names: Sequence[str]) -> str:
    normalized = "|".join(str(name).strip().lower() for name in feature_names)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

ML_MINMAX_LOW = np.zeros(NUM_FEATURES, dtype=np.float64)
ML_MINMAX_HIGH = np.array(
    [
        1e6,
        1e9,
        1.0,
        1.0,
        8.0,
        8.0,
        65535.0,
        1500.0,
        1000.0,
        100.0,
        1.0,
        8.0,
        65535.0,
        64.0,
        16.0,
        1e6,
        1e6,
        10000.0,
        1e6,
        1000.0,
    ],
    dtype=np.float64,
)
ML_MINMAX_RANGE = ML_MINMAX_HIGH - ML_MINMAX_LOW

BENIGN_LABEL_TOKENS = {
    "0",
    "0.0",
    "benign",
    "benigntraffic",
    "false",
    "normal",
    "normaltraffic",
}
LABEL_COLUMN_CANDIDATES = [
    "label",
    "attack",
    "attack_type",
    "attacktype",
    "attack_cat",
    "attack_category",
    "category",
    "class",
]


def normalize_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")


DATASET_SIGNATURES = {
    "sentinel_features": {normalize_name(name) for name in FEATURE_NAMES},
    "ciciot2023": {
        "rate",
        "srate",
        "drate",
        "http",
        "dns",
        "iat",
        "number",
        "tot_size",
        "syn_count",
        "rst_count",
    },
    "nf_unsw_nb15_v2": {
        "in_bytes",
        "out_bytes",
        "in_pkts",
        "out_pkts",
        "flow_duration_milliseconds",
        "l4_src_port",
        "l4_dst_port",
        "protocol",
        "label",
    },
    "unsw_nb15": {
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "rate",
        "sttl",
        "dttl",
        "sinpkt",
        "label",
    },
    "cicddos2019": {
        "flow_packets_s",
        "flow_bytes_s",
        "packet_length_mean",
        "packet_length_std",
        "flow_iat_mean",
        "flow_iat_std",
        "syn_flag_count",
        "rst_flag_count",
        "label",
    },
}


@dataclass
class DatasetChunk:
    path: str
    dataset_type: str
    split_hint: str
    label_column: str
    label_examples: Tuple[str, ...]
    feature_sources: Dict[str, str]
    X: np.ndarray
    y: np.ndarray

    @property
    def class_counts(self) -> Counter:
        return Counter(int(v) for v in self.y.tolist())

    @property
    def direct_feature_count(self) -> int:
        return sum(1 for src in self.feature_sources.values() if src.startswith("direct:"))

    @property
    def derived_feature_count(self) -> int:
        return sum(1 for src in self.feature_sources.values() if src.startswith("derived:"))

    @property
    def grounded_feature_count(self) -> int:
        return self.direct_feature_count + self.derived_feature_count


@dataclass
class SplitPlan:
    strategy: str
    family_splits: Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]]
    family_strategies: Dict[str, str]
    overlap_removed_rows: Dict[str, Dict[str, int]]


@dataclass
class ModelArtifact:
    name: str
    estimator: Any
    score_mode: str
    params: Dict[str, object] = field(default_factory=dict)
    threshold: Optional[float] = None
    training_note: Optional[str] = None
    exportable: bool = False


@dataclass
class ModelBenchmarkResult:
    artifact: ModelArtifact
    selection_train_metrics: Dict[str, object]
    selection_val_metrics: Dict[str, object]
    selection_summary: Dict[str, object]
    fit_metrics: Dict[str, object]
    test_metrics: Dict[str, object]
    validation_family_metrics: Dict[str, Dict[str, object]]
    dataset_test_metrics: Dict[str, Dict[str, object]]
    transfer_metrics: Dict[str, Dict[str, Dict[str, object]]]
    inference_ms_per_sample: float


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(result) or math.isinf(result):
        return default
    return result


def safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0.0:
        return 0.0
    result = numerator / denominator
    if math.isnan(result) or math.isinf(result):
        return 0.0
    return max(0.0, min(1.0, result))


def safe_div(numerator: float, denominator: float) -> float:
    if denominator <= 0.0:
        return 0.0
    result = numerator / denominator
    if math.isnan(result) or math.isinf(result):
        return 0.0
    return max(0.0, result)


def scale_features(X: np.ndarray) -> np.ndarray:
    scaled = np.asarray(X, dtype=np.float64).copy()
    np.subtract(scaled, ML_MINMAX_LOW, out=scaled)
    np.divide(scaled, ML_MINMAX_RANGE, out=scaled, where=ML_MINMAX_RANGE > 0)
    np.clip(scaled, 0.0, 1.0, out=scaled)
    return scaled


def infer_split_hint(path: str) -> str:
    normalized = path.replace("\\", "/").lower()
    if "/test/" in normalized or normalized.endswith("/test.csv") or "_test" in normalized:
        return "test"
    if "/validation/" in normalized or "/valid/" in normalized or "/val/" in normalized or "_val" in normalized:
        return "validation"
    if "/train/" in normalized or normalized.endswith("/train.csv") or "_train" in normalized:
        return "train"
    return "unspecified"


def header_map(headers: Sequence[str]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for header in headers:
        key = normalize_name(header)
        if key and key not in mapping:
            mapping[key] = header
    return mapping


def pick_header(mapping: Dict[str, str], candidates: Sequence[str]) -> Optional[str]:
    for candidate in candidates:
        key = normalize_name(candidate)
        if key in mapping:
            return mapping[key]
    return None


def parquet_headers(path: str) -> List[str]:
    if pq is None:
        raise RuntimeError(
            f"pyarrow is required to inspect parquet datasets such as {path}. "
            "Install pyarrow or convert the dataset to CSV."
        )
    parquet_file = pq.ParquetFile(path)
    return list(parquet_file.schema.names)


def row_value(row: Dict[str, str], column: Optional[str], default: float = 0.0) -> float:
    if not column:
        return default
    return safe_float(row.get(column), default)


def first_nonzero(row: Dict[str, str], columns: Sequence[Optional[str]], default: float = 0.0) -> float:
    for column in columns:
        if not column:
            continue
        value = safe_float(row.get(column), default)
        if value > 0.0:
            return value
    return default


def average_nonzero(values: Sequence[float]) -> float:
    kept = [value for value in values if value > 0.0]
    if not kept:
        return 0.0
    return float(sum(kept) / len(kept))


def parse_binary_label(raw_value: object) -> Optional[int]:
    if raw_value is None:
        return None
    text = str(raw_value).strip()
    if not text:
        return None
    normalized = text.lower()
    if normalized in BENIGN_LABEL_TOKENS or "benign" in normalized or "normal" in normalized:
        return 0
    try:
        numeric = float(normalized)
        if math.isnan(numeric) or math.isinf(numeric):
            return None
        return 0 if numeric == 0.0 else 1
    except ValueError:
        return 1


def capture_label_example(raw_value: object) -> str:
    if raw_value is None:
        return ""
    return str(raw_value).strip()[:80]


def detect_sentinel_json_payload_type(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            payload = json.load(handle)
    except (OSError, ValueError, json.JSONDecodeError):
        return None

    rows = payload.get("samples", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list) or not rows:
        return None

    sample = next((row for row in rows if isinstance(row, dict)), None)
    if sample is None:
        return None

    keys = {normalize_name(key) for key in sample.keys()}
    # Require strict matching of the core feature set for JSON datasets
    required_keys = DATASET_SIGNATURES["sentinel_features"]
    if required_keys.issubset(keys):
        return "sentinel_json"

    # Fallback for older sentinel JSON formats if they have enough mapped features
    label_keys = {"label", "attack", "class", "target"}
    if (label_keys & keys) and len(keys & required_keys) >= (NUM_FEATURES // 2):
        return "sentinel_json"

    return None


def detect_dataset_type(path: str) -> Optional[str]:
    if path.lower().endswith(".json"):
        return detect_sentinel_json_payload_type(path)
    if path.lower().endswith(".parquet"):
        headers = parquet_headers(path)
    else:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            headers = next(reader, [])
        if len(headers) == 4:
            numeric_tokens = 0
            for token in headers:
                value = token.strip()
                if not value:
                    break
                try:
                    float(value)
                    numeric_tokens += 1
                except ValueError:
                    break
            if numeric_tokens == 4:
                return "sdn_portblocking"

    if not headers:
        return None

    keys = set(header_map(headers))
    if DATASET_SIGNATURES["sentinel_features"].issubset(keys):
        return "sentinel_features"

    best_type = None
    best_score = 0
    for dataset_type in ("ciciot2023", "nf_unsw_nb15_v2", "unsw_nb15", "cicddos2019"):
        score = len(keys & DATASET_SIGNATURES[dataset_type])
        if score > best_score:
            best_type = dataset_type
            best_score = score

    if best_type == "ciciot2023" and best_score >= 6:
        return best_type
    if best_type in {"nf_unsw_nb15_v2", "unsw_nb15", "cicddos2019"} and best_score >= 5:
        return best_type
    return None


def resolve_label_column(mapping: Dict[str, str]) -> Optional[str]:
    return pick_header(mapping, LABEL_COLUMN_CANDIDATES)


def load_csv_rows(
    path: str,
    label_column: str,
    feature_builder: Callable[[Dict[str, str]], List[float]],
    feature_sources: Dict[str, str],
    max_rows: int,
) -> Optional[DatasetChunk]:
    X_rows: List[List[float]] = []
    y_list: List[int] = []
    label_examples: List[str] = []
    examples_seen = set()

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row_index, row in enumerate(reader):
            if max_rows and row_index >= max_rows:
                break
            raw_label = row.get(label_column)
            label = parse_binary_label(raw_label)
            if label is None:
                continue
            features = feature_builder(row)
            if len(features) != NUM_FEATURES:
                raise RuntimeError(f"Feature builder returned {len(features)} values for {path}")
            X_rows.append(features)
            y_list.append(label)
            example = capture_label_example(raw_label)
            if example and example not in examples_seen and len(label_examples) < 6:
                examples_seen.add(example)
                label_examples.append(example)

    if not X_rows:
        return None

    return DatasetChunk(
        path=path,
        dataset_type="unknown",
        split_hint=infer_split_hint(path),
        label_column=label_column,
        label_examples=tuple(label_examples),
        feature_sources=feature_sources,
        X=np.asarray(X_rows, dtype=np.float64),
        y=np.asarray(y_list, dtype=np.int64),
    )


def load_parquet_rows(
    path: str,
    label_column: str,
    feature_builder: Callable[[Dict[str, object]], List[float]],
    feature_sources: Dict[str, str],
    max_rows: int,
    columns: Sequence[Optional[str]],
) -> Optional[DatasetChunk]:
    if pq is None:
        raise RuntimeError(
            f"pyarrow is required to read parquet datasets such as {path}. "
            "Install pyarrow or convert the dataset to CSV."
        )

    selected_columns: List[str] = []
    seen_columns = set()
    for column in [label_column, *columns]:
        if column and column not in seen_columns:
            selected_columns.append(column)
            seen_columns.add(column)

    parquet_file = pq.ParquetFile(path)
    X_rows: List[List[float]] = []
    y_list: List[int] = []
    label_examples: List[str] = []
    examples_seen = set()
    loaded_rows = 0

    batch_size = min(65536, max_rows) if max_rows else 65536
    for batch in parquet_file.iter_batches(columns=selected_columns, batch_size=batch_size):
        batch_dict = batch.to_pydict()
        if not batch_dict:
            continue
        batch_len = len(next(iter(batch_dict.values())))
        for idx in range(batch_len):
            if max_rows and loaded_rows >= max_rows:
                break
            row = {column: values[idx] for column, values in batch_dict.items()}
            raw_label = row.get(label_column)
            label = parse_binary_label(raw_label)
            if label is None:
                continue
            features = feature_builder(row)
            if len(features) != NUM_FEATURES:
                raise RuntimeError(f"Feature builder returned {len(features)} values for {path}")
            X_rows.append(features)
            y_list.append(label)
            example = capture_label_example(raw_label)
            if example and example not in examples_seen and len(label_examples) < 6:
                examples_seen.add(example)
                label_examples.append(example)
            loaded_rows += 1
        if max_rows and loaded_rows >= max_rows:
            break

    if not X_rows:
        return None

    return DatasetChunk(
        path=path,
        dataset_type="unknown",
        split_hint=infer_split_hint(path),
        label_column=label_column,
        label_examples=tuple(label_examples),
        feature_sources=feature_sources,
        X=np.asarray(X_rows, dtype=np.float64),
        y=np.asarray(y_list, dtype=np.int64),
    )


def load_sentinel_feature_csv(path: str, max_rows: int) -> Optional[DatasetChunk]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
    mapping = header_map(headers)
    label_column = resolve_label_column(mapping)
    if not label_column:
        return None

    feature_columns = []
    for name in FEATURE_NAMES:
        column = mapping.get(normalize_name(name))
        if not column:
            return None
        feature_columns.append(column)
    feature_sources = {name: f"direct:{column}" for name, column in zip(FEATURE_NAMES, feature_columns)}

    def build_features(row: Dict[str, str]) -> List[float]:
        return [row_value(row, column, 0.0) for column in feature_columns]

    chunk = load_csv_rows(path, label_column, build_features, feature_sources, max_rows)
    if chunk:
        chunk.dataset_type = "sentinel_features"
    return chunk

def load_ciciot2023_csv(path: str, max_rows: int) -> Optional[DatasetChunk]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
    mapping = header_map(headers)
    label_column = resolve_label_column(mapping)
    if not label_column:
        return None

    rate_col = pick_header(mapping, ["rate"])
    srate_col = pick_header(mapping, ["srate"])
    duration_col = pick_header(mapping, ["duration"])
    avg_col = pick_header(mapping, ["avg", "average_packet_size"])
    std_col = pick_header(mapping, ["std", "stddev"])
    total_size_col = pick_header(mapping, ["tot_size", "total_size"])
    total_packets_col = pick_header(mapping, ["number"])
    syn_count_col = pick_header(mapping, ["syn_count", "syn_flag_number"])
    rst_count_col = pick_header(mapping, ["rst_count", "rst_flag_number"])
    fin_count_col = pick_header(mapping, ["fin_count", "fin_flag_number"])
    http_col = pick_header(mapping, ["http"])
    dns_col = pick_header(mapping, ["dns"])
    iat_col = pick_header(mapping, ["iat"])

    feature_sources = {
        "packets_per_second": f"direct:{rate_col or srate_col or 'missing'}",
        "bytes_per_second": "derived:tot_size/duration_or_rate*avg",
        "syn_ratio": "derived:syn_count/number",
        "rst_ratio": "derived:rst_count/number",
        "dst_port_entropy": "constant:0",
        "payload_byte_entropy": "constant:0",
        "unique_dst_ports": "constant:0",
        "avg_packet_size": f"direct:{avg_col or 'missing'}",
        "stddev_packet_size": f"direct:{std_col or 'missing'}",
        "http_request_count": f"direct:{http_col or 'missing'}",
        "fin_ratio": "derived:fin_count/number",
        "src_port_entropy": "constant:0",
        "unique_src_ports": "constant:0",
        "avg_ttl": "constant:0",
        "stddev_ttl": "constant:0",
        "avg_iat_us": f"direct:{iat_col or 'missing'}",
        "stddev_iat_us": "constant:0",
        "src_total_flows": "constant:0",
        "src_packets_per_second": f"direct:{srate_col or rate_col or 'missing'}",
        "dns_query_count": f"direct:{dns_col or 'missing'}",
    }

    def build_features(row: Dict[str, str]) -> List[float]:
        total_packets = row_value(row, total_packets_col, 0.0)
        packets_per_second = first_nonzero(row, [rate_col, srate_col], 0.0)
        avg_packet_size = row_value(row, avg_col, 0.0)
        duration = row_value(row, duration_col, 0.0)
        total_size = row_value(row, total_size_col, 0.0)
        if total_size > 0.0 and duration > 0.0:
            bytes_per_second = safe_div(total_size, duration)
        elif packets_per_second > 0.0 and avg_packet_size > 0.0:
            bytes_per_second = packets_per_second * avg_packet_size
        else:
            bytes_per_second = 0.0

        syn_count = row_value(row, syn_count_col, 0.0)
        rst_count = row_value(row, rst_count_col, 0.0)
        fin_count = row_value(row, fin_count_col, 0.0)

        return [
            packets_per_second,
            bytes_per_second,
            safe_ratio(syn_count, total_packets),
            safe_ratio(rst_count, total_packets),
            0.0,
            0.0,
            0.0,
            avg_packet_size,
            row_value(row, std_col, 0.0),
            row_value(row, http_col, 0.0),
            safe_ratio(fin_count, total_packets),
            0.0,
            0.0,
            0.0,
            0.0,
            row_value(row, iat_col, 0.0),
            0.0,
            0.0,
            first_nonzero(row, [srate_col, rate_col], 0.0),
            row_value(row, dns_col, 0.0),
        ]

    chunk = load_csv_rows(path, label_column, build_features, feature_sources, max_rows)
    if chunk:
        chunk.dataset_type = "ciciot2023"
    return chunk


def parse_tcp_flags(raw_value: object) -> Tuple[float, float, float]:
    if raw_value is None:
        return 0.0, 0.0, 0.0
    text = str(raw_value).strip()
    if not text:
        return 0.0, 0.0, 0.0
    upper = text.upper()
    if any(ch in upper for ch in "SFR"):
        return (
            1.0 if "S" in upper else 0.0,
            1.0 if "R" in upper else 0.0,
            1.0 if "F" in upper else 0.0,
        )
    try:
        flags = int(float(text))
    except ValueError:
        return 0.0, 0.0, 0.0
    return (
        1.0 if flags & 0x02 else 0.0,
        1.0 if flags & 0x04 else 0.0,
        1.0 if flags & 0x01 else 0.0,
    )


def load_nf_unsw_nb15_v2(path: str, max_rows: int) -> Optional[DatasetChunk]:
    if path.lower().endswith(".parquet"):
        headers = parquet_headers(path)
    else:
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            reader = csv.DictReader(handle)
            headers = list(reader.fieldnames or [])
    mapping = header_map(headers)
    label_column = resolve_label_column(mapping)
    if not label_column:
        return None

    in_bytes_col = pick_header(mapping, ["in_bytes"])
    out_bytes_col = pick_header(mapping, ["out_bytes"])
    in_pkts_col = pick_header(mapping, ["in_pkts"])
    out_pkts_col = pick_header(mapping, ["out_pkts"])
    duration_ms_col = pick_header(mapping, ["flow_duration_milliseconds"])
    ttl_a_col = pick_header(mapping, ["client_ttl", "sttl"])
    ttl_b_col = pick_header(mapping, ["server_ttl", "dttl"])
    http_col = pick_header(mapping, ["http", "ct_flw_http_mthd"])
    dns_col = pick_header(mapping, ["ct_dns_query", "dns_query_id"])
    tcp_flags_col = pick_header(mapping, ["tcp_flags", "client_tcp_flags", "server_tcp_flags"])
    iat_col = pick_header(mapping, ["sinpkt", "flow_iat_mean"])
    pps_col = pick_header(mapping, ["rate"])
    selected_columns = [
        in_bytes_col,
        out_bytes_col,
        in_pkts_col,
        out_pkts_col,
        duration_ms_col,
        ttl_a_col,
        ttl_b_col,
        http_col,
        dns_col,
        tcp_flags_col,
        iat_col,
        pps_col,
        label_column,
    ]

    feature_sources = {
        "packets_per_second": "derived:(in_pkts+out_pkts)/duration",
        "bytes_per_second": "derived:(in_bytes+out_bytes)/duration",
        "syn_ratio": f"derived:{tcp_flags_col or 'missing'}",
        "rst_ratio": f"derived:{tcp_flags_col or 'missing'}",
        "dst_port_entropy": "constant:0",
        "payload_byte_entropy": "constant:0",
        "unique_dst_ports": "constant:0",
        "avg_packet_size": "derived:(in_bytes+out_bytes)/(in_pkts+out_pkts)",
        "stddev_packet_size": "constant:0",
        "http_request_count": f"direct:{http_col or 'missing'}",
        "fin_ratio": f"derived:{tcp_flags_col or 'missing'}",
        "src_port_entropy": "constant:0",
        "unique_src_ports": "constant:0",
        "avg_ttl": f"derived:{ttl_a_col or ttl_b_col or 'missing'}",
        "stddev_ttl": f"derived:{ttl_a_col or ttl_b_col or 'missing'}",
        "avg_iat_us": f"direct:{iat_col or 'missing'}",
        "stddev_iat_us": "constant:0",
        "src_total_flows": "constant:0",
        "src_packets_per_second": "derived:in_pkts/duration",
        "dns_query_count": f"direct:{dns_col or 'missing'}",
    }

    def build_features(row: Dict[str, str]) -> List[float]:
        in_bytes = row_value(row, in_bytes_col, 0.0)
        out_bytes = row_value(row, out_bytes_col, 0.0)
        in_pkts = row_value(row, in_pkts_col, 0.0)
        out_pkts = row_value(row, out_pkts_col, 0.0)
        total_packets = in_pkts + out_pkts
        total_bytes = in_bytes + out_bytes
        duration_seconds = row_value(row, duration_ms_col, 0.0) / 1000.0
        packets_per_second = safe_div(total_packets, duration_seconds)
        bytes_per_second = safe_div(total_bytes, duration_seconds)
        if packets_per_second == 0.0:
            packets_per_second = row_value(row, pps_col, 0.0)
        syn_ratio, rst_ratio, fin_ratio = parse_tcp_flags(row.get(tcp_flags_col))
        ttl_a = row_value(row, ttl_a_col, 0.0)
        ttl_b = row_value(row, ttl_b_col, 0.0)
        avg_ttl = average_nonzero([ttl_a, ttl_b])
        std_ttl = abs(ttl_a - ttl_b) * 0.5 if ttl_a > 0.0 and ttl_b > 0.0 else 0.0

        return [
            packets_per_second,
            bytes_per_second,
            syn_ratio,
            rst_ratio,
            0.0,
            0.0,
            0.0,
            safe_div(total_bytes, total_packets),
            0.0,
            row_value(row, http_col, 0.0),
            fin_ratio,
            0.0,
            0.0,
            avg_ttl,
            std_ttl,
            row_value(row, iat_col, 0.0),
            0.0,
            0.0,
            safe_div(in_pkts, duration_seconds),
            row_value(row, dns_col, 0.0),
        ]

    if path.lower().endswith(".parquet"):
        chunk = load_parquet_rows(
            path,
            label_column,
            build_features,
            feature_sources,
            max_rows,
            selected_columns,
        )
    else:
        chunk = load_csv_rows(path, label_column, build_features, feature_sources, max_rows)
    if chunk:
        chunk.dataset_type = "nf_unsw_nb15_v2"
    return chunk

def load_unsw_nb15_csv(path: str, max_rows: int) -> Optional[DatasetChunk]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
    mapping = header_map(headers)
    label_column = resolve_label_column(mapping)
    if not label_column:
        return None

    duration_col = pick_header(mapping, ["dur"])
    sbytes_col = pick_header(mapping, ["sbytes"])
    dbytes_col = pick_header(mapping, ["dbytes"])
    spkts_col = pick_header(mapping, ["spkts"])
    dpkts_col = pick_header(mapping, ["dpkts"])
    rate_col = pick_header(mapping, ["rate"])
    sttl_col = pick_header(mapping, ["sttl"])
    dttl_col = pick_header(mapping, ["dttl"])
    sinpkt_col = pick_header(mapping, ["sinpkt"])
    sload_col = pick_header(mapping, ["sload"])
    dload_col = pick_header(mapping, ["dload"])
    smean_col = pick_header(mapping, ["smean"])
    dmean_col = pick_header(mapping, ["dmean"])
    http_col = pick_header(mapping, ["ct_flw_http_mthd", "ct_http_cmd"])
    dns_col = pick_header(mapping, ["ct_dns_query"])
    rst_col = pick_header(mapping, ["ct_rst_srv"])

    feature_sources = {
        "packets_per_second": f"direct:{rate_col or 'missing'}",
        "bytes_per_second": "derived:sload+dload_or_total_bytes/duration",
        "syn_ratio": "constant:0",
        "rst_ratio": f"derived:{rst_col or 'missing'}",
        "dst_port_entropy": "constant:0",
        "payload_byte_entropy": "constant:0",
        "unique_dst_ports": "constant:0",
        "avg_packet_size": "derived:smean_dmean_or_total_bytes/total_packets",
        "stddev_packet_size": "constant:0",
        "http_request_count": f"direct:{http_col or 'missing'}",
        "fin_ratio": "constant:0",
        "src_port_entropy": "constant:0",
        "unique_src_ports": "constant:0",
        "avg_ttl": f"derived:{sttl_col or dttl_col or 'missing'}",
        "stddev_ttl": f"derived:{sttl_col or dttl_col or 'missing'}",
        "avg_iat_us": f"direct:{sinpkt_col or 'missing'}",
        "stddev_iat_us": "constant:0",
        "src_total_flows": "constant:0",
        "src_packets_per_second": "derived:spkts/duration",
        "dns_query_count": f"direct:{dns_col or 'missing'}",
    }

    def build_features(row: Dict[str, str]) -> List[float]:
        sbytes = row_value(row, sbytes_col, 0.0)
        dbytes = row_value(row, dbytes_col, 0.0)
        spkts = row_value(row, spkts_col, 0.0)
        dpkts = row_value(row, dpkts_col, 0.0)
        total_bytes = sbytes + dbytes
        total_packets = spkts + dpkts
        duration = row_value(row, duration_col, 0.0)
        sload = row_value(row, sload_col, 0.0)
        dload = row_value(row, dload_col, 0.0)
        if sload > 0.0 or dload > 0.0:
            bytes_per_second = sload + dload
        elif duration > 0.0:
            bytes_per_second = safe_div(total_bytes, duration)
        else:
            bytes_per_second = 0.0
        avg_ttl = average_nonzero([row_value(row, sttl_col, 0.0), row_value(row, dttl_col, 0.0)])
        std_ttl = abs(row_value(row, sttl_col, 0.0) - row_value(row, dttl_col, 0.0)) * 0.5
        avg_packet_size = average_nonzero([row_value(row, smean_col, 0.0), row_value(row, dmean_col, 0.0)])
        if avg_packet_size == 0.0:
            avg_packet_size = safe_div(total_bytes, total_packets)
        packets_per_second = row_value(row, rate_col, 0.0)
        if packets_per_second == 0.0 and duration > 0.0:
            packets_per_second = safe_div(total_packets, duration)
        rst_indicator = 1.0 if row_value(row, rst_col, 0.0) > 0.0 else 0.0

        return [
            packets_per_second,
            bytes_per_second,
            0.0,
            rst_indicator,
            0.0,
            0.0,
            0.0,
            avg_packet_size,
            0.0,
            row_value(row, http_col, 0.0),
            0.0,
            0.0,
            0.0,
            avg_ttl,
            std_ttl,
            row_value(row, sinpkt_col, 0.0),
            0.0,
            0.0,
            safe_div(spkts, duration),
            row_value(row, dns_col, 0.0),
        ]

    chunk = load_csv_rows(path, label_column, build_features, feature_sources, max_rows)
    if chunk:
        chunk.dataset_type = "unsw_nb15"
    return chunk


def load_cicddos2019_csv(path: str, max_rows: int) -> Optional[DatasetChunk]:
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
    mapping = header_map(headers)
    label_column = resolve_label_column(mapping)
    if not label_column:
        return None

    pps_col = pick_header(mapping, ["flow_packets_s"])
    bps_col = pick_header(mapping, ["flow_bytes_s"])
    total_packets_col = pick_header(mapping, ["total_fwd_packets", "total_fwd_packet"])
    syn_col = pick_header(mapping, ["syn_flag_count", "syn_flag_cnt"])
    rst_col = pick_header(mapping, ["rst_flag_count", "rst_flag_cnt"])
    fin_col = pick_header(mapping, ["fin_flag_count", "fin_flag_cnt"])
    avg_size_col = pick_header(mapping, ["packet_length_mean", "fwd_packet_length_mean"])
    std_size_col = pick_header(mapping, ["packet_length_std", "fwd_packet_length_std"])
    iat_mean_col = pick_header(mapping, ["flow_iat_mean"])
    iat_std_col = pick_header(mapping, ["flow_iat_std", "fwd_iat_std"])
    fwd_pps_col = pick_header(mapping, ["fwd_packets_s", "flow_packets_s"])

    feature_sources = {
        "packets_per_second": f"direct:{pps_col or 'missing'}",
        "bytes_per_second": f"direct:{bps_col or 'missing'}",
        "syn_ratio": "derived:syn_flag_count/total_fwd_packets",
        "rst_ratio": "derived:rst_flag_count/total_fwd_packets",
        "dst_port_entropy": "constant:0",
        "payload_byte_entropy": "constant:0",
        "unique_dst_ports": "constant:0",
        "avg_packet_size": f"direct:{avg_size_col or 'missing'}",
        "stddev_packet_size": f"direct:{std_size_col or 'missing'}",
        "http_request_count": "constant:0",
        "fin_ratio": "derived:fin_flag_count/total_fwd_packets",
        "src_port_entropy": "constant:0",
        "unique_src_ports": "constant:0",
        "avg_ttl": "constant:0",
        "stddev_ttl": "constant:0",
        "avg_iat_us": f"direct:{iat_mean_col or 'missing'}",
        "stddev_iat_us": f"direct:{iat_std_col or 'missing'}",
        "src_total_flows": "constant:0",
        "src_packets_per_second": f"direct:{fwd_pps_col or 'missing'}",
        "dns_query_count": "constant:0",
    }

    def build_features(row: Dict[str, str]) -> List[float]:
        total_packets = row_value(row, total_packets_col, 0.0)
        return [
            row_value(row, pps_col, 0.0),
            row_value(row, bps_col, 0.0),
            safe_ratio(row_value(row, syn_col, 0.0), total_packets),
            safe_ratio(row_value(row, rst_col, 0.0), total_packets),
            0.0,
            0.0,
            0.0,
            row_value(row, avg_size_col, 0.0),
            row_value(row, std_size_col, 0.0),
            0.0,
            safe_ratio(row_value(row, fin_col, 0.0), total_packets),
            0.0,
            0.0,
            0.0,
            0.0,
            row_value(row, iat_mean_col, 0.0),
            row_value(row, iat_std_col, 0.0),
            0.0,
            row_value(row, fwd_pps_col, 0.0),
            0.0,
        ]

    chunk = load_csv_rows(path, label_column, build_features, feature_sources, max_rows)
    if chunk:
        chunk.dataset_type = "cicddos2019"
    return chunk


def load_sentinel_feature_json(path: str, max_rows: int) -> Optional[DatasetChunk]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        payload = json.load(handle)
    rows = payload.get("samples", []) if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        return None

    X_rows: List[List[float]] = []
    y_list: List[int] = []
    label_examples: List[str] = []
    examples_seen = set()

    for row_index, row in enumerate(rows):
        if max_rows and row_index >= max_rows:
            break
        if not isinstance(row, dict):
            continue
        raw_label = row.get("label", row.get("attack", row.get("class")))
        label = parse_binary_label(raw_label)
        if label is None:
            continue
        X_rows.append([safe_float(row.get(name), 0.0) for name in FEATURE_NAMES])
        y_list.append(label)
        example = capture_label_example(raw_label)
        if example and example not in examples_seen and len(label_examples) < 6:
            examples_seen.add(example)
            label_examples.append(example)

    if not X_rows:
        return None

    return DatasetChunk(
        path=path,
        dataset_type="sentinel_features",
        split_hint=infer_split_hint(path),
        label_column="label",
        label_examples=tuple(label_examples),
        feature_sources={name: f"direct:{name}" for name in FEATURE_NAMES},
        X=np.asarray(X_rows, dtype=np.float64),
        y=np.asarray(y_list, dtype=np.int64),
    )


def load_sdn_portblocking_csv(path: str, max_rows: int) -> Optional[DatasetChunk]:
    X_rows: List[List[float]] = []
    y_list: List[int] = []
    label_examples: List[str] = []
    examples_seen = set()

    feature_sources = {
        "packets_per_second": "direct:col0",
        "bytes_per_second": "derived:col0*64",
        "syn_ratio": "direct:col2",
        "rst_ratio": "derived:col1/(col0+1)",
        "dst_port_entropy": "constant:0",
        "payload_byte_entropy": "constant:0",
        "unique_dst_ports": "direct:col1",
        "avg_packet_size": "constant:64",
        "stddev_packet_size": "derived:abs(col0-col1)",
        "http_request_count": "constant:0",
        "fin_ratio": "constant:0",
        "src_port_entropy": "constant:0",
        "unique_src_ports": "direct:col1",
        "avg_ttl": "constant:0",
        "stddev_ttl": "constant:0",
        "avg_iat_us": "derived:1e6/(col0+1)",
        "stddev_iat_us": "constant:0",
        "src_total_flows": "direct:col1",
        "src_packets_per_second": "direct:col0",
        "dns_query_count": "constant:0",
    }

    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        for row_index, row in enumerate(reader):
            if max_rows and row_index >= max_rows:
                break
            if len(row) < 4:
                continue

            c0 = safe_float(row[0], 0.0)
            c1 = safe_float(row[1], 0.0)
            c2 = safe_float(row[2], 0.0)
            label = parse_binary_label(row[3])
            if label is None:
                continue

            syn_ratio = c2 if 0.0 <= c2 <= 1.0 else max(0.0, min(1.0, c2 / 100.0))
            pps = max(0.0, c0)
            ports = max(0.0, c1)

            features = [
                pps,
                pps * 64.0,
                syn_ratio,
                safe_ratio(ports, pps + 1.0),
                0.0,
                0.0,
                ports,
                64.0,
                abs(pps - ports),
                0.0,
                0.0,
                0.0,
                ports,
                0.0,
                0.0,
                safe_div(1_000_000.0, pps + 1.0),
                0.0,
                ports,
                pps,
                0.0,
            ]

            X_rows.append(features)
            y_list.append(label)

            example = capture_label_example(row[3])
            if example and example not in examples_seen and len(label_examples) < 6:
                examples_seen.add(example)
                label_examples.append(example)

    if not X_rows:
        return None

    return DatasetChunk(
        path=path,
        dataset_type="sdn_portblocking",
        split_hint=infer_split_hint(path),
        label_column="col3",
        label_examples=tuple(label_examples),
        feature_sources=feature_sources,
        X=np.asarray(X_rows, dtype=np.float64),
        y=np.asarray(y_list, dtype=np.int64),
    )


LOADERS: Dict[str, Callable[[str, int], Optional[DatasetChunk]]] = {
    "sentinel_features": load_sentinel_feature_csv,
    "sentinel_json": load_sentinel_feature_json,
    "ciciot2023": load_ciciot2023_csv,
    "nf_unsw_nb15_v2": load_nf_unsw_nb15_v2,
    "unsw_nb15": load_unsw_nb15_csv,
    "cicddos2019": load_cicddos2019_csv,
    "sdn_portblocking": load_sdn_portblocking_csv,
}


def chunk_summary(chunk: DatasetChunk) -> str:
    counts = chunk.class_counts
    labels = ", ".join(chunk.label_examples) if chunk.label_examples else "n/a"
    return (
        f"  Loaded {chunk.dataset_type}: {chunk.path} "
        f"({len(chunk.y)} rows, Normal: {counts.get(0, 0)}, Attack: {counts.get(1, 0)}, "
        f"split={chunk.split_hint}, grounded={chunk.grounded_feature_count}/{NUM_FEATURES}, "
        f"labels=[{labels}])"
    )


def determine_data_dirs(
    explicit_data_dirs: Optional[Sequence[str]] = None,
    auto_repo_data: Optional[bool] = None,
) -> List[str]:
    repo_root = os.path.dirname(__file__)

    def normalize_dirs(paths: Sequence[str]) -> List[str]:
        result: List[str] = []
        seen = set()
        for item in paths:
            if not item:
                continue
            p = item if os.path.isabs(item) else os.path.join(repo_root, item)
            p = os.path.normpath(p)
            if p in seen:
                continue
            if os.path.isdir(p):
                seen.add(p)
                result.append(p)
        return result

    def discover_data_dirs() -> List[str]:
        discovered: List[str] = []
        for entry in sorted(os.listdir(repo_root)):
            if entry.startswith("."):
                continue
            candidate = os.path.join(repo_root, entry)
            if not os.path.isdir(candidate):
                continue
            if entry in {"frontend", "__pycache__"}:
                continue
            if os.path.isdir(os.path.join(candidate, "dataresearch")):
                discovered.append(os.path.join(candidate, "dataresearch"))
                discovered.append(candidate)
                continue
            try:
                file_count = len(glob.glob(os.path.join(candidate, "*.csv")))
                file_count += len(glob.glob(os.path.join(candidate, "*.parquet")))
            except OSError:
                file_count = 0
            if file_count > 0:
                discovered.append(candidate)
        return discovered

    if auto_repo_data is None:
        auto_repo_data = os.environ.get("SENTINEL_AUTO_REPO_DATA", "0") == "1"

    if explicit_data_dirs is not None:
        directories = list(explicit_data_dirs)
    else:
        env_value = os.environ.get("SENTINEL_DATA_DIRS", "").strip()
        directories = [path for path in env_value.split(os.pathsep) if path] if env_value else list(AUTO_DATA_DIR_CANDIDATES)

    if auto_repo_data:
        directories.extend(discover_data_dirs())

    return normalize_dirs(directories)


def determine_required_dataset_types() -> Tuple[str, ...]:
    env_value = os.environ.get(
        "SENTINEL_REQUIRED_DATASETS",
        ",".join(DEFAULT_REQUIRED_DATASET_TYPES),
    ).strip()
    if not env_value:
        return tuple()
    dataset_types = []
    for item in env_value.split(","):
        normalized = normalize_name(item)
        if normalized and normalized not in dataset_types:
            dataset_types.append(normalized)
    return tuple(dataset_types)


def split_sort_key(path: str) -> Tuple[int, str]:
    split_hint = infer_split_hint(path)
    return SPLIT_PRIORITY.get(split_hint, SPLIT_PRIORITY["unspecified"]), path.lower()


def summarize_dataset_families(chunks: Sequence[DatasetChunk]) -> Dict[str, Counter]:
    summary: Dict[str, Counter] = defaultdict(Counter)
    for chunk in chunks:
        summary[chunk.dataset_type].update(chunk.class_counts)
        summary[chunk.dataset_type]["rows"] += len(chunk.y)
    return summary


def print_dataset_family_summary(chunks: Sequence[DatasetChunk]) -> None:
    summary = summarize_dataset_families(chunks)
    if not summary:
        return
    print("[*] Dataset family coverage:")
    for dataset_type in sorted(summary):
        counts = summary[dataset_type]
        print(
            f"  {dataset_type}: rows={counts.get('rows', 0)}, "
            f"Normal={counts.get(0, 0)}, Attack={counts.get(1, 0)}"
        )


def audit_dataset_inventory(data_dirs: Optional[Sequence[str]] = None) -> None:
    if data_dirs is None:
        data_dirs = determine_data_dirs()

    discovered: Dict[str, int] = Counter()
    unknown_files: List[str] = []
    total_files = 0

    for base_dir in data_dirs:
        if not os.path.isdir(base_dir):
            print(f"[*] Data directory missing: {base_dir}")
            continue
        file_paths = []
        file_paths.extend(glob.glob(os.path.join(base_dir, "**", "*.csv"), recursive=True))
        file_paths.extend(glob.glob(os.path.join(base_dir, "**", "*.json"), recursive=True))
        file_paths.extend(glob.glob(os.path.join(base_dir, "**", "*.parquet"), recursive=True))
        for path in sorted(file_paths):
            total_files += 1
            dataset_type = detect_dataset_type(path)
            if dataset_type:
                discovered[dataset_type] += 1
            else:
                unknown_files.append(path)

    print(f"[*] Dataset inventory: scanned {total_files} CSV/JSON/Parquet files")
    if discovered:
        for dataset_type in sorted(discovered):
            print(f"  {dataset_type}: {discovered[dataset_type]} files")
    else:
        print("  No supported dataset families detected")

    if unknown_files:
        print("[*] Unsupported or unrecognized files:")
        for path in unknown_files[:20]:
            print(f"  {path}")
        if len(unknown_files) > 20:
            print(f"  ... and {len(unknown_files) - 20} more")


def gather_datasets(data_dirs: Optional[Sequence[str]] = None, min_total: int = 100000) -> List[DatasetChunk]:
    if data_dirs is None:
        data_dirs = determine_data_dirs()

    required_dataset_types = determine_required_dataset_types()
    max_rows_per_file = int(os.environ.get("SENTINEL_MAX_ROWS_PER_FILE", "100000"))
    max_total_rows = int(os.environ.get("SENTINEL_MAX_TOTAL_ROWS", "600000"))

    chunks: List[DatasetChunk] = []
    skipped: List[str] = []
    seen_paths = set()
    accepted_rows = 0
    accepted_rows_by_type: Counter = Counter()

    file_paths: List[str] = []
    for base_dir in data_dirs:
        if not os.path.isdir(base_dir):
            continue
        file_paths.extend(glob.glob(os.path.join(base_dir, "**", "*.csv"), recursive=True))
        file_paths.extend(glob.glob(os.path.join(base_dir, "**", "*.json"), recursive=True))
        file_paths.extend(glob.glob(os.path.join(base_dir, "**", "*.parquet"), recursive=True))

    dataset_files: Dict[str, List[str]] = defaultdict(list)
    for path in sorted(file_paths):
        abs_path = os.path.abspath(path)
        if abs_path in seen_paths:
            continue
        seen_paths.add(abs_path)

        dataset_type = detect_dataset_type(path)
        if not dataset_type:
            skipped.append(f"  Skipped unsupported schema: {path}")
            continue
        dataset_files[dataset_type].append(path)

    missing_required = [dataset_type for dataset_type in required_dataset_types if dataset_type not in dataset_files]
    if missing_required:
        discovered_families = ", ".join(sorted(dataset_files)) if dataset_files else "none"
        hint = ""
        if "unsw_nb15" in dataset_files and "nf_unsw_nb15_v2" in missing_required:
            hint = (
                " Found UNSW-NB15 files, but not the NF-UNSW-NB15-v2 schema. "
                "Check the Colab download slug; it should be dhoogla/nfunswnb15v2."
            )
        raise RuntimeError(
            "Missing required dataset families: "
            + ", ".join(missing_required)
            + f". Discovered dataset families: {discovered_families}."
            + " Download both CICIoT2023 and NF-UNSW-NB15-v2 before training."
            + hint
        )

    active_dataset_types = list(required_dataset_types)
    for dataset_type in sorted(dataset_files):
        if dataset_type not in active_dataset_types:
            active_dataset_types.append(dataset_type)

    if not active_dataset_types:
        raise RuntimeError("No supported real dataset files were discovered under the configured data directories.")

    for dataset_type, paths in dataset_files.items():
        paths.sort(key=split_sort_key)

    dataset_caps: Dict[str, int] = {}
    base_cap = max_total_rows // len(active_dataset_types)
    remainder = max_total_rows % len(active_dataset_types)
    for index, dataset_type in enumerate(active_dataset_types):
        dataset_caps[dataset_type] = base_cap + (1 if index < remainder else 0)

    next_index = {dataset_type: 0 for dataset_type in active_dataset_types}
    progress = True
    while accepted_rows < max_total_rows and progress:
        progress = False
        for dataset_type in active_dataset_types:
            if accepted_rows >= max_total_rows:
                break
            paths = dataset_files.get(dataset_type, [])
            if next_index[dataset_type] >= len(paths):
                continue
            remaining_type_budget = dataset_caps[dataset_type] - accepted_rows_by_type[dataset_type]
            if remaining_type_budget <= 0:
                continue

            path = paths[next_index[dataset_type]]
            next_index[dataset_type] += 1

            loader = LOADERS[dataset_type]
            remaining_budget = min(max_total_rows - accepted_rows, remaining_type_budget)
            try:
                chunk = loader(path, max_rows=min(max_rows_per_file, remaining_budget))
            except Exception as exc:
                skipped.append(f"  Skipped {path}: loader error: {exc}")
                continue

            if not chunk:
                skipped.append(f"  Skipped {path}: no usable labeled rows")
                continue
            if chunk.grounded_feature_count < MIN_MAPPED_FEATURES:
                skipped.append(
                    f"  Skipped {path}: only {chunk.grounded_feature_count}/{NUM_FEATURES} grounded features"
                )
                continue

            chunks.append(chunk)
            accepted_rows += len(chunk.y)
            accepted_rows_by_type[dataset_type] += len(chunk.y)
            progress = True
            print(chunk_summary(chunk))

    if accepted_rows >= max_total_rows:
        print(f"[*] Reached row budget ({max_total_rows}); stopping additional file ingestion.")

    if skipped:
        print("[*] File audit:")
        for item in skipped:
            print(item)

    if not chunks:
        raise RuntimeError("No supported real dataset files were accepted under the configured data directories.")

    total_rows = sum(len(chunk.y) for chunk in chunks)
    if total_rows < min_total:
        raise RuntimeError(f"Insufficient accepted real samples: {total_rows} < required {min_total}.")

    total_counts = Counter()
    for chunk in chunks:
        total_counts.update(chunk.class_counts)
    if len(total_counts) < 2 or min(total_counts.values()) == 0:
        raise RuntimeError(
            "Refusing to train on a single-class corpus. The accepted files did not contain both benign and attack "
            "labels after schema validation."
        )

    per_family_summary = summarize_dataset_families(chunks)
    for dataset_type in required_dataset_types:
        family_counts = per_family_summary.get(dataset_type, Counter())
        if family_counts.get("rows", 0) == 0:
            raise RuntimeError(f"Required dataset family {dataset_type} contributed no accepted rows.")
        if family_counts.get(0, 0) == 0 or family_counts.get(1, 0) == 0:
            raise RuntimeError(
                f"Required dataset family {dataset_type} is single-class after validation. "
                "Both benign and attack labels are required in each dataset family."
            )

    return chunks

def concat_chunks(chunks: Sequence[DatasetChunk]) -> Tuple[np.ndarray, np.ndarray]:
    return np.vstack([chunk.X for chunk in chunks]), np.concatenate([chunk.y for chunk in chunks])


def has_both_classes(labels: np.ndarray) -> bool:
    counts = Counter(int(v) for v in labels.tolist())
    return counts.get(0, 0) > 0 and counts.get(1, 0) > 0


def empty_xy() -> Tuple[np.ndarray, np.ndarray]:
    return np.empty((0, NUM_FEATURES), dtype=np.float64), np.empty((0,), dtype=np.int64)


def concat_chunks_or_empty(chunks: Sequence[DatasetChunk]) -> Tuple[np.ndarray, np.ndarray]:
    if not chunks:
        return empty_xy()
    return concat_chunks(chunks)


def combine_xy_parts(parts: Sequence[Tuple[np.ndarray, np.ndarray]]) -> Tuple[np.ndarray, np.ndarray]:
    kept = [(X, y) for X, y in parts if len(y) > 0]
    if not kept:
        return empty_xy()
    return np.vstack([X for X, _ in kept]), np.concatenate([y for _, y in kept])


def split_row_view(X: np.ndarray, y: np.ndarray, decimals: int = 6) -> np.ndarray:
    rounded = np.round(np.asarray(X, dtype=np.float32), decimals=decimals)
    labels = np.asarray(y, dtype=np.float32).reshape(-1, 1)
    merged = np.ascontiguousarray(np.concatenate([rounded, labels], axis=1))
    dtype = np.dtype((np.void, merged.dtype.itemsize * merged.shape[1]))
    return merged.view(dtype).ravel()


def safe_train_test_split(
    indices: np.ndarray,
    labels: np.ndarray,
    test_size: float,
) -> Tuple[np.ndarray, np.ndarray]:
    if test_size <= 0.0 or test_size >= 1.0:
        raise ValueError(f"test_size must be between 0 and 1, got {test_size}")
    labels = np.asarray(labels, dtype=np.int64)
    label_counts = Counter(int(v) for v in labels.tolist())
    stratify = labels if len(label_counts) > 1 and min(label_counts.values()) >= 2 else None
    return train_test_split(
        indices,
        test_size=test_size,
        stratify=stratify,
        random_state=RANDOM_STATE,
    )


def assign_unique_groups(
    inverse: np.ndarray,
    X: np.ndarray,
    y: np.ndarray,
    group_ids: np.ndarray,
) -> Tuple[np.ndarray, np.ndarray]:
    mask = np.isin(inverse, group_ids)
    if not np.any(mask):
        return empty_xy()
    return X[mask], y[mask]


def grouped_train_validation_split(
    X: np.ndarray,
    y: np.ndarray,
    validation_size: float = 0.15,
) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
    if len(y) == 0:
        return {"train": empty_xy(), "validation": empty_xy()}

    row_keys = split_row_view(X, y)
    unique_keys, first_indices, inverse = np.unique(row_keys, return_index=True, return_inverse=True)
    unique_labels = y[first_indices]
    unique_indices = np.arange(len(unique_keys))

    train_unique, validation_unique = safe_train_test_split(unique_indices, unique_labels, validation_size)
    return {
        "train": assign_unique_groups(inverse, X, y, train_unique),
        "validation": assign_unique_groups(inverse, X, y, validation_unique),
    }


def grouped_unique_split(
    X: np.ndarray,
    y: np.ndarray,
    test_size: float = 0.20,
    validation_size: float = 0.15,
) -> Dict[str, Tuple[np.ndarray, np.ndarray]]:
    if len(y) == 0:
        return {"train": empty_xy(), "validation": empty_xy(), "test": empty_xy()}

    row_keys = split_row_view(X, y)
    unique_keys, first_indices, inverse = np.unique(row_keys, return_index=True, return_inverse=True)
    unique_labels = y[first_indices]
    unique_indices = np.arange(len(unique_keys))

    train_val_unique, test_unique = safe_train_test_split(unique_indices, unique_labels, test_size)
    train_unique, validation_unique = safe_train_test_split(
        train_val_unique,
        unique_labels[train_val_unique],
        validation_size,
    )

    return {
        "train": assign_unique_groups(inverse, X, y, train_unique),
        "validation": assign_unique_groups(inverse, X, y, validation_unique),
        "test": assign_unique_groups(inverse, X, y, test_unique),
    }


def filter_rows_by_blocked_keys(
    X: np.ndarray,
    y: np.ndarray,
    blocked_keys: np.ndarray,
) -> Tuple[np.ndarray, np.ndarray, int]:
    if len(y) == 0 or len(blocked_keys) == 0:
        return X, y, 0
    row_keys = split_row_view(X, y)
    keep_mask = ~np.isin(row_keys, blocked_keys)
    removed_rows = int(len(keep_mask) - np.count_nonzero(keep_mask))
    return X[keep_mask], y[keep_mask], removed_rows


def deduplicate_family_splits(
    train_xy: Tuple[np.ndarray, np.ndarray],
    validation_xy: Tuple[np.ndarray, np.ndarray],
    test_xy: Tuple[np.ndarray, np.ndarray],
) -> Tuple[Dict[str, Tuple[np.ndarray, np.ndarray]], Dict[str, int]]:
    X_test, y_test = test_xy
    X_validation, y_validation = validation_xy
    X_train, y_train = train_xy

    test_keys = np.unique(split_row_view(X_test, y_test)) if len(y_test) > 0 else np.empty((0,), dtype=np.void)
    X_validation, y_validation, removed_validation = filter_rows_by_blocked_keys(X_validation, y_validation, test_keys)

    validation_keys = (
        np.unique(split_row_view(X_validation, y_validation))
        if len(y_validation) > 0
        else np.empty((0,), dtype=np.void)
    )
    blocked_for_train = np.union1d(test_keys, validation_keys)
    X_train, y_train, removed_train = filter_rows_by_blocked_keys(X_train, y_train, blocked_for_train)

    return (
        {
            "train": (X_train, y_train),
            "validation": (X_validation, y_validation),
            "test": (X_test, y_test),
        },
        {
            "train": removed_train,
            "validation": removed_validation,
            "test": 0,
        },
    )


def split_map_has_all_classes(split_map: Dict[str, Tuple[np.ndarray, np.ndarray]]) -> bool:
    for split_name in ("train", "validation", "test"):
        _, y = split_map[split_name]
        if len(y) == 0 or not has_both_classes(y):
            return False
    return True


def summarize_split_counts(X: np.ndarray, y: np.ndarray) -> str:
    counts = Counter(int(v) for v in y.tolist())
    return f"rows={len(y)}, Normal={counts.get(0, 0)}, Attack={counts.get(1, 0)}"


def build_family_split_map(
    chunks: Sequence[DatasetChunk],
) -> Tuple[Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]], Dict[str, str], Dict[str, Dict[str, int]]]:
    families = sorted({chunk.dataset_type for chunk in chunks})
    family_splits: Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]] = {}
    family_strategies: Dict[str, str] = {}
    overlap_removed_rows: Dict[str, Dict[str, int]] = {}

    for dataset_type in families:
        family_chunks = [chunk for chunk in chunks if chunk.dataset_type == dataset_type]
        train_chunks = [chunk for chunk in family_chunks if chunk.split_hint == "train"]
        validation_chunks = [chunk for chunk in family_chunks if chunk.split_hint == "validation"]
        test_chunks = [chunk for chunk in family_chunks if chunk.split_hint == "test"]
        unspecified_chunks = [chunk for chunk in family_chunks if chunk.split_hint == "unspecified"]
        train_xy = concat_chunks_or_empty(train_chunks)
        validation_xy = concat_chunks_or_empty(validation_chunks)
        test_xy = concat_chunks_or_empty(test_chunks)
        unspecified_xy = concat_chunks_or_empty(unspecified_chunks)

        if train_chunks and test_chunks:
            train_xy = combine_xy_parts([train_xy, unspecified_xy])
            if validation_chunks:
                strategy = "provided train/validation/test"
            else:
                derived = grouped_train_validation_split(*train_xy, validation_size=0.15)
                train_xy = derived["train"]
                validation_xy = derived["validation"]
                strategy = "provided test with derived validation"
            split_map, removed = deduplicate_family_splits(train_xy, validation_xy, test_xy)
            if not split_map_has_all_classes(split_map):
                X_all, y_all = combine_xy_parts([train_xy, validation_xy, test_xy])
                split_map = grouped_unique_split(X_all, y_all)
                removed = {"train": 0, "validation": 0, "test": 0}
                strategy = "re-derived train/validation/test from unique rows"
        else:
            X_all, y_all = combine_xy_parts([train_xy, validation_xy, test_xy, unspecified_xy])
            split_map = grouped_unique_split(X_all, y_all)
            removed = {"train": 0, "validation": 0, "test": 0}
            strategy = "derived train/validation/test from unique rows"

        family_splits[dataset_type] = split_map
        family_strategies[dataset_type] = strategy
        overlap_removed_rows[dataset_type] = removed

    return family_splits, family_strategies, overlap_removed_rows


def global_unique_keys_for_split(
    family_splits: Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]],
    split_name: str,
) -> np.ndarray:
    key_parts: List[np.ndarray] = []
    for dataset_type in sorted(family_splits):
        X_part, y_part = family_splits[dataset_type][split_name]
        if len(y_part) == 0:
            continue
        key_parts.append(np.unique(split_row_view(X_part, y_part)))
    if not key_parts:
        return np.empty((0,), dtype=np.void)
    return np.unique(np.concatenate(key_parts))


def deduplicate_global_family_splits(
    family_splits: Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]],
    overlap_removed_rows: Dict[str, Dict[str, int]],
) -> Tuple[Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]], Dict[str, Dict[str, int]]]:
    test_keys = global_unique_keys_for_split(family_splits, "test")
    for dataset_type in sorted(family_splits):
        X_validation, y_validation = family_splits[dataset_type]["validation"]
        X_validation, y_validation, removed = filter_rows_by_blocked_keys(X_validation, y_validation, test_keys)
        family_splits[dataset_type]["validation"] = (X_validation, y_validation)
        overlap_removed_rows[dataset_type]["validation"] += removed

    blocked_train_keys = np.union1d(test_keys, global_unique_keys_for_split(family_splits, "validation"))
    for dataset_type in sorted(family_splits):
        X_train, y_train = family_splits[dataset_type]["train"]
        X_train, y_train, removed = filter_rows_by_blocked_keys(X_train, y_train, blocked_train_keys)
        family_splits[dataset_type]["train"] = (X_train, y_train)
        overlap_removed_rows[dataset_type]["train"] += removed

    return family_splits, overlap_removed_rows


def aggregate_split(
    family_splits: Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]],
    split_name: str,
) -> Tuple[np.ndarray, np.ndarray]:
    return combine_xy_parts([family_splits[dataset_type][split_name] for dataset_type in sorted(family_splits)])


def aggregate_split_with_family(
    family_splits: Dict[str, Dict[str, Tuple[np.ndarray, np.ndarray]]],
    split_name: str,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    X_parts: List[np.ndarray] = []
    y_parts: List[np.ndarray] = []
    family_parts: List[np.ndarray] = []
    for dataset_type in sorted(family_splits):
        X_part, y_part = family_splits[dataset_type][split_name]
        if len(y_part) == 0:
            continue
        X_parts.append(X_part)
        y_parts.append(y_part)
        family_parts.append(np.full(len(y_part), dataset_type, dtype=object))
    if not y_parts:
        return empty_xy()[0], empty_xy()[1], np.empty((0,), dtype=object)
    return np.vstack(X_parts), np.concatenate(y_parts), np.concatenate(family_parts)


def build_split_plan(chunks: Sequence[DatasetChunk]) -> SplitPlan:
    family_splits, family_strategies, overlap_removed_rows = build_family_split_map(chunks)
    family_splits, overlap_removed_rows = deduplicate_global_family_splits(family_splits, overlap_removed_rows)
    return SplitPlan(
        strategy="family-aware mixed split",
        family_splits=family_splits,
        family_strategies=family_strategies,
        overlap_removed_rows=overlap_removed_rows,
    )


def build_splits(chunks: Sequence[DatasetChunk]) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray, str]:
    split_plan = build_split_plan(chunks)
    X_train, y_train = aggregate_split(split_plan.family_splits, "train")
    X_val, y_val = aggregate_split(split_plan.family_splits, "validation")
    X_test, y_test = aggregate_split(split_plan.family_splits, "test")
    return X_train, y_train, X_val, y_val, X_test, y_test, split_plan.strategy


def print_split_plan_summary(split_plan: SplitPlan) -> None:
    print("[*] Family split plan:")
    for dataset_type in sorted(split_plan.family_splits):
        split_map = split_plan.family_splits[dataset_type]
        removed = split_plan.overlap_removed_rows[dataset_type]
        print(
            f"  {dataset_type}: {split_plan.family_strategies[dataset_type]}; "
            f"train[{summarize_split_counts(*split_map['train'])}], "
            f"validation[{summarize_split_counts(*split_map['validation'])}], "
            f"test[{summarize_split_counts(*split_map['test'])}], "
            f"overlap-removed(train={removed['train']}, validation={removed['validation']}, test={removed['test']})"
        )


def overlap_count(X_a: np.ndarray, y_a: np.ndarray, X_b: np.ndarray, y_b: np.ndarray) -> int:
    if len(y_a) == 0 or len(y_b) == 0:
        return 0
    left = np.unique(split_row_view(X_a, y_a))
    right = np.unique(split_row_view(X_b, y_b))
    return int(np.intersect1d(left, right).size)


def audit_split_leakage(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, int]:
    return {
        "train_vs_validation": overlap_count(X_train, y_train, X_val, y_val),
        "train_vs_test": overlap_count(X_train, y_train, X_test, y_test),
        "validation_vs_test": overlap_count(X_val, y_val, X_test, y_test),
    }


def print_leakage_audit(overlap_summary: Dict[str, int]) -> None:
    print("[*] Duplicate-row leakage audit:")
    for pair_name, count in overlap_summary.items():
        print(f"  {pair_name}: {count} exact engineered-row overlaps")


def chunks_for_dataset_type(chunks: Sequence[DatasetChunk], dataset_type: str) -> List[DatasetChunk]:
    return [chunk for chunk in chunks if chunk.dataset_type == dataset_type]


def summarize_family_class_counts(y: np.ndarray, family_ids: np.ndarray) -> str:
    lines = []
    for dataset_type in sorted({str(item) for item in family_ids.tolist()}):
        mask = family_ids == dataset_type
        counts = Counter(int(v) for v in y[mask].tolist())
        lines.append(f"{dataset_type}(Normal={counts.get(0, 0)}, Attack={counts.get(1, 0)})")
    return "; ".join(lines)


def rebalance_training_data(
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[np.ndarray, np.ndarray, Optional[np.ndarray], Optional[str]]:
    max_ratio = float(os.environ.get("SENTINEL_MAX_CLASS_RATIO", "4.0"))
    if family_ids is not None and len(family_ids) != len(y):
        raise ValueError("family_ids length must match y length")
    counts = Counter(int(v) for v in y.tolist())
    if len(counts) < 2:
        return X, y, family_ids, None

    if family_ids is not None and len(family_ids) > 0:
        family_ids = np.asarray(family_ids, dtype=object)
        bucket_counts: Counter = Counter((str(family), int(label)) for family, label in zip(family_ids.tolist(), y.tolist()))
        capped_sizes: Dict[Tuple[str, int], int] = {}
        needs_rebalance = False
        for dataset_type in sorted({str(item) for item in family_ids.tolist()}):
            family_count_0 = bucket_counts.get((dataset_type, 0), 0)
            family_count_1 = bucket_counts.get((dataset_type, 1), 0)
            present_counts = [count for count in (family_count_0, family_count_1) if count > 0]
            if not present_counts:
                continue
            family_minority = min(present_counts)
            family_cap = int(max(1, round(family_minority * max_ratio)))
            for label in (0, 1):
                original_count = bucket_counts.get((dataset_type, label), 0)
                capped_sizes[(dataset_type, label)] = min(original_count, family_cap)
                if original_count > capped_sizes[(dataset_type, label)]:
                    needs_rebalance = True

        if not needs_rebalance:
            return X, y, family_ids, None

        rng = np.random.default_rng(RANDOM_STATE)
        keep_indices: List[np.ndarray] = []
        for dataset_type in sorted({str(item) for item in family_ids.tolist()}):
            for label in (0, 1):
                label_indices = np.flatnonzero((family_ids == dataset_type) & (y == label))
                target_size = capped_sizes.get((dataset_type, label), len(label_indices))
                if len(label_indices) > target_size:
                    keep_indices.append(np.sort(rng.choice(label_indices, size=target_size, replace=False)))
                elif len(label_indices) > 0:
                    keep_indices.append(label_indices)

        merged = np.sort(np.concatenate(keep_indices))
        before = summarize_family_class_counts(y, family_ids)
        after_family_ids = family_ids[merged]
        after = summarize_family_class_counts(y[merged], after_family_ids)
        return (
            X[merged],
            y[merged],
            after_family_ids,
            f"rebalanced training subset by dataset family/class from {before} to {after}",
        )

    minority_count = min(counts.values())
    cap = int(max(1, round(minority_count * max_ratio)))
    if max(counts.values()) <= cap:
        return X, y, family_ids, None

    rng = np.random.default_rng(RANDOM_STATE)
    keep_indices: List[np.ndarray] = []
    for label in sorted(counts):
        label_indices = np.flatnonzero(y == label)
        if len(label_indices) > cap:
            keep_indices.append(np.sort(rng.choice(label_indices, size=cap, replace=False)))
        else:
            keep_indices.append(label_indices)
    merged = np.sort(np.concatenate(keep_indices))
    before = f"Normal={counts.get(0, 0)}, Attack={counts.get(1, 0)}"
    after_counts = Counter(int(v) for v in y[merged].tolist())
    after = f"Normal={after_counts.get(0, 0)}, Attack={after_counts.get(1, 0)}"
    rebalanced_family_ids = family_ids[merged] if family_ids is not None else None
    return X[merged], y[merged], rebalanced_family_ids, f"rebalanced training subset from {before} to {after}"


def evaluate_model(clf: RandomForestClassifier, X: np.ndarray, y: np.ndarray) -> Dict[str, object]:
    predictions = clf.predict(X)
    probabilities = clf.predict_proba(X)[:, 1] if hasattr(clf, "predict_proba") else None
    class_precision, class_recall, class_f1, class_support = precision_recall_fscore_support(
        y,
        predictions,
        labels=[0, 1],
        zero_division=0,
    )
    metrics: Dict[str, object] = {
        "accuracy": accuracy_score(y, predictions),
        "balanced_accuracy": balanced_accuracy_score(y, predictions),
        "precision": precision_score(y, predictions, zero_division=0),
        "recall": recall_score(y, predictions, zero_division=0),
        "f1": f1_score(y, predictions, zero_division=0),
        "macro_precision": precision_score(y, predictions, average="macro", zero_division=0),
        "macro_recall": recall_score(y, predictions, average="macro", zero_division=0),
        "macro_f1": f1_score(y, predictions, average="macro", zero_division=0),
        "weighted_f1": f1_score(y, predictions, average="weighted", zero_division=0),
        "mcc": matthews_corrcoef(y, predictions),
        "confusion_matrix": confusion_matrix(y, predictions, labels=[0, 1]),
        "class_breakdown": {
            "normal": {
                "precision": float(class_precision[0]),
                "recall": float(class_recall[0]),
                "f1": float(class_f1[0]),
                "support": int(class_support[0]),
            },
            "attack": {
                "precision": float(class_precision[1]),
                "recall": float(class_recall[1]),
                "f1": float(class_f1[1]),
                "support": int(class_support[1]),
            },
        },
    }
    if probabilities is not None and has_both_classes(y):
        metrics["roc_auc"] = roc_auc_score(y, probabilities)
    else:
        metrics["roc_auc"] = float("nan")
    return metrics


def evaluate_model_by_family(
    clf: RandomForestClassifier,
    X: np.ndarray,
    y: np.ndarray,
    family_ids: np.ndarray,
) -> Dict[str, Dict[str, object]]:
    metrics_by_family: Dict[str, Dict[str, object]] = {}
    family_ids = np.asarray(family_ids, dtype=object)
    for dataset_type in sorted({str(item) for item in family_ids.tolist()}):
        mask = family_ids == dataset_type
        if not np.any(mask):
            continue
        metrics_by_family[dataset_type] = evaluate_model(clf, X[mask], y[mask])
    return metrics_by_family


def summarize_family_metric_map(metric_map: Dict[str, Dict[str, object]]) -> Dict[str, float]:
    if not metric_map:
        return {
            "worst_macro_f1": 0.0,
            "mean_macro_f1": 0.0,
            "worst_balanced_accuracy": 0.0,
            "mean_balanced_accuracy": 0.0,
            "macro_f1_spread": 0.0,
        }

    macro_f1_values = [float(metrics["macro_f1"]) for metrics in metric_map.values()]
    balanced_accuracy_values = [float(metrics["balanced_accuracy"]) for metrics in metric_map.values()]
    return {
        "worst_macro_f1": min(macro_f1_values),
        "mean_macro_f1": float(sum(macro_f1_values) / len(macro_f1_values)),
        "worst_balanced_accuracy": min(balanced_accuracy_values),
        "mean_balanced_accuracy": float(sum(balanced_accuracy_values) / len(balanced_accuracy_values)),
        "macro_f1_spread": max(macro_f1_values) - min(macro_f1_values),
    }


def print_metrics(title: str, metrics: Dict[str, object]) -> None:
    cm = metrics["confusion_matrix"]
    roc_auc = metrics["roc_auc"]
    roc_text = f"{roc_auc * 100:.2f}%" if isinstance(roc_auc, float) and not math.isnan(roc_auc) else "n/a"
    normal = metrics["class_breakdown"]["normal"]
    attack = metrics["class_breakdown"]["attack"]
    print(title)
    print(f"Accuracy:           {metrics['accuracy'] * 100:.2f}%")
    print(f"Balanced Accuracy:  {metrics['balanced_accuracy'] * 100:.2f}%")
    print(f"Attack Precision:   {metrics['precision'] * 100:.2f}%")
    print(f"Attack Recall:      {metrics['recall'] * 100:.2f}%")
    print(f"Attack F1:          {metrics['f1'] * 100:.2f}%")
    print(f"Macro Precision:    {metrics['macro_precision'] * 100:.2f}%")
    print(f"Macro Recall:       {metrics['macro_recall'] * 100:.2f}%")
    print(f"Macro F1:           {metrics['macro_f1'] * 100:.2f}%")
    print(f"Weighted F1:        {metrics['weighted_f1'] * 100:.2f}%")
    print(f"MCC:                {metrics['mcc']:.4f}")
    print(f"ROC-AUC:            {roc_text}")
    print(
        "Normal class:       "
        f"P={normal['precision'] * 100:.2f}% "
        f"R={normal['recall'] * 100:.2f}% "
        f"F1={normal['f1'] * 100:.2f}% "
        f"(n={normal['support']})"
    )
    print(
        "Attack class:       "
        f"P={attack['precision'] * 100:.2f}% "
        f"R={attack['recall'] * 100:.2f}% "
        f"F1={attack['f1'] * 100:.2f}% "
        f"(n={attack['support']})"
    )
    print(f"Confusion Matrix:\n{cm}")


def candidate_grid(lite_mode: bool) -> List[Dict[str, object]]:
    if lite_mode:
        return [
            {"n_estimators": 24, "max_depth": 8, "min_samples_leaf": 4},
            {"n_estimators": 32, "max_depth": 12, "min_samples_leaf": 2},
        ]
    return [
        {"n_estimators": 100, "max_depth": 10, "min_samples_leaf": 4},
        {"n_estimators": 100, "max_depth": 14, "min_samples_leaf": 2},
        {"n_estimators": 100, "max_depth": 18, "min_samples_leaf": 1},
    ]


def determine_rf_n_jobs() -> int:
    configured = os.environ.get("SENTINEL_RF_N_JOBS")
    if configured is not None:
        return int(configured)
    if os.name == "nt":
        return 1
    return -1


def choose_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> Tuple[RandomForestClassifier, Dict[str, object], Dict[str, object], Dict[str, object]]:
    X_train_balanced, y_train_balanced, _, rebalance_note = rebalance_training_data(
        X_train,
        y_train,
        train_family_ids,
    )
    if rebalance_note:
        print(f"[*] {rebalance_note}")

    scaled_train_balanced = scale_features(X_train_balanced)
    scaled_train = scale_features(X_train)
    scaled_val = scale_features(X_val)

    best_payload = None

    for candidate in candidate_grid(lite_mode):
        params = {
            "n_estimators": int(candidate["n_estimators"]),
            "max_depth": int(candidate["max_depth"]),
            "min_samples_leaf": int(candidate["min_samples_leaf"]),
            "min_samples_split": 4,
            "max_features": "sqrt",
            "bootstrap": True,
            "oob_score": True,
            "max_samples": 0.85,
            "class_weight": "balanced_subsample",
            "n_jobs": determine_rf_n_jobs(),
            "random_state": RANDOM_STATE,
        }
        print(
            "[*] Candidate RF: "
            f"estimators={params['n_estimators']}, max_depth={params['max_depth']}, "
            f"min_samples_leaf={params['min_samples_leaf']}"
        )
        clf = RandomForestClassifier(**params)
        clf.fit(scaled_train_balanced, y_train_balanced)
        train_metrics = evaluate_model(clf, scaled_train, y_train)
        val_metrics = evaluate_model(clf, scaled_val, y_val)
        train_family_metrics = evaluate_model_by_family(clf, scaled_train, y_train, train_family_ids)
        val_family_metrics = evaluate_model_by_family(clf, scaled_val, y_val, val_family_ids)
        train_family_summary = summarize_family_metric_map(train_family_metrics)
        val_family_summary = summarize_family_metric_map(val_family_metrics)
        fit_gap = max(
            0.0,
            float(train_metrics["macro_f1"]) - float(val_metrics["macro_f1"]),
            float(train_family_summary["worst_macro_f1"]) - float(val_family_summary["worst_macro_f1"]),
        )
        selection_score = (
            (0.40 * float(val_family_summary["worst_macro_f1"]))
            + (0.20 * float(val_family_summary["mean_macro_f1"]))
            + (0.15 * float(val_family_summary["worst_balanced_accuracy"]))
            + (0.15 * float(val_metrics["macro_f1"]))
            + (0.10 * float(val_metrics["balanced_accuracy"]))
            - (0.25 * fit_gap)
        )
        candidate_summary = {
            "params": params,
            "fit_gap": fit_gap,
            "selection_score": selection_score,
            "oob_score": float(getattr(clf, "oob_score_", 0.0)),
            "train_family_summary": train_family_summary,
            "validation_family_summary": val_family_summary,
            "validation_family_metrics": val_family_metrics,
            "balanced_train_rows": int(len(y_train_balanced)),
        }
        print(
            f"    validation worst-family macro-F1={float(val_family_summary['worst_macro_f1']) * 100:.2f}%, "
            f"mean-family macro-F1={float(val_family_summary['mean_macro_f1']) * 100:.2f}%, "
            f"aggregate macro-F1={float(val_metrics['macro_f1']) * 100:.2f}%, "
            f"train-validation gap={fit_gap * 100:.2f}pp, "
            f"OOB={candidate_summary['oob_score'] * 100:.2f}%"
        )
        if best_payload is None or selection_score > best_payload[0]:
            best_payload = (selection_score, clf, train_metrics, val_metrics, candidate_summary)

    assert best_payload is not None
    _, best_model, best_train_metrics, best_val_metrics, best_summary = best_payload
    return best_model, best_train_metrics, best_val_metrics, best_summary


def print_feature_importance(clf: RandomForestClassifier) -> None:
    if not hasattr(clf, "feature_importances_"):
        return
    print("[*] Top learned features:")
    ranked = sorted(
        zip(FEATURE_NAMES, clf.feature_importances_.tolist()),
        key=lambda item: item[1],
        reverse=True,
    )
    for name, importance in ranked[:8]:
        print(f"    {name:<24} {importance:.4f}")


def fit_random_forest(
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[RandomForestClassifier, Optional[str]]:
    X_balanced, y_balanced, _, rebalance_note = rebalance_training_data(X, y, family_ids)
    model = RandomForestClassifier(**params)
    model.fit(scale_features(X_balanced), y_balanced)
    return model, rebalance_note


def evaluate_test_chunks_by_dataset(
    clf: RandomForestClassifier,
    split_plan: SplitPlan,
) -> Dict[str, Dict[str, object]]:
    dataset_metrics: Dict[str, Dict[str, object]] = {}
    for dataset_type in sorted(split_plan.family_splits):
        X_test, y_test = split_plan.family_splits[dataset_type]["test"]
        if len(y_test) == 0:
            continue
        dataset_metrics[dataset_type] = evaluate_model(clf, scale_features(X_test), y_test)
    return dataset_metrics


def print_dataset_metric_table(title: str, metric_map: Dict[str, Dict[str, object]]) -> None:
    if not metric_map:
        return
    print(title)
    for dataset_type, metrics in sorted(metric_map.items()):
        print(
            f"  {dataset_type}: "
            f"macro-F1={float(metrics['macro_f1']) * 100:.2f}%, "
            f"balanced-acc={float(metrics['balanced_accuracy']) * 100:.2f}%, "
            f"attack-F1={float(metrics['f1']) * 100:.2f}%, "
            f"normal-F1={float(metrics['class_breakdown']['normal']['f1']) * 100:.2f}%"
        )


def evaluate_cross_dataset_transfer(
    params: Dict[str, object],
    split_plan: SplitPlan,
) -> Dict[str, Dict[str, Dict[str, object]]]:
    dataset_types = sorted(split_plan.family_splits)
    if len(dataset_types) < 2:
        return {}

    results: Dict[str, Dict[str, Dict[str, object]]] = {}
    for source_type in dataset_types:
        source_train = split_plan.family_splits[source_type]["train"]
        source_validation = split_plan.family_splits[source_type]["validation"]
        source_fit_X, source_fit_y = combine_xy_parts([source_train, source_validation])
        if len(source_fit_y) == 0 or not has_both_classes(source_fit_y):
            continue

        model, _ = fit_random_forest(params, source_fit_X, source_fit_y)
        target_results: Dict[str, Dict[str, object]] = {}
        for target_type in dataset_types:
            if target_type == source_type:
                continue
            X_target, y_target = split_plan.family_splits[target_type]["test"]
            if len(y_target) == 0 or not has_both_classes(y_target):
                continue
            target_results[target_type] = evaluate_model(model, scale_features(X_target), y_target)
        if target_results:
            results[source_type] = target_results
    return results


def determine_positive_n_jobs(env_name: str, fallback: int = 1) -> int:
    configured = int(os.environ.get(env_name, str(fallback)))
    if configured > 0:
        return configured
    return max(1, os.cpu_count() or 1)


def determine_xgb_n_jobs() -> int:
    configured = os.environ.get("SENTINEL_XGB_N_JOBS")
    if configured is not None:
        return determine_positive_n_jobs("SENTINEL_XGB_N_JOBS")
    rf_jobs = determine_rf_n_jobs()
    if rf_jobs > 0:
        return rf_jobs
    return max(1, os.cpu_count() or 1)


def determine_if_n_jobs() -> int:
    configured = os.environ.get("SENTINEL_IF_N_JOBS")
    if configured is not None:
        return determine_positive_n_jobs("SENTINEL_IF_N_JOBS")
    rf_jobs = determine_rf_n_jobs()
    if rf_jobs > 0:
        return rf_jobs
    return max(1, os.cpu_count() or 1)


def normalize_binary_predictions(predictions: np.ndarray) -> np.ndarray:
    normalized = np.asarray(predictions)
    if normalized.ndim != 1:
        normalized = normalized.reshape(-1)
    unique_values = set(np.unique(normalized).tolist())
    if unique_values.issubset({0, 1}):
        return normalized.astype(np.int64, copy=False)
    if unique_values.issubset({-1, 1}):
        return (normalized == -1).astype(np.int64)
    if normalized.dtype.kind == "f":
        return (normalized >= 0.5).astype(np.int64)
    return (normalized > 0).astype(np.int64)


def evaluate_predictions(
    y: np.ndarray,
    predictions: np.ndarray,
    scores: Optional[np.ndarray] = None,
) -> Dict[str, object]:
    normalized_predictions = normalize_binary_predictions(predictions)
    class_precision, class_recall, class_f1, class_support = precision_recall_fscore_support(
        y,
        normalized_predictions,
        labels=[0, 1],
        zero_division=0,
    )
    metrics: Dict[str, object] = {
        "accuracy": accuracy_score(y, normalized_predictions),
        "balanced_accuracy": balanced_accuracy_score(y, normalized_predictions),
        "precision": precision_score(y, normalized_predictions, zero_division=0),
        "recall": recall_score(y, normalized_predictions, zero_division=0),
        "f1": f1_score(y, normalized_predictions, zero_division=0),
        "macro_precision": precision_score(y, normalized_predictions, average="macro", zero_division=0),
        "macro_recall": recall_score(y, normalized_predictions, average="macro", zero_division=0),
        "macro_f1": f1_score(y, normalized_predictions, average="macro", zero_division=0),
        "weighted_f1": f1_score(y, normalized_predictions, average="weighted", zero_division=0),
        "mcc": matthews_corrcoef(y, normalized_predictions),
        "confusion_matrix": confusion_matrix(y, normalized_predictions, labels=[0, 1]),
        "class_breakdown": {
            "normal": {
                "precision": float(class_precision[0]),
                "recall": float(class_recall[0]),
                "f1": float(class_f1[0]),
                "support": int(class_support[0]),
            },
            "attack": {
                "precision": float(class_precision[1]),
                "recall": float(class_recall[1]),
                "f1": float(class_f1[1]),
                "support": int(class_support[1]),
            },
        },
    }
    if scores is not None and has_both_classes(y):
        try:
            metrics["roc_auc"] = roc_auc_score(y, np.asarray(scores, dtype=np.float64))
        except ValueError:
            metrics["roc_auc"] = float("nan")
    else:
        metrics["roc_auc"] = float("nan")
    return metrics


def score_model_artifact(artifact: ModelArtifact, X: np.ndarray) -> Optional[np.ndarray]:
    if artifact.score_mode == "probability":
        probabilities = np.asarray(artifact.estimator.predict_proba(X), dtype=np.float64)
        if probabilities.ndim == 2 and probabilities.shape[1] >= 2:
            return probabilities[:, 1]
        return probabilities.reshape(-1)
    if artifact.score_mode == "decision":
        return np.asarray(artifact.estimator.decision_function(X), dtype=np.float64).reshape(-1)
    if artifact.score_mode == "anomaly":
        return -np.asarray(artifact.estimator.score_samples(X), dtype=np.float64).reshape(-1)
    return None


def predict_with_artifact(artifact: ModelArtifact, X: np.ndarray) -> Tuple[np.ndarray, Optional[np.ndarray]]:
    scores = score_model_artifact(artifact, X)
    if artifact.threshold is not None and scores is not None:
        return (scores >= artifact.threshold).astype(np.int64), scores
    return normalize_binary_predictions(artifact.estimator.predict(X)), scores


def evaluate_model_artifact(artifact: ModelArtifact, X: np.ndarray, y: np.ndarray) -> Dict[str, object]:
    predictions, scores = predict_with_artifact(artifact, X)
    return evaluate_predictions(y, predictions, scores)


def measure_inference_latency_ms_per_sample(
    artifact: ModelArtifact,
    X_scaled: np.ndarray,
    repeats: int = 3,
    max_samples: int = 4096,
) -> float:
    if len(X_scaled) == 0:
        return float("nan")

    sample_count = min(len(X_scaled), max_samples)
    sample = X_scaled[:sample_count]

    # Warm up estimator internals before timing.
    predict_with_artifact(artifact, sample)

    started = time.perf_counter()
    for _ in range(max(1, repeats)):
        predict_with_artifact(artifact, sample)
    elapsed = time.perf_counter() - started

    total_predictions = float(max(1, repeats) * sample_count)
    return (elapsed * 1000.0) / total_predictions


def evaluate_model_by_family_artifact(
    artifact: ModelArtifact,
    X: np.ndarray,
    y: np.ndarray,
    family_ids: np.ndarray,
) -> Dict[str, Dict[str, object]]:
    metrics_by_family: Dict[str, Dict[str, object]] = {}
    family_ids = np.asarray(family_ids, dtype=object)
    for dataset_type in sorted({str(item) for item in family_ids.tolist()}):
        mask = family_ids == dataset_type
        if not np.any(mask):
            continue
        metrics_by_family[dataset_type] = evaluate_model_artifact(artifact, X[mask], y[mask])
    return metrics_by_family


def validation_selection_score(metrics: Dict[str, object], family_summary: Dict[str, float]) -> float:
    return (
        (0.40 * float(family_summary["worst_macro_f1"]))
        + (0.20 * float(family_summary["mean_macro_f1"]))
        + (0.15 * float(family_summary["worst_balanced_accuracy"]))
        + (0.15 * float(metrics["macro_f1"]))
        + (0.10 * float(metrics["balanced_accuracy"]))
    )


def build_selection_summary(
    train_metrics: Dict[str, object],
    val_metrics: Dict[str, object],
    train_family_metrics: Dict[str, Dict[str, object]],
    val_family_metrics: Dict[str, Dict[str, object]],
    extra: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    train_family_summary = summarize_family_metric_map(train_family_metrics)
    val_family_summary = summarize_family_metric_map(val_family_metrics)
    fit_gap = max(
        0.0,
        float(train_metrics["macro_f1"]) - float(val_metrics["macro_f1"]),
        float(train_family_summary["worst_macro_f1"]) - float(val_family_summary["worst_macro_f1"]),
    )
    summary: Dict[str, object] = {
        "fit_gap": fit_gap,
        "selection_score": validation_selection_score(val_metrics, val_family_summary) - (0.25 * fit_gap),
        "train_family_summary": train_family_summary,
        "validation_family_summary": val_family_summary,
        "validation_family_metrics": val_family_metrics,
    }
    if extra:
        summary.update(extra)
    return summary


def xgb_candidate_grid(lite_mode: bool) -> List[Dict[str, object]]:
    if lite_mode:
        return [
            {
                "n_estimators": 80,
                "max_depth": 5,
                "learning_rate": 0.10,
                "min_child_weight": 3,
                "subsample": 0.85,
                "colsample_bytree": 0.80,
            },
            {
                "n_estimators": 120,
                "max_depth": 6,
                "learning_rate": 0.08,
                "min_child_weight": 2,
                "subsample": 0.90,
                "colsample_bytree": 0.85,
            },
        ]
    return [
        {
            "n_estimators": 140,
            "max_depth": 6,
            "learning_rate": 0.08,
            "min_child_weight": 3,
            "subsample": 0.85,
            "colsample_bytree": 0.80,
        },
        {
            "n_estimators": 220,
            "max_depth": 8,
            "learning_rate": 0.05,
            "min_child_weight": 2,
            "subsample": 0.90,
            "colsample_bytree": 0.85,
        },
        {
            "n_estimators": 280,
            "max_depth": 10,
            "learning_rate": 0.04,
            "min_child_weight": 1,
            "subsample": 0.90,
            "colsample_bytree": 0.90,
        },
    ]


def isolation_candidate_grid(lite_mode: bool) -> List[Dict[str, object]]:
    if lite_mode:
        return [
            {"n_estimators": 100, "max_samples": 0.80, "max_features": 0.80},
            {"n_estimators": 150, "max_samples": 1.00, "max_features": 1.00},
        ]
    return [
        {"n_estimators": 160, "max_samples": 0.75, "max_features": 0.80},
        {"n_estimators": 220, "max_samples": 0.90, "max_features": 0.90},
        {"n_estimators": 280, "max_samples": 1.00, "max_features": 1.00},
    ]


def summarize_family_reference_counts(family_ids: np.ndarray) -> str:
    counts = Counter(str(item) for item in family_ids.tolist())
    return "; ".join(f"{dataset_type}(Normal={counts[dataset_type]})" for dataset_type in sorted(counts))


def rebalance_benign_reference_data(
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[np.ndarray, np.ndarray, Optional[np.ndarray], Optional[str]]:
    benign_mask = y == 0
    if not np.any(benign_mask):
        raise RuntimeError("IsolationForest requires benign-labeled reference data in the training split.")

    X_reference = X[benign_mask]
    y_reference = y[benign_mask]
    reference_family_ids = None if family_ids is None else np.asarray(family_ids, dtype=object)[benign_mask]
    if reference_family_ids is None or len(reference_family_ids) == 0:
        return X_reference, y_reference, reference_family_ids, None

    family_counts = Counter(str(item) for item in reference_family_ids.tolist())
    if len(family_counts) < 2:
        return X_reference, y_reference, reference_family_ids, None

    max_ratio = float(os.environ.get("SENTINEL_MAX_REFERENCE_FAMILY_RATIO", "4.0"))
    cap = int(max(1, round(min(family_counts.values()) * max_ratio)))
    if max(family_counts.values()) <= cap:
        return X_reference, y_reference, reference_family_ids, None

    rng = np.random.default_rng(RANDOM_STATE)
    keep_indices: List[np.ndarray] = []
    for dataset_type in sorted(family_counts):
        family_indices = np.flatnonzero(reference_family_ids == dataset_type)
        if len(family_indices) > cap:
            keep_indices.append(np.sort(rng.choice(family_indices, size=cap, replace=False)))
        else:
            keep_indices.append(family_indices)

    merged = np.sort(np.concatenate(keep_indices))
    before = summarize_family_reference_counts(reference_family_ids)
    after_family_ids = reference_family_ids[merged]
    after = summarize_family_reference_counts(after_family_ids)
    return (
        X_reference[merged],
        y_reference[merged],
        after_family_ids,
        f"rebalanced benign reference subset by dataset family from {before} to {after}",
    )


def build_score_thresholds(scores: np.ndarray, y: np.ndarray) -> List[float]:
    if len(scores) == 0:
        return [0.0]

    thresholds = {
        float(np.min(scores) - 1e-9),
        float(np.max(scores) + 1e-9),
        float(np.median(scores)),
    }
    for quantile in np.linspace(0.50, 0.995, 28):
        thresholds.add(float(np.quantile(scores, quantile)))

    attack_rate = float(np.mean(y == 1))
    if 0.0 < attack_rate < 1.0:
        base_quantile = min(0.999, max(0.001, 1.0 - attack_rate))
        for delta in (-0.10, -0.05, -0.02, 0.0, 0.02, 0.05, 0.10):
            quantile = min(0.999, max(0.001, base_quantile + delta))
            thresholds.add(float(np.quantile(scores, quantile)))

    return sorted(thresholds)


def evaluate_scores_by_family(
    y: np.ndarray,
    scores: np.ndarray,
    family_ids: np.ndarray,
    threshold: float,
) -> Dict[str, Dict[str, object]]:
    metrics_by_family: Dict[str, Dict[str, object]] = {}
    family_ids = np.asarray(family_ids, dtype=object)
    for dataset_type in sorted({str(item) for item in family_ids.tolist()}):
        mask = family_ids == dataset_type
        if not np.any(mask):
            continue
        predictions = (scores[mask] >= threshold).astype(np.int64)
        metrics_by_family[dataset_type] = evaluate_predictions(y[mask], predictions, scores[mask])
    return metrics_by_family


def choose_best_anomaly_threshold(
    train_scores: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    val_scores: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
) -> Tuple[float, Dict[str, object], Dict[str, object], Dict[str, object]]:
    best_payload = None
    for threshold in build_score_thresholds(val_scores, y_val):
        train_predictions = (train_scores >= threshold).astype(np.int64)
        val_predictions = (val_scores >= threshold).astype(np.int64)
        train_metrics = evaluate_predictions(y_train, train_predictions, train_scores)
        val_metrics = evaluate_predictions(y_val, val_predictions, val_scores)
        train_family_metrics = evaluate_scores_by_family(y_train, train_scores, train_family_ids, threshold)
        val_family_metrics = evaluate_scores_by_family(y_val, val_scores, val_family_ids, threshold)
        summary = build_selection_summary(
            train_metrics,
            val_metrics,
            train_family_metrics,
            val_family_metrics,
            {"threshold": float(threshold)},
        )
        if best_payload is None or float(summary["selection_score"]) > best_payload[0]:
            best_payload = (float(summary["selection_score"]), float(threshold), train_metrics, val_metrics, summary)

    assert best_payload is not None
    _, threshold, train_metrics, val_metrics, summary = best_payload
    return threshold, train_metrics, val_metrics, summary


def calibrate_anomaly_threshold(
    scores: np.ndarray,
    y: np.ndarray,
    family_ids: np.ndarray,
) -> Tuple[float, Dict[str, object], Dict[str, Dict[str, object]]]:
    best_payload = None
    for threshold in build_score_thresholds(scores, y):
        predictions = (scores >= threshold).astype(np.int64)
        metrics = evaluate_predictions(y, predictions, scores)
        family_metrics = evaluate_scores_by_family(y, scores, family_ids, threshold)
        family_summary = summarize_family_metric_map(family_metrics)
        calibration_score = validation_selection_score(metrics, family_summary)
        if best_payload is None or calibration_score > best_payload[0]:
            best_payload = (calibration_score, float(threshold), metrics, family_metrics)

    assert best_payload is not None
    _, threshold, metrics, family_metrics = best_payload
    return threshold, metrics, family_metrics


def fit_random_forest_artifact(
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[ModelArtifact, Optional[str]]:
    X_balanced, y_balanced, _, rebalance_note = rebalance_training_data(X, y, family_ids)
    model = RandomForestClassifier(**params)
    model.fit(scale_features(X_balanced), y_balanced)
    return (
        ModelArtifact(
            name="random_forest",
            estimator=model,
            score_mode="probability",
            params=dict(params),
            training_note=rebalance_note,
            exportable=True,
        ),
        rebalance_note,
    )


def fit_xgboost_artifact(
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[ModelArtifact, Optional[str]]:
    if XGBClassifier is None:
        raise RuntimeError("xgboost is not installed in this environment.")

    X_balanced, y_balanced, _, rebalance_note = rebalance_training_data(X, y, family_ids)
    counts = Counter(int(value) for value in y_balanced.tolist())
    attack_count = counts.get(1, 0)
    normal_count = counts.get(0, 0)
    scale_pos_weight = safe_div(float(normal_count), float(attack_count)) if attack_count > 0 else 1.0
    full_params = dict(params)
    full_params.update(
        {
            "objective": "binary:logistic",
            "eval_metric": "logloss",
            "tree_method": "hist",
            "random_state": RANDOM_STATE,
            "n_jobs": determine_xgb_n_jobs(),
            "verbosity": 0,
            "scale_pos_weight": max(1.0, scale_pos_weight),
        }
    )
    model = XGBClassifier(**full_params)
    model.fit(scale_features(X_balanced), y_balanced)
    return (
        ModelArtifact(
            name="xgboost",
            estimator=model,
            score_mode="probability",
            params=full_params,
            training_note=rebalance_note,
        ),
        rebalance_note,
    )


def fit_isolation_forest_artifact(
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: np.ndarray,
    calibration_X: Optional[np.ndarray] = None,
    calibration_y: Optional[np.ndarray] = None,
    calibration_family_ids: Optional[np.ndarray] = None,
) -> Tuple[ModelArtifact, Optional[str]]:
    X_reference, _y_reference, _reference_family_ids, rebalance_note = rebalance_benign_reference_data(X, y, family_ids)
    full_params = dict(params)
    full_params.update(
        {
            "contamination": "auto",
            "random_state": RANDOM_STATE,
            "n_jobs": determine_if_n_jobs(),
        }
    )
    model = IsolationForest(**full_params)
    model.fit(scale_features(X_reference))
    artifact = ModelArtifact(
        name="isolation_forest",
        estimator=model,
        score_mode="anomaly",
        params=full_params,
        training_note=rebalance_note,
    )

    threshold_X = X if calibration_X is None else calibration_X
    threshold_y = y if calibration_y is None else calibration_y
    threshold_family_ids = family_ids if calibration_family_ids is None else calibration_family_ids
    threshold_scores = score_model_artifact(artifact, scale_features(threshold_X))
    assert threshold_scores is not None
    threshold, _metrics, _family_metrics = calibrate_anomaly_threshold(
        threshold_scores,
        threshold_y,
        np.asarray(threshold_family_ids, dtype=object),
    )
    artifact.threshold = threshold
    return artifact, rebalance_note


def choose_random_forest_benchmark(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]:
    X_train_balanced, y_train_balanced, _, rebalance_note = rebalance_training_data(X_train, y_train, train_family_ids)
    if rebalance_note:
        print(f"[*] {rebalance_note}")

    scaled_train_balanced = scale_features(X_train_balanced)
    scaled_train = scale_features(X_train)
    scaled_val = scale_features(X_val)

    best_payload = None
    for candidate in candidate_grid(lite_mode):
        params = {
            "n_estimators": int(candidate["n_estimators"]),
            "max_depth": int(candidate["max_depth"]),
            "min_samples_leaf": int(candidate["min_samples_leaf"]),
            "min_samples_split": 4,
            "max_features": "sqrt",
            "bootstrap": True,
            "oob_score": True,
            "max_samples": 0.85,
            "class_weight": "balanced_subsample",
            "n_jobs": determine_rf_n_jobs(),
            "random_state": RANDOM_STATE,
        }
        print(
            "[*] Candidate RF: "
            f"estimators={params['n_estimators']}, max_depth={params['max_depth']}, "
            f"min_samples_leaf={params['min_samples_leaf']}"
        )
        estimator = RandomForestClassifier(**params)
        estimator.fit(scaled_train_balanced, y_train_balanced)
        artifact = ModelArtifact(
            name="random_forest",
            estimator=estimator,
            score_mode="probability",
            params=params,
            training_note=rebalance_note,
            exportable=True,
        )
        train_metrics = evaluate_model_artifact(artifact, scaled_train, y_train)
        val_metrics = evaluate_model_artifact(artifact, scaled_val, y_val)
        train_family_metrics = evaluate_model_by_family_artifact(artifact, scaled_train, y_train, train_family_ids)
        val_family_metrics = evaluate_model_by_family_artifact(artifact, scaled_val, y_val, val_family_ids)
        summary = build_selection_summary(
            train_metrics,
            val_metrics,
            train_family_metrics,
            val_family_metrics,
            {
                "params": params,
                "oob_score": float(getattr(estimator, "oob_score_", 0.0)),
                "balanced_train_rows": int(len(y_train_balanced)),
            },
        )
        print(
            f"    validation worst-family macro-F1={float(summary['validation_family_summary']['worst_macro_f1']) * 100:.2f}%, "
            f"mean-family macro-F1={float(summary['validation_family_summary']['mean_macro_f1']) * 100:.2f}%, "
            f"aggregate macro-F1={float(val_metrics['macro_f1']) * 100:.2f}%, "
            f"train-validation gap={float(summary['fit_gap']) * 100:.2f}pp, "
            f"OOB={float(summary['oob_score']) * 100:.2f}%"
        )
        if best_payload is None or float(summary["selection_score"]) > best_payload[0]:
            best_payload = (float(summary["selection_score"]), artifact, train_metrics, val_metrics, summary)

    assert best_payload is not None
    _, artifact, train_metrics, val_metrics, summary = best_payload
    return artifact, train_metrics, val_metrics, summary


def choose_xgboost_benchmark(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> Optional[Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]]:
    if XGBClassifier is None:
        print("[*] Skipping XGBoost benchmark: xgboost is not installed in this environment.")
        return None

    X_train_balanced, y_train_balanced, _, rebalance_note = rebalance_training_data(X_train, y_train, train_family_ids)
    if rebalance_note:
        print(f"[*] {rebalance_note}")

    counts = Counter(int(value) for value in y_train_balanced.tolist())
    attack_count = counts.get(1, 0)
    normal_count = counts.get(0, 0)
    scale_pos_weight = safe_div(float(normal_count), float(attack_count)) if attack_count > 0 else 1.0
    scaled_train_balanced = scale_features(X_train_balanced)
    scaled_train = scale_features(X_train)
    scaled_val = scale_features(X_val)

    best_payload = None
    for candidate in xgb_candidate_grid(lite_mode):
        params = dict(candidate)
        params.update(
            {
                "objective": "binary:logistic",
                "eval_metric": "logloss",
                "tree_method": "hist",
                "random_state": RANDOM_STATE,
                "n_jobs": determine_xgb_n_jobs(),
                "verbosity": 0,
                "scale_pos_weight": max(1.0, scale_pos_weight),
            }
        )
        print(
            "[*] Candidate XGBoost: "
            f"estimators={params['n_estimators']}, max_depth={params['max_depth']}, "
            f"learning_rate={params['learning_rate']:.3f}, min_child_weight={params['min_child_weight']}"
        )
        estimator = XGBClassifier(**params)
        estimator.fit(scaled_train_balanced, y_train_balanced)
        artifact = ModelArtifact(
            name="xgboost",
            estimator=estimator,
            score_mode="probability",
            params=params,
            training_note=rebalance_note,
        )
        train_metrics = evaluate_model_artifact(artifact, scaled_train, y_train)
        val_metrics = evaluate_model_artifact(artifact, scaled_val, y_val)
        train_family_metrics = evaluate_model_by_family_artifact(artifact, scaled_train, y_train, train_family_ids)
        val_family_metrics = evaluate_model_by_family_artifact(artifact, scaled_val, y_val, val_family_ids)
        summary = build_selection_summary(
            train_metrics,
            val_metrics,
            train_family_metrics,
            val_family_metrics,
            {
                "params": params,
                "balanced_train_rows": int(len(y_train_balanced)),
            },
        )
        print(
            f"    validation worst-family macro-F1={float(summary['validation_family_summary']['worst_macro_f1']) * 100:.2f}%, "
            f"mean-family macro-F1={float(summary['validation_family_summary']['mean_macro_f1']) * 100:.2f}%, "
            f"aggregate macro-F1={float(val_metrics['macro_f1']) * 100:.2f}%, "
            f"train-validation gap={float(summary['fit_gap']) * 100:.2f}pp"
        )
        if best_payload is None or float(summary["selection_score"]) > best_payload[0]:
            best_payload = (float(summary["selection_score"]), artifact, train_metrics, val_metrics, summary)

    assert best_payload is not None
    _, artifact, train_metrics, val_metrics, summary = best_payload
    return artifact, train_metrics, val_metrics, summary


def choose_isolation_forest_benchmark(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]:
    X_reference, _y_reference, _reference_family_ids, rebalance_note = rebalance_benign_reference_data(
        X_train,
        y_train,
        train_family_ids,
    )
    if rebalance_note:
        print(f"[*] {rebalance_note}")

    scaled_reference = scale_features(X_reference)
    scaled_train = scale_features(X_train)
    scaled_val = scale_features(X_val)

    best_payload = None
    for candidate in isolation_candidate_grid(lite_mode):
        params = dict(candidate)
        params.update(
            {
                "contamination": "auto",
                "random_state": RANDOM_STATE,
                "n_jobs": determine_if_n_jobs(),
            }
        )
        print(
            "[*] Candidate IsolationForest: "
            f"estimators={params['n_estimators']}, max_samples={params['max_samples']}, "
            f"max_features={params['max_features']}"
        )
        estimator = IsolationForest(**params)
        estimator.fit(scaled_reference)
        provisional_artifact = ModelArtifact(
            name="isolation_forest",
            estimator=estimator,
            score_mode="anomaly",
            params=params,
            training_note=rebalance_note,
        )
        train_scores = score_model_artifact(provisional_artifact, scaled_train)
        val_scores = score_model_artifact(provisional_artifact, scaled_val)
        assert train_scores is not None and val_scores is not None
        threshold, train_metrics, val_metrics, summary = choose_best_anomaly_threshold(
            train_scores,
            y_train,
            train_family_ids,
            val_scores,
            y_val,
            val_family_ids,
        )
        artifact = ModelArtifact(
            name="isolation_forest",
            estimator=estimator,
            score_mode="anomaly",
            params=params,
            threshold=threshold,
            training_note=rebalance_note,
        )
        summary["params"] = params
        summary["threshold"] = threshold
        summary["reference_rows"] = int(len(X_reference))
        print(
            f"    validation worst-family macro-F1={float(summary['validation_family_summary']['worst_macro_f1']) * 100:.2f}%, "
            f"mean-family macro-F1={float(summary['validation_family_summary']['mean_macro_f1']) * 100:.2f}%, "
            f"aggregate macro-F1={float(val_metrics['macro_f1']) * 100:.2f}%, "
            f"train-validation gap={float(summary['fit_gap']) * 100:.2f}pp, "
            f"threshold={threshold:.6f}"
        )
        if best_payload is None or float(summary["selection_score"]) > best_payload[0]:
            best_payload = (float(summary["selection_score"]), artifact, train_metrics, val_metrics, summary)

    assert best_payload is not None
    _, artifact, train_metrics, val_metrics, summary = best_payload
    return artifact, train_metrics, val_metrics, summary


def choose_knn_benchmark(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]:
    X_train_balanced, y_train_balanced, _, rebalance_note = rebalance_training_data(
        X_train, y_train, train_family_ids
    )
    if rebalance_note:
        print(f"[*] {rebalance_note}")
    scaled_train = scale_features(X_train_balanced)
    scaled_val = scale_features(X_val)
    params = {"n_neighbors": 15, "weights": "distance", "metric": "minkowski", "p": 2}
    estimator = KNeighborsClassifier(**params)
    estimator.fit(scaled_train, y_train_balanced)
    artifact = ModelArtifact(
        name="knn",
        estimator=estimator,
        score_mode="probability",
        params=params,
        training_note=rebalance_note,
        exportable=False,
    )
    train_metrics = evaluate_model_artifact(artifact, scale_features(X_train), y_train)
    val_metrics = evaluate_model_artifact(artifact, scaled_val, y_val)
    val_family_metrics = evaluate_model_by_family_artifact(artifact, scaled_val, y_val, val_family_ids)
    summary = build_selection_summary(
        train_metrics,
        val_metrics,
        evaluate_model_by_family_artifact(artifact, scale_features(X_train), y_train, train_family_ids),
        val_family_metrics,
        {"params": params},
    )
    print(
        f"    validation macro-F1={float(val_metrics['macro_f1']) * 100:.2f}%, "
        f"balanced-acc={float(val_metrics['balanced_accuracy']) * 100:.2f}%"
    )
    return artifact, train_metrics, val_metrics, summary


def choose_dt_benchmark(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]:
    X_train_balanced, y_train_balanced, _, rebalance_note = rebalance_training_data(
        X_train, y_train, train_family_ids
    )
    if rebalance_note:
        print(f"[*] {rebalance_note}")
    scaled_train = scale_features(X_train_balanced)
    scaled_val = scale_features(X_val)
    params = {
        "max_depth": 12,
        "min_samples_leaf": 4,
        "min_samples_split": 8,
        "class_weight": "balanced",
        "random_state": RANDOM_STATE,
    }
    estimator = DecisionTreeClassifier(**params)
    estimator.fit(scaled_train, y_train_balanced)
    artifact = ModelArtifact(
        name="decision_tree",
        estimator=estimator,
        score_mode="probability",
        params=params,
        training_note=rebalance_note,
        exportable=False,
    )
    train_metrics = evaluate_model_artifact(artifact, scale_features(X_train), y_train)
    val_metrics = evaluate_model_artifact(artifact, scaled_val, y_val)
    val_family_metrics = evaluate_model_by_family_artifact(artifact, scaled_val, y_val, val_family_ids)
    summary = build_selection_summary(
        train_metrics,
        val_metrics,
        evaluate_model_by_family_artifact(artifact, scale_features(X_train), y_train, train_family_ids),
        val_family_metrics,
        {"params": params},
    )
    print(
        f"    validation macro-F1={float(val_metrics['macro_f1']) * 100:.2f}%, "
        f"balanced-acc={float(val_metrics['balanced_accuracy']) * 100:.2f}%"
    )
    return artifact, train_metrics, val_metrics, summary


def fit_knn_artifact(
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[ModelArtifact, Optional[str]]:
    X_balanced, y_balanced, _, rebalance_note = rebalance_training_data(X, y, family_ids)
    model = KNeighborsClassifier(**{k: v for k, v in params.items() if k != "n_jobs"})
    model.fit(scale_features(X_balanced), y_balanced)
    return (
        ModelArtifact(
            name="knn",
            estimator=model,
            score_mode="probability",
            params=dict(params),
            training_note=rebalance_note,
            exportable=False,
        ),
        rebalance_note,
    )


def fit_dt_artifact(
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: Optional[np.ndarray] = None,
) -> Tuple[ModelArtifact, Optional[str]]:
    X_balanced, y_balanced, _, rebalance_note = rebalance_training_data(X, y, family_ids)
    model = DecisionTreeClassifier(**{k: v for k, v in params.items() if k != "n_jobs"})
    model.fit(scale_features(X_balanced), y_balanced)
    return (
        ModelArtifact(
            name="decision_tree",
            estimator=model,
            score_mode="probability",
            params=dict(params),
            training_note=rebalance_note,
            exportable=True,
        ),
        rebalance_note,
    )


def fit_benchmark_artifact(
    model_name: str,
    params: Dict[str, object],
    X: np.ndarray,
    y: np.ndarray,
    family_ids: np.ndarray,
) -> Tuple[ModelArtifact, Optional[str]]:
    if model_name == "random_forest":
        return fit_random_forest_artifact(params, X, y, family_ids)
    if model_name == "xgboost":
        return fit_xgboost_artifact(params, X, y, family_ids)
    if model_name == "isolation_forest":
        return fit_isolation_forest_artifact(params, X, y, family_ids, X, y, family_ids)
    if model_name == "knn":
        return fit_knn_artifact(params, X, y, family_ids)
    if model_name == "decision_tree":
        return fit_dt_artifact(params, X, y, family_ids)
    raise ValueError(f"Unsupported benchmark model: {model_name}")


def evaluate_test_chunks_by_dataset_for_artifact(
    artifact: ModelArtifact,
    split_plan: SplitPlan,
) -> Dict[str, Dict[str, object]]:
    dataset_metrics: Dict[str, Dict[str, object]] = {}
    for dataset_type in sorted(split_plan.family_splits):
        X_test, y_test = split_plan.family_splits[dataset_type]["test"]
        if len(y_test) == 0:
            continue
        dataset_metrics[dataset_type] = evaluate_model_artifact(artifact, scale_features(X_test), y_test)
    return dataset_metrics


def evaluate_cross_dataset_transfer_for_artifact(
    model_name: str,
    params: Dict[str, object],
    split_plan: SplitPlan,
) -> Dict[str, Dict[str, Dict[str, object]]]:
    dataset_types = sorted(split_plan.family_splits)
    if len(dataset_types) < 2:
        return {}

    results: Dict[str, Dict[str, Dict[str, object]]] = {}
    for source_type in dataset_types:
        source_train = split_plan.family_splits[source_type]["train"]
        source_validation = split_plan.family_splits[source_type]["validation"]
        source_fit_X, source_fit_y = combine_xy_parts([source_train, source_validation])
        if len(source_fit_y) == 0 or not has_both_classes(source_fit_y):
            continue
        source_family_ids = np.full(len(source_fit_y), source_type, dtype=object)
        artifact, _ = fit_benchmark_artifact(model_name, params, source_fit_X, source_fit_y, source_family_ids)
        target_results: Dict[str, Dict[str, object]] = {}
        for target_type in dataset_types:
            if target_type == source_type:
                continue
            X_target, y_target = split_plan.family_splits[target_type]["test"]
            if len(y_target) == 0 or not has_both_classes(y_target):
                continue
            target_results[target_type] = evaluate_model_artifact(artifact, scale_features(X_target), y_target)
        if target_results:
            results[source_type] = target_results
    return results


def select_benchmark_models(
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    lite_mode: bool,
) -> List[Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]]:
    selections: List[Tuple[ModelArtifact, Dict[str, object], Dict[str, object], Dict[str, object]]] = []

    print("[*] Selecting a RandomForest configuration with validation gating...")
    selections.append(
        choose_random_forest_benchmark(X_train, y_train, train_family_ids, X_val, y_val, val_family_ids, lite_mode)
    )

    print("[*] Selecting an XGBoost configuration with validation gating...")
    xgb_selection = choose_xgboost_benchmark(X_train, y_train, train_family_ids, X_val, y_val, val_family_ids, lite_mode)
    if xgb_selection is not None:
        selections.append(xgb_selection)

    print("[*] Selecting an IsolationForest configuration with validation gating...")
    selections.append(
        choose_isolation_forest_benchmark(X_train, y_train, train_family_ids, X_val, y_val, val_family_ids, lite_mode)
    )

    print("[*] Selecting a KNN configuration with validation gating...")
    selections.append(
        choose_knn_benchmark(X_train, y_train, train_family_ids, X_val, y_val, val_family_ids, lite_mode)
    )

    print("[*] Selecting a DecisionTree configuration with validation gating...")
    selections.append(
        choose_dt_benchmark(X_train, y_train, train_family_ids, X_val, y_val, val_family_ids, lite_mode)
    )
    return selections


def run_benchmark_suite(
    split_plan: SplitPlan,
    X_train: np.ndarray,
    y_train: np.ndarray,
    train_family_ids: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    val_family_ids: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    lite_mode: bool,
) -> Dict[str, ModelBenchmarkResult]:
    selected_models = select_benchmark_models(
        X_train,
        y_train,
        train_family_ids,
        X_val,
        y_val,
        val_family_ids,
        lite_mode,
    )
    X_fit = np.vstack([X_train, X_val])
    y_fit = np.concatenate([y_train, y_val])
    fit_family_ids = np.concatenate([train_family_ids, val_family_ids])

    results: Dict[str, ModelBenchmarkResult] = {}
    for selected_artifact, selection_train_metrics, selection_val_metrics, selection_summary in selected_models:
        model_name = selected_artifact.name
        params = dict(selection_summary["params"])
        print(f"[*] Re-fitting {model_name} on train+validation data...")
        final_artifact, training_note = fit_benchmark_artifact(model_name, params, X_fit, y_fit, fit_family_ids)
        if training_note:
            print(f"[*] {training_note}")

        scaled_fit = scale_features(X_fit)
        scaled_test = scale_features(X_test)
        fit_metrics = evaluate_model_artifact(final_artifact, scaled_fit, y_fit)
        test_metrics = evaluate_model_artifact(final_artifact, scaled_test, y_test)
        inference_ms_per_sample = measure_inference_latency_ms_per_sample(final_artifact, scaled_test)
        dataset_test_metrics = evaluate_test_chunks_by_dataset_for_artifact(final_artifact, split_plan)
        transfer_metrics = evaluate_cross_dataset_transfer_for_artifact(model_name, params, split_plan)
        results[model_name] = ModelBenchmarkResult(
            artifact=final_artifact,
            selection_train_metrics=selection_train_metrics,
            selection_val_metrics=selection_val_metrics,
            selection_summary=selection_summary,
            fit_metrics=fit_metrics,
            test_metrics=test_metrics,
            validation_family_metrics=selection_summary["validation_family_metrics"],
            dataset_test_metrics=dataset_test_metrics,
            transfer_metrics=transfer_metrics,
            inference_ms_per_sample=inference_ms_per_sample,
        )

    return results


def transfer_macro_f1_values(transfer_metrics: Dict[str, Dict[str, Dict[str, object]]]) -> List[float]:
    values: List[float] = []
    for target_map in transfer_metrics.values():
        for metrics in target_map.values():
            values.append(float(metrics["macro_f1"]))
    return values


def print_cross_dataset_transfer(title: str, transfer_metrics: Dict[str, Dict[str, Dict[str, object]]]) -> None:
    if not transfer_metrics:
        return
    print(title)
    for source_type, target_map in sorted(transfer_metrics.items()):
        for target_type, metrics in sorted(target_map.items()):
            print(
                f"  train={source_type} -> test={target_type}: "
                f"macro-F1={float(metrics['macro_f1']) * 100:.2f}%, "
                f"balanced-acc={float(metrics['balanced_accuracy']) * 100:.2f}%, "
                f"normal-F1={float(metrics['class_breakdown']['normal']['f1']) * 100:.2f}%, "
                f"attack-F1={float(metrics['f1']) * 100:.2f}%"
            )
    print("------------------------------------\n")


def print_benchmark_result(result: ModelBenchmarkResult) -> None:
    display_name = result.artifact.name.replace("_", " ").title()
    print(f"\n=== {display_name} ===")
    print("--- MODEL SELECTION METRICS ---")
    print_metrics("Selection Train:", result.selection_train_metrics)
    print()
    print_metrics("Selection Validation:", result.selection_val_metrics)
    print()
    print_dataset_metric_table("Selection Validation by Family:", result.validation_family_metrics)
    print("-------------------------------\n")

    print("--- FINAL HELD-OUT TEST METRICS ---")
    print_metrics("Train+Validation Fit:", result.fit_metrics)
    print()
    print_metrics("Held-out Test:", result.test_metrics)
    generalization_gap = float(result.fit_metrics["macro_f1"]) - float(result.test_metrics["macro_f1"])
    print(f"Generalization gap (Macro F1): {generalization_gap * 100:.2f}pp")
    print("-----------------------------------\n")

    print_dataset_metric_table("--- HELD-OUT TEST BY DATASET FAMILY ---", result.dataset_test_metrics)
    if result.dataset_test_metrics:
        print()

    print_cross_dataset_transfer("--- CROSS-DATASET TRANSFER CHECKS ---", result.transfer_metrics)


def print_model_comparison_summary(results: Dict[str, ModelBenchmarkResult], runtime_model_name: Optional[str] = None) -> None:
    if not results:
        return
    print("--- MODEL COMPARISON SUMMARY ---")
    for model_name, result in sorted(results.items()):
        dataset_summary = summarize_family_metric_map(result.dataset_test_metrics)
        transfer_values = transfer_macro_f1_values(result.transfer_metrics)
        transfer_text = "n/a" if not transfer_values else f"{(sum(transfer_values) / len(transfer_values)) * 100:.2f}%"
        exported_text = " [exported]" if result.artifact.exportable else ""
        runtime_text = " [runtime]" if runtime_model_name and model_name == runtime_model_name else ""
        latency_text = (
            "n/a"
            if math.isnan(float(result.inference_ms_per_sample))
            else f"{float(result.inference_ms_per_sample):.4f} ms/sample"
        )
        print(
            f"  {model_name}{exported_text}{runtime_text}: "
            f"test macro-F1={float(result.test_metrics['macro_f1']) * 100:.2f}%, "
            f"accuracy={float(result.test_metrics['accuracy']) * 100:.2f}%, "
            f"balanced-acc={float(result.test_metrics['balanced_accuracy']) * 100:.2f}%, "
            f"latency={latency_text}, "
            f"worst-family macro-F1={float(dataset_summary['worst_macro_f1']) * 100:.2f}%, "
            f"mean transfer macro-F1={transfer_text}"
        )
    print("--------------------------------\n")


def choose_runtime_model(results: Dict[str, ModelBenchmarkResult]) -> str:
    exportable = [(name, result) for name, result in results.items() if result.artifact.exportable]
    if not exportable:
        raise RuntimeError("No exportable model is available for runtime deployment.")

    latency_budget_ms = safe_float(os.environ.get("SENTINEL_RUNTIME_MAX_INFERENCE_MS", "0.20"), 0.20)
    latency_budget_ms = max(0.001, latency_budget_ms)
    accuracy_tie_epsilon = safe_float(os.environ.get("SENTINEL_RUNTIME_ACCURACY_TIE_EPS", "0.002"), 0.002)
    accuracy_tie_epsilon = max(0.0, accuracy_tie_epsilon)

    eligible = [
        (name, result)
        for name, result in exportable
        if not math.isnan(float(result.inference_ms_per_sample))
        and float(result.inference_ms_per_sample) <= latency_budget_ms
    ]
    pool = eligible if eligible else exportable

    if not eligible:
        print(
            f"[!] No exportable model met latency budget ({latency_budget_ms:.4f} ms/sample). "
            "Falling back to the fastest exportable model."
        )
        fastest = sorted(
            pool,
            key=lambda item: (
                math.isnan(float(item[1].inference_ms_per_sample)),
                float(item[1].inference_ms_per_sample),
                -float(item[1].selection_val_metrics["accuracy"]),
                -float(item[1].selection_val_metrics["macro_f1"]),
                ),
        )[0]
        return fastest[0]

    best_accuracy = max(float(result.selection_val_metrics["accuracy"]) for _, result in pool)
    near_best = [
        (name, result)
        for name, result in pool
        if (best_accuracy - float(result.selection_val_metrics["accuracy"])) <= accuracy_tie_epsilon
    ]
    selected = sorted(
        near_best,
        key=lambda item: (
            float(item[1].inference_ms_per_sample),
            -float(item[1].selection_val_metrics["accuracy"]),
            -float(item[1].selection_val_metrics["macro_f1"]),
            item[0],
        ),
    )[0]
    return selected[0]


def serialize_metrics(metrics: Dict[str, object]) -> Dict[str, object]:
    normal = metrics["class_breakdown"]["normal"]
    attack = metrics["class_breakdown"]["attack"]
    confusion = metrics["confusion_matrix"]
    return {
        "accuracy": float(metrics["accuracy"]),
        "balanced_accuracy": float(metrics["balanced_accuracy"]),
        "attack_precision": float(metrics["precision"]),
        "attack_recall": float(metrics["recall"]),
        "attack_f1": float(metrics["f1"]),
        "macro_precision": float(metrics["macro_precision"]),
        "macro_recall": float(metrics["macro_recall"]),
        "macro_f1": float(metrics["macro_f1"]),
        "weighted_f1": float(metrics["weighted_f1"]),
        "mcc": float(metrics["mcc"]),
        "roc_auc": None if math.isnan(float(metrics["roc_auc"])) else float(metrics["roc_auc"]),
        "normal": {
            "precision": float(normal["precision"]),
            "recall": float(normal["recall"]),
            "f1": float(normal["f1"]),
            "support": int(normal["support"]),
        },
        "attack": {
            "precision": float(attack["precision"]),
            "recall": float(attack["recall"]),
            "f1": float(attack["f1"]),
            "support": int(attack["support"]),
        },
        "confusion_matrix": np.asarray(confusion, dtype=np.int64).tolist(),
    }


def serialize_metric_map(metric_map: Dict[str, Dict[str, object]]) -> Dict[str, Dict[str, object]]:
    return {key: serialize_metrics(metrics) for key, metrics in sorted(metric_map.items())}


def serialize_transfer_metrics(
    transfer_metrics: Dict[str, Dict[str, Dict[str, object]]]
) -> Dict[str, Dict[str, Dict[str, object]]]:
    serialized: Dict[str, Dict[str, Dict[str, object]]] = {}
    for source_type, target_map in sorted(transfer_metrics.items()):
        serialized[source_type] = {target_type: serialize_metrics(metrics) for target_type, metrics in sorted(target_map.items())}
    return serialized


def extract_top_model_features(artifact: ModelArtifact) -> List[Dict[str, object]]:
    estimator = artifact.estimator
    if not hasattr(estimator, "feature_importances_"):
        return []
    ranked = sorted(
        zip(FEATURE_NAMES, np.asarray(estimator.feature_importances_, dtype=np.float64).tolist()),
        key=lambda item: item[1],
        reverse=True,
    )
    return [{"name": name, "importance": float(importance)} for name, importance in ranked[:8]]


def extract_global_importances(artifact: ModelArtifact) -> List[Dict[str, object]]:
    """Full ranked list of all features by tree-based importance (RF/XGBoost)."""
    estimator = artifact.estimator
    if not hasattr(estimator, "feature_importances_"):
        return []
    ranked = sorted(
        zip(FEATURE_NAMES, np.asarray(estimator.feature_importances_, dtype=np.float64).tolist()),
        key=lambda item: item[1],
        reverse=True,
    )
    return [{"name": name, "importance": float(importance)} for name, importance in ranked]


def extract_per_class_attack_importance(
    artifact: ModelArtifact,
    X: np.ndarray,
    y: np.ndarray,
    n_repeats: int = 3,
) -> Optional[List[Dict[str, object]]]:
    """Permutation importance using attack-class recall. Expensive; used for explainability config."""
    estimator = artifact.estimator
    if artifact.name == "isolation_forest":
        return None
    X_scaled = scale_features(X)
    try:
        attack_recall_scorer = make_scorer(recall_score, pos_label=1, zero_division=0)
        r = permutation_importance(
            estimator, X_scaled, y,
            n_repeats=n_repeats,
            random_state=RANDOM_STATE,
            scoring=attack_recall_scorer,
            n_jobs=1,
        )
        ranked = sorted(
            zip(FEATURE_NAMES, r.importances_mean.tolist()),
            key=lambda item: item[1],
            reverse=True,
        )
        return [{"name": name, "attack_recall_importance": float(imp)} for name, imp in ranked]
    except Exception:
        return None


def build_explainability_config(
    results: Dict[str, ModelBenchmarkResult],
    runtime_model_name: str,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> Dict[str, object]:
    """Build explainability config with global and per-class importances for deployed model."""
    deployed = results.get(runtime_model_name)
    if not deployed:
        deployed = results.get("xgboost") or next(iter(results.values()), None)
    if not deployed:
        return {"note": "No tree model available for explainability", "global_importances": []}
    artifact = deployed.artifact
    cfg: Dict[str, object] = {
        "model": artifact.name,
        "note": "Global importances from tree model. Per-attack SHAP requires off-path analysis endpoint.",
        "global_importances": extract_global_importances(artifact),
    }
    per_class = extract_per_class_attack_importance(artifact, X_test, y_test)
    if per_class is not None:
        cfg["per_class_attack_importance"] = per_class
    return cfg


def summarize_chunk_families(chunks: Sequence[DatasetChunk]) -> Dict[str, Dict[str, int]]:
    family_summary: Dict[str, Dict[str, int]] = {}
    for dataset_type in sorted({chunk.dataset_type for chunk in chunks}):
        matching = [chunk for chunk in chunks if chunk.dataset_type == dataset_type]
        counts = Counter()
        for chunk in matching:
            counts.update(chunk.class_counts)
        family_summary[dataset_type] = {
            "rows": int(sum(len(chunk.y) for chunk in matching)),
            "normal": int(counts.get(0, 0)),
            "attack": int(counts.get(1, 0)),
        }
    return family_summary


def summarize_split_plan_for_export(split_plan: SplitPlan) -> Dict[str, Dict[str, Dict[str, int]]]:
    payload: Dict[str, Dict[str, Dict[str, int]]] = {}
    for dataset_type, split_map in sorted(split_plan.family_splits.items()):
        payload[dataset_type] = {}
        for split_name, (X_part, y_part) in split_map.items():
            counts = Counter(int(value) for value in y_part.tolist())
            payload[dataset_type][split_name] = {
                "rows": int(len(y_part)),
                "normal": int(counts.get(0, 0)),
                "attack": int(counts.get(1, 0)),
            }
    return payload


EXPLAINABILITY_CONFIG_NAME = "explainability_config.json"


def export_benchmark_report(
    chunks: Sequence[DatasetChunk],
    split_plan: SplitPlan,
    results: Dict[str, ModelBenchmarkResult],
    runtime_model_name: str,
    X_test: np.ndarray,
    y_test: np.ndarray,
) -> None:
    report = {
        "trainer_version": TRAINER_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "runtime_model": runtime_model_name,
        "feature_schema": {
            "runtime_feature_count": len(FEATURE_NAMES),
            "runtime_feature_names": list(FEATURE_NAMES),
            "runtime_feature_schema_hash": compute_feature_schema_hash(FEATURE_NAMES),
            "shap_feature_count": len(SHAP_FEATURE_NAMES),
            "shap_feature_names": list(SHAP_FEATURE_NAMES),
            "shap_feature_schema_hash": compute_feature_schema_hash(SHAP_FEATURE_NAMES),
        },
        "dataset_family_coverage": summarize_chunk_families(chunks),
        "split_plan": summarize_split_plan_for_export(split_plan),
        "models": [],
    }

    for model_name, result in sorted(results.items()):
        dataset_summary = summarize_family_metric_map(result.dataset_test_metrics)
        transfer_values = transfer_macro_f1_values(result.transfer_metrics)
        model_entry = {
            "name": model_name,
            "display_name": model_name.replace("_", " ").title(),
            "exported": bool(result.artifact.exportable),
            "threshold": None if result.artifact.threshold is None else float(result.artifact.threshold),
            "params": dict(result.artifact.params),
            "selection_summary": {
                "fit_gap": float(result.selection_summary["fit_gap"]),
                "worst_family_macro_f1": float(result.selection_summary["validation_family_summary"]["worst_macro_f1"]),
                "mean_family_macro_f1": float(result.selection_summary["validation_family_summary"]["mean_macro_f1"]),
                "aggregate_macro_f1": float(result.selection_val_metrics["macro_f1"]),
            },
            "fit_metrics": serialize_metrics(result.fit_metrics),
            "test_metrics": serialize_metrics(result.test_metrics),
            "family_test_metrics": serialize_metric_map(result.dataset_test_metrics),
            "transfer_metrics": serialize_transfer_metrics(result.transfer_metrics),
            "top_features": extract_top_model_features(result.artifact),
            "global_importances": extract_global_importances(result.artifact),
            "summary": {
                "worst_family_macro_f1": float(dataset_summary["worst_macro_f1"]),
                "mean_family_macro_f1": float(dataset_summary["mean_macro_f1"]),
                "mean_transfer_macro_f1": None if not transfer_values else float(sum(transfer_values) / len(transfer_values)),
            },
            "inference_ms_per_sample": None
            if math.isnan(float(result.inference_ms_per_sample))
            else float(result.inference_ms_per_sample),
        }
        per_class = extract_per_class_attack_importance(
            result.artifact, X_test, y_test, n_repeats=2
        )
        if per_class is not None:
            model_entry["per_class_attack_importance"] = per_class
        report["models"].append(model_entry)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_paths = [
        os.path.join(script_dir, BENCHMARK_ARTIFACT_DIRS[0], BENCHMARK_ARTIFACT_NAME),
        os.path.join(script_dir, *BENCHMARK_ARTIFACT_DIRS[1], BENCHMARK_ARTIFACT_NAME),
    ]
    for output_path in output_paths:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(f"[*] Wrote benchmark report: {output_path}")

    comparison_path = os.path.join(script_dir, BENCHMARK_ARTIFACT_DIRS[0], "model_comparison.csv")
    os.makedirs(os.path.dirname(comparison_path), exist_ok=True)
    with open(comparison_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["model", "accuracy", "macro_f1", "balanced_accuracy", "exported"])
        for model_name, result in sorted(results.items()):
            tm = result.test_metrics
            writer.writerow([
                model_name,
                f"{float(tm['accuracy']):.6f}",
                f"{float(tm['macro_f1']):.6f}",
                f"{float(tm['balanced_accuracy']):.6f}",
                "yes" if result.artifact.exportable else "no",
            ])
    print(f"[*] Wrote model comparison: {comparison_path}")

    explain_cfg = build_explainability_config(results, runtime_model_name, X_test, y_test)
    explain_paths = [
        os.path.join(script_dir, BENCHMARK_ARTIFACT_DIRS[0], EXPLAINABILITY_CONFIG_NAME),
        os.path.join(script_dir, *BENCHMARK_ARTIFACT_DIRS[1], EXPLAINABILITY_CONFIG_NAME),
    ]
    for explain_path in explain_paths:
        with open(explain_path, "w", encoding="utf-8") as handle:
            json.dump(explain_cfg, handle, indent=2)
            handle.write("\n")
        print(f"[*] Wrote explainability config: {explain_path}")

def export_model(estimator: Any, runtime_model_name: str, joblib_path: Optional[str] = None) -> None:
    if m2c is None:
        print("[!] Skipping C export: m2cgen is not installed (pip install m2cgen).")
        return

    code = m2c.export_to_c(estimator)

    c_header = f"""/*
 * AUTO-GENERATED MACHINE LEARNING MODEL
 * Generated by train_ml.py (scikit-learn + m2cgen).
 * Runtime model: {runtime_model_name}
 * The model expects Sentinel's 20 engineered features after fixed min-max scaling.
 * Do not edit manually.
 */

#ifndef SENTINEL_ML_MODEL_H
#define SENTINEL_ML_MODEL_H

#include <math.h>

"""
    c_footer = """
static inline void sentinel_ml_scale_input(double input[20]) {
    static const double lo[20] = {
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0,
        0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
    };
    static const double hi[20] = {
        1000000.0, 1000000000.0, 1.0, 1.0, 8.0, 8.0, 65535.0, 1500.0, 1000.0, 100.0,
        1.0, 8.0, 65535.0, 64.0, 16.0, 1000000.0, 1000000.0, 10000.0, 1000000.0, 1000.0
    };
    for (int i = 0; i < 20; i++) {
        double value = input[i];
        if (isnan(value) || isinf(value) || value <= lo[i]) {
            input[i] = 0.0;
            continue;
        }
        if (value >= hi[i]) {
            input[i] = 1.0;
            continue;
        }
        input[i] = (value - lo[i]) / (hi[i] - lo[i]);
    }
}

/*
 * Wrapper for Sentinel 20-feature vector.
 * Returns probability of attack [0.0 - 1.0].
 */
static inline double run_ml_inference(const sentinel_feature_vector_t *f) {
    double input[20];
    double output[2];

    input[0]  = f->packets_per_second;
    input[1]  = f->bytes_per_second;
    input[2]  = f->syn_ratio;
    input[3]  = f->rst_ratio;
    input[4]  = f->dst_port_entropy;
    input[5]  = f->payload_byte_entropy;
    input[6]  = (double)f->unique_dst_ports;
    input[7]  = f->avg_packet_size;
    input[8]  = f->stddev_packet_size;
    input[9]  = (double)f->http_request_count;
    input[10] = f->fin_ratio;
    input[11] = f->src_port_entropy;
    input[12] = (double)f->unique_src_ports;
    input[13] = f->avg_ttl;
    input[14] = f->stddev_ttl;
    input[15] = f->avg_iat_us;
    input[16] = f->stddev_iat_us;
    input[17] = (double)f->src_total_flows;
    input[18] = f->src_packets_per_second;
    input[19] = (double)f->dns_query_count;

    sentinel_ml_scale_input(input);
    score(input, output);
    return output[1];
}

#endif /* SENTINEL_ML_MODEL_H */
"""

    output_path = os.path.join(os.path.dirname(__file__), "ml_engine", "ml_model.h")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(c_header)
        handle.write(code)
        handle.write(c_footer)
    print(f"Successfully generated ML model: {output_path}")

    if joblib is not None:
        model_path = joblib_path or os.path.join(os.path.dirname(__file__), "benchmarks", "sentinel_model.joblib")
        model_dir = os.path.dirname(model_path)
        if model_dir:
            os.makedirs(model_dir, exist_ok=True)
        joblib.dump(  # nosec B301
            {
                "estimator": estimator,
                "feature_names": FEATURE_NAMES,
                "feature_schema_hash": compute_feature_schema_hash(FEATURE_NAMES),
                "trainer_version": TRAINER_VERSION,
                "runtime_model": runtime_model_name,
                "scale": (ML_MINMAX_LOW, ML_MINMAX_HIGH),
            },
            model_path,
        )
        print(f"[*] Saved model for SHAP/explain API: {model_path}")


def train_and_export_model(
    data_dirs: Optional[Sequence[str]] = None,
    lite_mode: Optional[bool] = None,
    min_samples: Optional[int] = None,
    joblib_path: Optional[str] = None,
    auto_repo_data: Optional[bool] = None,
) -> None:
    print("=========================================================")
    print("SENTINEL CORE - ML TRAINING PIPELINE")
    print("=========================================================")
    print(f"[*] Trainer version: {TRAINER_VERSION}")

    if lite_mode is None:
        lite_mode = os.environ.get("SENTINEL_LITE_TRAIN", "0") == "1"
    if min_samples is None:
        min_samples = 1000 if lite_mode else 100000
    required_dataset_types = determine_required_dataset_types()
    if required_dataset_types:
        print(f"[*] Required dataset families: {', '.join(required_dataset_types)}")

    resolved_data_dirs = determine_data_dirs(data_dirs, auto_repo_data=auto_repo_data)
    if resolved_data_dirs:
        print(f"[*] Data directories: {', '.join(resolved_data_dirs)}")

    print(f"[*] Gathering datasets (min required: {min_samples})...")
    try:
        chunks = gather_datasets(data_dirs=resolved_data_dirs, min_total=min_samples)
    except Exception as exc:
        print(f"[!] Error loading datasets: {exc}")
        return

    total_counts = Counter()
    for chunk in chunks:
        total_counts.update(chunk.class_counts)
    total_rows = sum(len(chunk.y) for chunk in chunks)
    print(
        f"[*] Accepted {total_rows} total samples. "
        f"Normal: {total_counts.get(0, 0)}, Attack: {total_counts.get(1, 0)}"
    )
    print_dataset_family_summary(chunks)

    print("[*] Building train/validation/test splits...")
    split_plan = build_split_plan(chunks)
    X_train, y_train, train_family_ids = aggregate_split_with_family(split_plan.family_splits, "train")
    X_val, y_val, val_family_ids = aggregate_split_with_family(split_plan.family_splits, "validation")
    X_test, y_test, _test_family_ids = aggregate_split_with_family(split_plan.family_splits, "test")
    split_strategy = split_plan.strategy
    print(
        f"[*] Split strategy: {split_strategy}. "
        f"Train={len(y_train)}, Validation={len(y_val)}, Test={len(y_test)}"
    )
    print_split_plan_summary(split_plan)
    print_leakage_audit(audit_split_leakage(X_train, y_train, X_val, y_val, X_test, y_test))

    benchmark_results = run_benchmark_suite(
        split_plan,
        X_train,
        y_train,
        train_family_ids,
        X_val,
        y_val,
        val_family_ids,
        X_test,
        y_test,
        lite_mode,
    )

    for model_name in ("random_forest", "xgboost", "isolation_forest"):
        if model_name in benchmark_results:
            print_benchmark_result(benchmark_results[model_name])

    runtime_model_name = choose_runtime_model(benchmark_results)
    print_model_comparison_summary(benchmark_results, runtime_model_name=runtime_model_name)
    export_benchmark_report(chunks, split_plan, benchmark_results, runtime_model_name, X_test, y_test)

    deployed_result = benchmark_results.get(runtime_model_name)
    if deployed_result is None:
        print("[!] Runtime model selection failed; aborting C export because no deployed model is available.")
        return

    runtime_accuracy = float(deployed_result.test_metrics["accuracy"]) * 100.0
    runtime_latency = deployed_result.inference_ms_per_sample
    runtime_latency_text = "n/a" if math.isnan(float(runtime_latency)) else f"{float(runtime_latency):.4f} ms/sample"
    print(
        f"[*] Runtime model selected: {runtime_model_name} "
        f"(test accuracy={runtime_accuracy:.2f}%, latency={runtime_latency_text})."
    )
    print_feature_importance(deployed_result.artifact.estimator)

    print("[*] Exporting model to raw C code via m2cgen...")
    export_model(deployed_result.artifact.estimator, runtime_model_name, joblib_path=joblib_path)


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sentinel mixed-dataset ML trainer")
    parser.add_argument(
        "--dataset-dir",
        dest="dataset_dirs",
        action="append",
        default=[],
        help="Directory containing real dataset files. Repeat for multiple directories.",
    )
    parser.add_argument(
        "--auto-repo-data",
        action="store_true",
        help="Also auto-scan repo subdirectories for dataset files. Disabled by default.",
    )
    parser.add_argument(
        "--lite",
        action="store_true",
        help="Use lite training mode (lower sample target).",
    )
    parser.add_argument(
        "--min-samples",
        type=int,
        default=None,
        help="Override minimum accepted sample count before training.",
    )
    parser.add_argument(
        "--required-datasets",
        type=str,
        default=None,
        help="Comma-separated required dataset family names.",
    )
    parser.add_argument(
        "--runtime-max-inference-ms",
        type=float,
        default=None,
        help="Latency budget in milliseconds per sample for runtime model selection.",
    )
    parser.add_argument(
        "--runtime-accuracy-tie-eps",
        type=float,
        default=None,
        help="Accuracy epsilon for latency-first tie-breaking during runtime model selection.",
    )
    parser.add_argument(
        "--export-joblib",
        type=str,
        default=None,
        help="Override the exported joblib path for the Explain API model artifact.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args()
    if args.required_datasets is not None:
        os.environ["SENTINEL_REQUIRED_DATASETS"] = args.required_datasets
    if args.runtime_max_inference_ms is not None:
        os.environ["SENTINEL_RUNTIME_MAX_INFERENCE_MS"] = f"{args.runtime_max_inference_ms}"
    if args.runtime_accuracy_tie_eps is not None:
        os.environ["SENTINEL_RUNTIME_ACCURACY_TIE_EPS"] = f"{args.runtime_accuracy_tie_eps}"
    train_and_export_model(
        data_dirs=args.dataset_dirs or None,
        lite_mode=args.lite or None,
        min_samples=args.min_samples,
        joblib_path=args.export_joblib,
        auto_repo_data=args.auto_repo_data,
    )
