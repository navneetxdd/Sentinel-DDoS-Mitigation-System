# Sentinel Explainability API

Optional off-path HTTP service for per-feature SHAP contributions. Runs independently of the C pipeline.

## Prerequisites

```bash
pip install joblib numpy shap
```

(joblib and numpy are typically already installed with scikit-learn.)

## Start

After running `train_ml.py` to generate `benchmarks/sentinel_model.joblib`:

```bash
python explain_api.py --port 5001
```

## Endpoints

### GET /health

Returns model and SHAP availability.

### POST /shap

Request body:

```json
{
  "samples": [
    [f1, f2, ..., f20],
    ...
  ]
}
```

Each inner array is a raw 20-feature vector (pre-scaling). See `FEATURE_NAMES` in `train_ml.py` for the feature order.

Response:

```json
{
  "contributions": [
    [{"name": "packets_per_second", "value": 0.02}, ...],
    ...
  ],
  "base_value": 0.15,
  "num_samples": 2
}
```

## Usage from UI

The UI can call this service when the user requests a SHAP analysis. For example, collect recent flow feature vectors from telemetry, POST to `http://localhost:5001/shap`, and display the per-feature contributions.
