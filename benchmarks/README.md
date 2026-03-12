# Benchmark Harness

This directory contains a reproducible Mininet + controller benchmark harness.

## Scope

`run_mininet_benchmark.sh` performs:
- build check (`make -j4`)
- controller startup (`start_ryu.py`)
- baseline connectivity (`mn --test pingall`)
- controller flow operation validation (`test_ryu_integration.sh` during active topology)
- artifact collection (logs + JSON snapshots + CSV summary)

## Prerequisites

- root privileges (`sudo`)
- Mininet and OVS installed
- controller runtime available through `start_ryu.py`
- `curl`, `python3`

## Run

From `Sentinel_DDOS_Core/`:

```bash
chmod +x benchmarks/run_mininet_benchmark.sh
sudo benchmarks/run_mininet_benchmark.sh
```

Results are written to:

`benchmarks/results/<timestamp>/`

## Notes

- This harness validates real integration and produces report artifacts.
- It is intended as a baseline reproducibility layer; extend scenarios for throughput/latency stress tiers as needed.
