# WebSocket Telemetry Server

Real-time data streaming from the Sentinel DDoS Core pipeline to the React frontend.

## Streams (12 channels)

| Stream | Type | Interval |
|--------|------|----------|
| `metrics` | System counters | 1s |
| `activity_logs` | Mitigation actions | event |
| `blocked_ips` | Blocked IP list | on-change |
| `rate_limited_ips` | Rate limited IPs | on-change |
| `monitored_ips` | Monitored IPs | on-change |
| `whitelisted_ips` | Whitelisted IPs | on-change |
| `traffic_rate` | Traffic throughput | 1s |
| `protocol_distribution` | Protocol breakdown | 1s |
| `top_sources` | Top traffic sources | 5s |
| `feature_importance` | ML detection factors | 10s |
| `active_connections` | Active flows | 1s |
| `mitigation_status` | Mitigation summary | 1s |

## Frontend

The React dashboard lives in `../frontend/`. To run:

```bash
cd ../frontend
npm install
npm run dev
# Open http://localhost:5173
```

The frontend connects to `ws://localhost:8765` automatically.

## Architecture

```
Pipeline (C) --> WebSocket Server (port 8765) --> React Frontend (port 5173)
     |                    |
     |              ws_update_*()
     |                    |
     +-- ws_context_t ----+
```
