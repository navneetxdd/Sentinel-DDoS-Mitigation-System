# Sentinel Dashboard — Frontend

Real-time DDoS detection and mitigation dashboard for the Sentinel pipeline.

## Tech Stack

- **React 18** + **TypeScript** — UI framework
- **Vite** — Build tooling
- **Tailwind CSS** + **shadcn/ui** — Styling and component library
- **Recharts** — Traffic and protocol charts
- **WebSocket** — Real-time data from the C backend pipeline

## Architecture

The frontend connects to two backend services:

1. **C Pipeline WebSocket** (`ws://localhost:8765`) — Streams 12 real-time data channels (metrics, traffic rates, protocol distribution, top sources, feature importance, SHAP vectors, mitigation status, activity logs, blocked/rate-limited/monitored/whitelisted IPs, active connections).
2. **Explain API** (`http://localhost:5001`) — Python service providing SHAP explainability and Gemini-powered threat analysis.

## Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Default | Description |
|---|---|---|
| `VITE_WS_URL` | `ws://localhost:8765` | WebSocket URL for the C pipeline |
| `VITE_EXPLAIN_API_URL` | `http://localhost:5001` | SHAP Explain API + Gemini proxy |

## Getting Started

```bash
npm install
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

## Pages

| Route | Description |
|---|---|
| `/` | Main dashboard — KPIs, traffic chart, risk gauge, AI analyst, threat intelligence |
| `/traffic` | Live traffic analysis — protocol distribution, top IPs, active connections |
| `/decision` | Decision engine — ML classification, SHAP explainability, model benchmarks |
| `/mitigation` | Mitigation control — block/rate-limit management, timeline, quick actions |
| `/settings` | Detection thresholds, mitigation rules, IP lists, notifications |

