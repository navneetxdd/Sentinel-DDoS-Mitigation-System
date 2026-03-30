# Sentinel Production Readiness Audit (Networking and Infrastructure)

Audit Date: 2026-03-27  
Status: Draft / Handover

## 1. Current State

Sentinel is validated in a WSL2 plus Windows lab topology where dataplane capture often uses loopback and fallback paths.

- Data Plane: Sentinel pipeline in Linux userspace (WSL2 today).
- Control Plane: SDN controller in Linux userspace.
- Explain API: Python service.
- Frontend: Vite/React dashboard.

Primary gap: NAT isolation between internet edge and WSL guest means external attack traffic does not naturally traverse the same NIC dataplane path that AF_XDP expects.

## 2. Production Constraints and Required Controls

### A. Interface Binding and Dataplane Path

- Requirement: bind Sentinel to an externally facing interface (for example eth0 or ens5), not loopback.
- Implemented: sentinel_pipeline now resolves interface in this order:
  1. CLI flag -i if explicitly set and not auto.
  2. SENTINEL_INTERFACE or SENTINEL_CAPTURE_IFACE env.
  3. Default-route interface from /proc/net/route.
  4. First non-loopback device from /proc/net/dev.
  5. Fallback to eth0.

### B. XDP Native Driver Mode

- Requirement: hardware-level drop path.
- Implemented scripts:
  - deploy/enable_xdp_native.sh
  - scripts/attach_tc_clsact.sh --xdp-native <iface>
- TC path remains fallback and policy continuity mechanism.

### C. Shared State for Multi-Core and Multi-Process Safety

- Requirement: move process-local _Atomic globals to shared state backend.
- Implemented: POSIX shared memory state segment in sentinel_pipeline.
- Environment:
  - SENTINEL_SHARED_STATE_BACKEND=shm
  - SENTINEL_SHARED_STATE_NAME=/sentinel_state_v1
- Shared fields include auto mitigation toggle, SDN health status, and queued command actions.

## 3. WSL2 Networking Transition (Mirror or Bridge)

Use Windows 11 WSL mirror mode where possible.

### Option 1: Mirror Mode (Preferred)

1. Edit C:\Users\<user>\.wslconfig:

```ini
[wsl2]
networkingMode=mirrored
autoProxy=true
```

2. Restart WSL:

```powershell
wsl --shutdown
```

3. Start distro and verify interfaces:

```bash
ip addr
ip route
```

4. Start Sentinel with interface auto-resolution or explicit external NIC:

```bash
sudo SENTINEL_INTERFACE=eth0 ./sentinel_pipeline -w 8765
```

### Option 2: Bridged Pattern

If mirror mode is unavailable, use Hyper-V external switch or equivalent bridge model so Linux guest sees routable L2 traffic on an external NIC. Validate with tcpdump before Sentinel start.

## 4. Router and NAT Traversal Requirements (Home Lab)

Target external public IP: 106.192.76.75

### Minimal inbound forwarding

Forward WAN to Sentinel host private IP for:

- TCP 80 -> frontend/nginx
- TCP 443 -> frontend/nginx TLS
- Optional TCP 8765 -> direct WebSocket (prefer reverse proxy over 443)

### DMZ mode (test only)

- Place Sentinel host in DMZ only for controlled tests.
- Keep host firewall strict and expose only required ports.
- Do not keep DMZ active in normal operation.

### Required topology for real mitigation validation

To validate dataplane mitigation against attack ingress, attack packets must traverse the Sentinel capture interface before service termination.

Recommended patterns:

- Inline: internet edge -> Sentinel host -> protected service.
- Reverse proxy on Sentinel host with backend internal.
- Tap plus policy enforcement on same ingress interface with XDP hook.

## 5. Ubuntu 22.04 Cloud VM Automation

Use deploy/bootstrap_ubuntu22_vm.sh to provision complete stack.

Example:

```bash
sudo bash deploy/bootstrap_ubuntu22_vm.sh \
  --repo-path /opt/Sentinel-main \
  --iface eth0 \
  --ws-port 8765 \
  --explain-port 5001 \
  --web-port 80 \
  --ws-api-key '<strong-secret>'
```

This script:

- Installs C, Python, Node, nginx, and Redis dependencies.
- Builds Sentinel pipeline and frontend.
- Creates systemd units for pipeline and explain API.
- Configures nginx static hosting plus API and WebSocket proxying.

## 6. External Attack Validation Procedure

1. Confirm XDP native attach:

```bash
sudo bash deploy/enable_xdp_native.sh eth0 proxy/sentinel_xdp.o
ip -details link show dev eth0 | grep -E 'xdp|prog/xdp'
```

2. Start stack and confirm services:

```bash
systemctl status sentinel-pipeline sentinel-explain-api nginx
```

3. From external VPS, generate controlled flood:

```bash
hping3 --flood -S -p 80 106.192.76.75
```

4. Expected outcomes:

- Dashboard updates in near real time.
- top_sources and activity streams show attacker source distribution.
- mitigation_status counters rise for blocked or rate-limited actions.
- Kernel dataplane path remains active under load.

## 7. Remaining Hardening Recommendations

- Move from single-node control plane to active-standby pair for explain API and websocket relay.
- Add mTLS between control and telemetry components.
- Add fail2ban or edge WAF rules for API endpoint abuse.
- Add synthetic probes and SLO alerts for detection and mitigation latency.
