# DDoS Simulation & Testing Guide

This guide explains how to simulate DDoS attacks against Sentinel for testing the detection and mitigation pipeline.

## Prerequisites

- Sentinel pipeline built and running: `sudo ./sentinel_pipeline -i <interface> -q 0 -w 8765`
- Frontend running: `cd frontend && npm run dev`
- WebSocket server on port 8765
- Root/sudo access (AF_XDP requires it)

## Attack Types Supported by Sentinel

| Attack Type     | Protocol | Typical Tool   | Description                    |
|-----------------|----------|----------------|--------------------------------|
| SYN Flood       | TCP      | hping3, scapy  | Flood of TCP SYN packets       |
| UDP Flood       | UDP      | hping3, nping  | High-rate UDP packets          |
| ICMP Flood      | ICMP     | ping -f, hping3| ICMP echo flood                |
| DNS Amplification| UDP     | Custom         | DNS query amplification        |
| NTP Amplification| UDP     | Custom         | NTP monlist amplification      |
| Slowloris       | TCP      | slowloris.py   | Slow HTTP request exhaustion   |
| Port Scan       | TCP/UDP  | nmap           | Rapid port probing             |
| LAND            | TCP      | Custom         | src_ip == dst_ip               |
| Smurf           | ICMP     | Custom         | ICMP broadcast amplification   |

## Simulation Commands

### SYN Flood (recommended for quick test)

From a separate machine or terminal targeting your Sentinel-monitored interface IP:

```bash
# Install hping3 if needed: apt install hping3  or  brew install hping3
sudo hping3 -S -p 80 --flood <TARGET_IP>
```

- `-S`: SYN flag
- `-p 80`: destination port
- `--flood`: send as fast as possible
- Replace `<TARGET_IP>` with the IP of the machine running Sentinel (e.g. 192.168.1.100)

### UDP Flood

```bash
sudo hping3 --udp -p 53 --flood <TARGET_IP>
```

### ICMP Flood

```bash
ping -f <TARGET_IP>
# or
sudo hping3 --icmp --flood <TARGET_IP>
```

## What to Expect in the UI

1. **Overview (Index)**: Risk Gauge rises, Traffic Chart shows packet spike, Status Badge turns "Attack"
2. **Traffic Analysis**: Top Source IPs table shows attacker IP with high packet count and Threat %
3. **Decision Engine**: Attack Probability increases, Classification switches to "DDoS Attack"
4. **Mitigation Control**:
   - Mitigation Log shows entries with: **Source IP**, **Attack Type** (e.g. SYN_FLOOD), **Protocol** (TCP), **Threat Score**
   - Blocked IPs and Rate-Limited IPs tables populate with attacker IPs
   - Unblock / Clear actions available per IP

## Verification Checklist

- [ ] Pipeline receives packets (check verbose logs: `-v`)
- [ ] Frontend connects (WebSocket status: "Pipeline Connected")
- [ ] Traffic chart updates during attack
- [ ] Top IPs table shows attacker source IP
- [ ] Mitigation Log shows attack type and protocol
- [ ] Blocked IPs table shows mitigated IPs (when auto-mitigation enabled)
- [ ] Unblock clears IP from list (when pipeline processes command)

## Important Notes

- **Single-interface testing**: If attacking the same machine running Sentinel, use the loopback or a secondary interface. The pipeline typically binds to a physical NIC (e.g. eth0).
- **Rate**: Start with moderate rates; very high rates may overwhelm the system.
- **Legal**: Only test on networks you own or have explicit permission to test.
