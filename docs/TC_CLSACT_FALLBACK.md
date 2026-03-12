# TC clsact Kernel Mitigation Fallback

When AF_XDP is unavailable (WSL2, VMs, or unsupported NICs), the Sentinel pipeline falls back to raw socket capture. In that mode, **XDP kernel drops are disabled** by default—blocked IPs are only enforced via SDN/user-space.

The **tc clsact fallback** lets you re-enable kernel-level drops using a TC BPF classifier instead of XDP.

## How It Works

1. **sentinel_tc.c** – BPF program that looks up the source IP in `blacklist_map` and returns `TC_ACT_SHOT` (drop) if found.
2. **attach_tc_clsact.sh** – Attaches this program to the interface’s ingress path via the `clsact` qdisc.
3. The pipeline’s `find_map_fd_by_name("blacklist_map")` discovers the map created by the tc loader and uses it for `pipeline_blacklist_ip()`.

## Prerequisites

- **Native Linux** (recommended; WSL2 has limited eBPF support)
- Root or `CAP_NET_ADMIN`
- iproute2 with `tc`
- `clang` (or `clang-18`) for building the BPF object

## Build

```bash
make -C proxy sentinel_tc.o
```

## Attach

```bash
sudo ./scripts/attach_tc_clsact.sh eth0
```

Replace `eth0` with your capture interface.

## Detach

```bash
sudo tc qdisc del dev eth0 clsact
```

## Pipeline Integration

1. Start the pipeline **after** attaching the tc program.
2. The pipeline will call `find_map_fd_by_name("blacklist_map")` and will find the map created by the tc loader.
3. `kernel_dropping_enabled` in the mitigation status will report `true` once the map is found.

**Important:** Attach the tc program before starting the pipeline. If the pipeline starts first and AF_XDP fails, it will not automatically run the attach script—you must run it manually.

## Limitation

- The tc classifier runs in the **ingress** path only (ingress traffic). Egress is not filtered by this program.
- For full testing, use a native Linux host; WSL2 and some VMs may have restricted eBPF support.
