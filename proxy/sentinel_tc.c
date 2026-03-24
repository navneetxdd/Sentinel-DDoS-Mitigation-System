/*
 * Sentinel DDoS Core - TC clsact BPF Program (Kernel Mitigation Fallback)
 *
 * Attach to tc ingress/egress when AF_XDP is unavailable (e.g. WSL, VMs).
 * Uses the same blacklist_map as XDP: if source IP is in the map, drop (TC_ACT_SHOT).
 *
 * Build: make -C proxy sentinel_tc.o
 * Attach: ./scripts/attach_tc_clsact.sh <interface>
 *
 * Requires: Linux kernel 4.1+ (cls_bpf), iproute2 with tc.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
 
/* BTF-defined maps for libbpf 1.0+ compatibility */
#ifndef __uint
# define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
# define __type(name, val) val *name
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif

/* TC clsact uses different helper prototypes; map lookup is the same */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_skb_load_bytes)(void *ctx, __u32 off, void *to, __u32 len) = (void *) BPF_FUNC_skb_load_bytes;

#define TC_ACT_OK    0
#define TC_ACT_SHOT  2
#define ETH_P_IP     0x0800
#define IPHEADER_LEN 20

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} blacklist_map SEC(".maps");

/*
 * TC classifier: parse Ethernet + IPv4, lookup src IP in blacklist.
 * Returns TC_ACT_SHOT if blacklisted, TC_ACT_OK otherwise.
 */
SEC("classifier")
int sentinel_tc_drop(struct __sk_buff *skb)
{
    __u8 *data_end = (__u8 *)(long)skb->data_end;
    __u8 *data = (__u8 *)(long)skb->data;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    __u16 eth_proto;
    bpf_skb_load_bytes(skb, 12, &eth_proto, 2);
    if (eth_proto != __builtin_bswap16(ETH_P_IP))
        return TC_ACT_OK;

    __u32 src_ip;
    bpf_skb_load_bytes(skb, 14 + 12, &src_ip, 4);  /* eth 14B; ip src at iphdr+12 */

    if (bpf_map_lookup_elem(&blacklist_map, &src_ip))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
