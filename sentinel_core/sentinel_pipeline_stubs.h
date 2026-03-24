/*
 * Non-Linux editor support only
 *
 * This header exists solely for non-Linux builds (e.g. Windows IDE / IntelliSense).
 * It provides stub types and constants so the pipeline compiles for editing and
 * navigation. These stubs are NOT used at runtime on Linux; the real Linux
 * headers are used there. Do not rely on this header for any production build.
 */
#ifndef SENTINEL_PIPELINE_STUBS_H
#define SENTINEL_PIPELINE_STUBS_H

#ifdef __linux__
#if !defined(SENTINEL_ALLOW_STUBS)
#error "sentinel_pipeline_stubs.h must NOT be included on Linux production builds. Define SENTINEL_ALLOW_STUBS to override."
#endif
#endif

# include <stdint.h>
#if defined(_WIN32) || !__has_include(<netinet/in.h>)
#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

struct ether_header {
    uint8_t ether_dhost[6];
    uint8_t ether_shost[6];
    uint16_t ether_type;
};

struct iphdr {
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint8_t ihl:4;
    uint8_t version:4;
#else
    uint8_t version:4;
    uint8_t ihl:4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t flags:8;
#else
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t flags:8;
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

struct icmphdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint32_t rest;
};

#else
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#endif
union bpf_attr {
    uint64_t map_fd, key, value, flags, info, pathname;
    uint32_t start_id, next_id, map_id, bpf_fd, info_len;
};

# define BPF_MAP_UPDATE_ELEM    0xDEAD0001
# define BPF_MAP_DELETE_ELEM    0xDEAD0002
# define BPF_MAP_GET_NEXT_KEY   0xDEAD0003
# define BPF_MAP_GET_NEXT_ID    0xDEAD0004
# define BPF_MAP_GET_FD_BY_ID   0xDEAD0005
# define BPF_OBJ_GET_INFO_BY_FD 0xDEAD0006
# define BPF_OBJ_GET            0xDEAD0007
# define __NR_bpf               (-1)

struct xdp_desc { __u64 addr; __u32 len; };
struct xdp_umem { char *frames; };
struct xdp_rx_queue {
    __u32 *producer; __u32 *consumer;
    struct xdp_desc *ring;
    __u32 mask, size;
    void *map;
};
struct xsk_socket_info { struct xdp_umem *umem; int xsk_fd; struct xdp_rx_queue rx; };

#endif /* SENTINEL_PIPELINE_STUBS_H */
