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
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
# include <net/ethernet.h>

typedef uint64_t __u64;
typedef uint32_t __u32;

struct bpf_map_info { char name[16]; };

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
