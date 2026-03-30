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
# include <stddef.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

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

struct bpf_map_info {
    uint32_t type;
    uint32_t id;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint32_t map_flags;
    char name[16];
};

union bpf_attr {
    struct {
        uint32_t map_fd;
        uint64_t key;
        union {
            uint64_t value;
            uint64_t next_key;
        } v;
        uint64_t flags;
    } map_elem;
    struct {
        uint32_t start_id;
        uint32_t next_id;
        uint32_t open_flags;
    } get_id;
    struct {
        uint32_t bpf_fd;
        uint32_t info_len;
        uint64_t info;
    } info;
    struct {
        uint64_t pathname;
        uint32_t bpf_fd;
        uint32_t file_flags;
    } obj_get;
    uint32_t map_fd;
    uint64_t key;
    uint64_t value;
    uint64_t next_key;
    uint64_t flags;
    uint32_t start_id;
    uint32_t next_id;
    uint32_t map_id;
    uint64_t pathname;
    uint32_t bpf_fd;
    uint32_t info_len;
};

#if defined(_WIN32)
typedef long ssize_t;
typedef long long off_t;

struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};

#ifndef no_argument
# define no_argument 0
#endif
#ifndef required_argument
# define required_argument 1
#endif

static char *optarg = NULL;

typedef struct { unsigned long long bits; } cpu_set_t;
#define CPU_ZERO(setptr) do { (setptr)->bits = 0ULL; } while (0)
#define CPU_SET(cpu, setptr) do { (setptr)->bits |= (1ULL << ((cpu) & 63)); } while (0)

#ifndef _SC_NPROCESSORS_ONLN
# define _SC_NPROCESSORS_ONLN 84
#endif

struct sigaction {
    void (*sa_handler)(int);
    unsigned long sa_flags;
    int sa_mask;
};

#ifndef SA_RESTART
# define SA_RESTART 0x10000000
#endif

struct pollfd {
    int fd;
    short events;
    short revents;
};

#ifndef POLLIN
# define POLLIN 0x0001
#endif

#ifndef MSG_DONTWAIT
# define MSG_DONTWAIT 0x40
#endif

#ifndef PROT_READ
# define PROT_READ 0x1
#endif
#ifndef PROT_WRITE
# define PROT_WRITE 0x2
#endif
#ifndef MAP_SHARED
# define MAP_SHARED 0x01
#endif
#ifndef MAP_POPULATE
# define MAP_POPULATE 0x8000
#endif
#ifndef MAP_FAILED
# define MAP_FAILED ((void *)(intptr_t)-1)
#endif

#ifndef AF_PACKET
# define AF_PACKET 17
#endif
#ifndef ETH_P_ALL
# define ETH_P_ALL 0x0003
#endif

struct sockaddr_ll {
    unsigned short sll_family;
    unsigned short sll_protocol;
    int sll_ifindex;
    unsigned short sll_hatype;
    unsigned char sll_pkttype;
    unsigned char sll_halen;
    unsigned char sll_addr[8];
};

typedef void CURL;
typedef int CURLcode;
#ifndef CURL_GLOBAL_DEFAULT
# define CURL_GLOBAL_DEFAULT 0L
#endif
#ifndef CURLE_OK
# define CURLE_OK 0
#endif

static inline int sched_setaffinity(int pid, size_t cpusetsize, const cpu_set_t *mask)
{ (void)pid; (void)cpusetsize; (void)mask; return 0; }
static inline long sysconf(int name)
{ (void)name; return 4; }
static inline int sigemptyset(int *set)
{ if (set) *set = 0; return 0; }
static inline int sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)
{ (void)signum; (void)act; (void)oldact; return 0; }
static inline void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{ (void)addr; (void)length; (void)prot; (void)flags; (void)fd; (void)offset; return MAP_FAILED; }
static inline int munmap(void *addr, size_t length)
{ (void)addr; (void)length; return 0; }
static inline int poll(struct pollfd *fds, unsigned long nfds, int timeout)
{ (void)fds; (void)nfds; (void)timeout; return 0; }
static inline int pthread_create(uintptr_t *thread, const void *attr, void *(*start_routine)(void *), void *arg)
{ (void)thread; (void)attr; (void)start_routine; (void)arg; return 0; }
static inline int pthread_join(uintptr_t thread, void **retval)
{ (void)thread; (void)retval; return 0; }
static inline CURLcode curl_global_init(long flags)
{ (void)flags; return CURLE_OK; }
static inline void curl_global_cleanup(void)
{ }

typedef uintptr_t pthread_t;
#endif

# define BPF_MAP_UPDATE_ELEM    0xDEAD0001
# define BPF_MAP_DELETE_ELEM    0xDEAD0002
# define BPF_MAP_GET_NEXT_KEY   0xDEAD0003
# define BPF_MAP_GET_NEXT_ID    0xDEAD0004
# define BPF_MAP_GET_FD_BY_ID   0xDEAD0005
# define BPF_OBJ_GET_INFO_BY_FD 0xDEAD0006
# define BPF_OBJ_GET            0xDEAD0007
# define __NR_bpf               (-1)

#ifndef AF_XDP
# define AF_XDP 44
#endif
#ifndef PF_XDP
# define PF_XDP AF_XDP
#endif

#ifndef SOL_XDP
# define SOL_XDP 283
#endif

#ifndef XDP_UMEM_REG
# define XDP_UMEM_REG 4
#endif
#ifndef XDP_UMEM_FILL_RING
# define XDP_UMEM_FILL_RING 5
#endif
#ifndef XDP_RX_RING
# define XDP_RX_RING 6
#endif
#ifndef XDP_MMAP_OFFSETS
# define XDP_MMAP_OFFSETS 1
#endif

#ifndef XDP_PGOFF_RX_RING
# define XDP_PGOFF_RX_RING 0
#endif
#ifndef XDP_UMEM_PGOFF_FILL_RING
# define XDP_UMEM_PGOFF_FILL_RING 0x100000000ULL
#endif

#ifndef XDP_ZEROCOPY
# define XDP_ZEROCOPY (1U << 2)
#endif
#ifndef XDP_COPY
# define XDP_COPY (1U << 1)
#endif

#ifndef XDP_FLAGS_SKB_MODE
# define XDP_FLAGS_SKB_MODE (1U << 1)
#endif
#ifndef XDP_FLAGS_DRV_MODE
# define XDP_FLAGS_DRV_MODE (1U << 2)
#endif
#ifndef XDP_FLAGS_UPDATE_IF_NOEXIST
# define XDP_FLAGS_UPDATE_IF_NOEXIST (1U << 0)
#endif

#ifndef IFLA_XDP
# define IFLA_XDP 43
#endif
#ifndef IFLA_XDP_FD
# define IFLA_XDP_FD 1
#endif
#ifndef IFLA_XDP_FLAGS
# define IFLA_XDP_FLAGS 3
#endif

struct xdp_desc {
    __u64 addr;
    __u32 len;
    __u32 options;
};

struct xdp_umem_reg {
    __u64 addr;
    __u64 len;
    __u32 chunk_size;
    __u32 headroom;
    __u32 flags;
    __u32 tx_metadata_len;
};

struct xdp_ring_offset {
    __u64 producer;
    __u64 consumer;
    __u64 desc;
    __u64 flags;
};

struct xdp_mmap_offsets {
    struct xdp_ring_offset rx;
    struct xdp_ring_offset tx;
    struct xdp_ring_offset fr;
    struct xdp_ring_offset cr;
};

struct sockaddr_xdp {
    __u16 sxdp_family;
    __u16 sxdp_flags;
    __u32 sxdp_ifindex;
    __u32 sxdp_queue_id;
    __u32 sxdp_shared_umem_fd;
};

#endif /* SENTINEL_PIPELINE_STUBS_H */
