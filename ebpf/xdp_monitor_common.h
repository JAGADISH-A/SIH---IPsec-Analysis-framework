#ifndef XDP_MONITOR_COMMON_H
#define XDP_MONITOR_COMMON_H

#define COUNTER_TOTAL      0
#define COUNTER_IKE        1
#define COUNTER_IKE_NATT   2
#define COUNTER_ESP        3
#define COUNTER_AH         4
#define COUNTER_OTHER      5
#define COUNTER_MAX        6

/*
 * Lightweight per-packet observation event emitted by XDP into a BPF ring
 * buffer.  This is NOT the ML feature schema - a later userspace layer will
 * aggregate these into the feature/100ms-window schema.
 *
 * All multi-byte fields except `timestamp` are stored in network byte order
 * (as read from the wire); userspace converts with ntohs/ntohl as needed.
 * `sport`/`dport` are zero for ESP/AH; `spi`/`seq` are zero otherwise.
 *
 * Family/address handling: the outer header is classified for both IPv4
 * (``family == 4``, ``src``/``dst`` hold the 32-bit addresses) and IPv6
 * (``family == 6``, ``src6``/``dst6`` hold the 128-bit addresses in network
 * byte order as read from the wire).  ``src``/``dst`` are zero for IPv6
 * events and ``src6``/``dst6`` are zero for IPv4 events.
 */
struct xdp_monitor_event {
    __u64 timestamp;   /* bpf_ktime_get_ns() */
    __u32 src;         /* IPv4 source address             (family == 4) */
    __u32 dst;         /* IPv4 destination address        (family == 4) */
    __u32 spi;         /* ESP/AH SPI (network order)      */
    __u32 seq;         /* ESP/AH sequence (network order) */
    __u16 sport;       /* UDP source port                 */
    __u16 dport;       /* UDP destination port            */
    __u16 len;         /* captured frame length           */
    __u16 type;        /* COUNTER_IKE / _IKE_NATT / _ESP / _AH / _OTHER */
    __u8 proto;        /* IP protocol / IPv6 next header (17, 50, 51, ...) */
    __u8 family;       /* outer address family: 4 or 6   */
    __u8 pad[6];       /* padding to natural alignment    */
    __u8 src6[16];     /* IPv6 source address       (family == 6, net order) */
    __u8 dst6[16];     /* IPv6 destination address  (family == 6, net order) */
};

#endif