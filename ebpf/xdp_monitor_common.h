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
 */
struct xdp_monitor_event {
    __u64 timestamp;   /* bpf_ktime_get_ns() */
    __u32 src;         /* IPv4 source address             */
    __u32 dst;         /* IPv4 destination address        */
    __u32 spi;         /* ESP/AH SPI (network order)      */
    __u32 seq;         /* ESP/AH sequence (network order) */
    __u16 sport;       /* UDP source port                 */
    __u16 dport;       /* UDP destination port            */
    __u16 len;         /* captured frame length           */
    __u16 type;        /* COUNTER_IKE / _IKE_NATT / _ESP / _AH / _OTHER */
    __u8 proto;        /* IP protocol (17, 50, 51, ...)   */
    __u8 pad;          /* padding to 8-byte alignment     */
};

#endif