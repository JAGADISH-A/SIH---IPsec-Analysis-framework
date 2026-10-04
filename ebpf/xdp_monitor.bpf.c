#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_monitor_common.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#define RINGBUF_ENTRIES (1 << 18)

/*
 * RFC 3948 (UDP encapsulation of IPsec) framing.  A UDP/4500 payload that
 * starts with this 4-byte non-ESP marker is NOT ESP - it carries IKE over
 * NAT-T instead.  Because the marker's SPI field is zero, "leading SPI == 0"
 * is the single test that separates NAT-T negotiation from NAT-T data.  See
 * classify_nat_t_udp() below for the framing that actually appears on the wire.
 */
#define NAT_T_NON_ESP_MARKER 0x00000000

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, COUNTER_MAX);
	__type(key, __u32);
	__type(value, __u64);
} packet_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, RINGBUF_ENTRIES);
} events SEC(".maps");

static __always_inline void increment(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&packet_count, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

/*
 * Classify a UDP/4500 datagram as ESP-in-UDP (NAT-T data) or IKE-over-NAT-T.
 *
 * RFC 3948 says a UDP/4500 payload starting with the 4-byte non-ESP marker
 * (00 00 00 00) is NOT ESP, and since the marker's SPI field is zero that is
 * exactly how the two are told apart.  IKE-over-NAT-T therefore reads a zero
 * SPI at the start of the payload.
 *
 * IMPORTANT: the Linux kernel's UDP ESP encapsulation (XFRM_ENCAP, which is
 * what strongSwan's charon-kernel-netlink uses) does NOT insert the non-ESP
 * marker - the real ESP header starts immediately at the UDP payload.  Both
 * encodings are therefore handled by the same rule:
 *
 *   - leading SPI == 0            -> IKE over NAT-T (marker present), no SPI
 *                                    is invented
 *   - leading SPI != 0            -> ESP-in-UDP, and the SPI/sequence are read
 *                                    from the real ESP header, so NAT-T data
 *                                    carries exactly the same SPI/sequence
 *                                    evidence as native protocol-50 ESP.
 */
static __always_inline void classify_nat_t_udp(struct xdp_monitor_event *e,
						struct udphdr *udp,
						void *data_end)
{
	/* NOTE: (udp + 1) advances one whole struct udphdr (8 bytes); casting to
	 * void* first and adding 1 would advance a single byte and read the SPI
	 * out of the UDP header itself. */
	void *payload = (void *)(udp + 1);
	__u32 spi;

	if ((void *)payload + 12 > data_end)
		goto ike;
	spi = *(__u32 *)payload;

	/* Zero SPI == RFC 3948 non-ESP marker == IKE, never data. */
	if (spi == 0)
		goto ike;

	/* ESP header: SPI(4) + sequence(4). */
	e->spi = spi;
	e->seq = *(__u32 *)((char *)payload + 4);
	e->type = COUNTER_ESP_NATT;
	increment(COUNTER_ESP_NATT);
	return;

ike:
	e->type = COUNTER_IKE_NATT;
	increment(COUNTER_IKE_NATT);
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct xdp_monitor_event *e;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct ipv6hdr *ip6;
	struct udphdr *udp;

	increment(COUNTER_TOTAL);

	/*
	 * Reserve a ring-buffer slot before parsing.  If the ring buffer is
	 * full (or reservation fails) we skip this packet's event entirely
	 * and still pass the packet onward - a monitoring failure must never
	 * affect packet forwarding.
	 */
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return XDP_PASS;

	__builtin_memset(e, 0, sizeof(*e));
	e->timestamp = bpf_ktime_get_ns();
	e->type = COUNTER_OTHER;
	e->len = (__u16)((__u64)(data_end - data));

	eth = data;
	if ((void *)(eth + 1) > data_end)
		goto submit;

	/*
	 * IPv4 outer header.
	 */
	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			goto submit;

		if (ip->version != 4)
			goto submit;

		e->family = 4;
		e->src = ip->saddr;
		e->dst = ip->daddr;
		e->proto = ip->protocol;

		if (ip->protocol == IPPROTO_ESP) {
			void *esp = (void *)ip + (__u32)ip->ihl * 4;

			if ((void *)esp + 8 > data_end)
				goto submit;
			e->spi = *(__u32 *)esp;
			e->seq = *(__u32 *)(esp + 4);
			e->type = COUNTER_ESP;
			increment(COUNTER_ESP);
			goto submit;
		}

		if (ip->protocol == IPPROTO_AH) {
			void *ah = (void *)ip + (__u32)ip->ihl * 4;

			if ((void *)ah + 12 > data_end)
				goto submit;
			e->spi = *(__u32 *)(ah + 4);
			e->seq = *(__u32 *)(ah + 8);
			e->type = COUNTER_AH;
			increment(COUNTER_AH);
			goto submit;
		}

		if (ip->protocol != IPPROTO_UDP)
			goto submit;

		if (ip->ihl < 5)
			goto submit;

		udp = (void *)ip + (__u32)ip->ihl * 4;
		if ((void *)(udp + 1) > data_end)
			goto submit;

		e->sport = udp->source;
		e->dport = udp->dest;

		if (udp->source == bpf_htons(500) || udp->dest == bpf_htons(500)) {
			e->type = COUNTER_IKE;
			increment(COUNTER_IKE);
			goto submit;
		}

		if (udp->source == bpf_htons(4500) || udp->dest == bpf_htons(4500)) {
			classify_nat_t_udp(e, udp, data_end);
			goto submit;
		}

		increment(COUNTER_OTHER);
		goto submit;
	}

	/*
	 * IPv6 outer header.
	 *
	 * Parsing scope: only the immediate IPv6 header is examined.  The
	 * next-header field (`nexthdr`) is inspected directly; extension
	 * headers (hop-by-hop 0, routing 43, fragment 44, destination 60, ...)
	 * are NOT traversed, so ESP/AH following an extension header is not
	 * classified (falls through to OTHER).  This is a documented scope
	 * limitation of the lightweight classifier, not silent misclassification.
	 */
	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			goto submit;

		if (ip6->version != 6)
			goto submit;

		e->family = 6;
		__builtin_memcpy(e->src6, &ip6->saddr, sizeof(ip6->saddr));
		__builtin_memcpy(e->dst6, &ip6->daddr, sizeof(ip6->daddr));
		e->proto = ip6->nexthdr;

		if (ip6->nexthdr == IPPROTO_ESP) {
			void *esp = (void *)(ip6 + 1);

			if ((void *)esp + 8 > data_end)
				goto submit;
			e->spi = *(__u32 *)esp;
			e->seq = *(__u32 *)(esp + 4);
			e->type = COUNTER_ESP;
			increment(COUNTER_ESP);
			goto submit;
		}

		if (ip6->nexthdr == IPPROTO_AH) {
			void *ah = (void *)(ip6 + 1);

			if ((void *)ah + 12 > data_end)
				goto submit;
			e->spi = *(__u32 *)(ah + 4);
			e->seq = *(__u32 *)(ah + 8);
			e->type = COUNTER_AH;
			increment(COUNTER_AH);
			goto submit;
		}

		if (ip6->nexthdr != IPPROTO_UDP)
			goto submit;

		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end)
			goto submit;

		e->sport = udp->source;
		e->dport = udp->dest;

		if (udp->source == bpf_htons(500) || udp->dest == bpf_htons(500)) {
			e->type = COUNTER_IKE;
			increment(COUNTER_IKE);
			goto submit;
		}

		if (udp->source == bpf_htons(4500) || udp->dest == bpf_htons(4500)) {
			classify_nat_t_udp(e, udp, data_end);
			goto submit;
		}

		increment(COUNTER_OTHER);
		goto submit;
	}

	increment(COUNTER_OTHER);
submit:
	bpf_ringbuf_submit(e, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";