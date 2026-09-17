#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_monitor_common.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#define RINGBUF_ENTRIES (1 << 18)

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

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct xdp_monitor_event *e;
	struct ethhdr *eth;
	struct iphdr *ip;
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

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		goto submit;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		goto submit;

	if (ip->version != 4)
		goto submit;

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
		e->type = COUNTER_IKE_NATT;
		increment(COUNTER_IKE_NATT);
		goto submit;
	}

	increment(COUNTER_OTHER);
submit:
	bpf_ringbuf_submit(e, 0);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";