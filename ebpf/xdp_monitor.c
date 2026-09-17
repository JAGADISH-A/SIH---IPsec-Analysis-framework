#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>

#include "xdp_monitor.skel.h"
#include "xdp_monitor_common.h"

static volatile sig_atomic_t stop;

/*
 * When set (--json), each ring-buffer event is emitted as one JSONL record on
 * stdout and all human-oriented banners/counters go to stderr.  The XDP
 * program itself is untouched; this is purely an output format switch.
 */
static int json_out = 0;

static void banner(const char *fmt, ...)
{
    va_list ap;

    if (json_out)
        return;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

static void handle_signal(int sig)
{
    (void)sig;
    stop = 1;
}

static const char *const counter_labels[COUNTER_MAX] = {
    [COUNTER_TOTAL]    = "total",
    [COUNTER_IKE]      = "IKE",
    [COUNTER_IKE_NATT] = "IKE-NAT-T",
    [COUNTER_ESP]      = "ESP",
    [COUNTER_AH]       = "AH",
    [COUNTER_OTHER]    = "OTHER",
};

/* ------------------------------------------------------------------------- */
/* Ring-buffer event handler: print one concise structured line per packet.  */
/* ------------------------------------------------------------------------- */
static int handle_event(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct xdp_monitor_event))
        return 0;

    const struct xdp_monitor_event *e = data;
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &e->src, src, sizeof(src));
    inet_ntop(AF_INET, &e->dst, dst, sizeof(dst));

    if (json_out) {
        if (e->type == COUNTER_ESP || e->type == COUNTER_AH) {
            printf("{\"ts\":%llu,\"type\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\","
                   "\"proto\":%u,\"len\":%u,\"spi\":%u,\"seq\":%u}\n",
                   (unsigned long long)e->timestamp,
                   e->type < COUNTER_MAX ? counter_labels[e->type] : "?",
                   src,
                   dst,
                   e->proto,
                   e->len,
                   ntohl(e->spi),
                   ntohl(e->seq));
        } else {
            printf("{\"ts\":%llu,\"type\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\","
                   "\"proto\":%u,\"len\":%u,\"sport\":%u,\"dport\":%u}\n",
                   (unsigned long long)e->timestamp,
                   e->type < COUNTER_MAX ? counter_labels[e->type] : "?",
                   src,
                   dst,
                   e->proto,
                   e->len,
                   ntohs(e->sport),
                   ntohs(e->dport));
        }
        fflush(stdout);
        return 0;
    }

    printf("ts=%llu type=%s src=%s dst=%s proto=%u len=%u",
           (unsigned long long)e->timestamp,
           e->type < COUNTER_MAX ? counter_labels[e->type] : "?",
           src,
           dst,
           e->proto,
           e->len);

    if (e->type == COUNTER_ESP || e->type == COUNTER_AH) {
        printf(" spi=0x%x seq=0x%x",
               ntohl(e->spi),
               ntohl(e->seq));
    } else {
        printf(" sport=%u dport=%u",
               ntohs(e->sport),
               ntohs(e->dport));
    }

    printf("\n");
    fflush(stdout);
    return 0;
}

/* Print counters at most once per `interval_ms`. */
static void print_counters(struct xdp_monitor_bpf *skel, long interval_ms)
{
    static long last_print_ms = 0;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long now_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;

    if (now_ms - last_print_ms < interval_ms)
        return;
    last_print_ms = now_ms;

    FILE *out = json_out ? stderr : stdout;

    if (!json_out)
        fprintf(out, "\n");
    for (uint32_t key = 0; key < COUNTER_MAX; key++) {
        uint64_t value = 0;
        int err = bpf_map__lookup_elem(
            skel->maps.packet_count,
            &key,
            sizeof(key),
            &value,
            sizeof(value),
            0
        );

        if (err) {
            fprintf(
                stderr,
                "WARNING: counter lookup failed (key %u): %s\n",
                key,
                strerror(-err)
            );
        } else {
            fprintf(
                out,
                "%-9s : %llu\n",
                counter_labels[key],
                (unsigned long long)value
            );
        }
    }
}

int main(int argc, char **argv)
{
    const char *ifname = "ens33";
    int have_ifname = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) {
            json_out = 1;
        } else if (!have_ifname) {
            ifname = argv[i];
            have_ifname = 1;
        }
    }

    /*
     * Convert interface name to interface index (never hard-coded).
     */
    int ifindex = if_nametoindex(ifname);

    if (!ifindex) {
        fprintf(stderr,
                "ERROR: interface '%s' not found\n",
                ifname);
        return 1;
    }

    banner("interface: %s\n", ifname);
    banner("ifindex: %d\n", ifindex);

    /*
     * Open and load the BPF skeleton.
     */
    struct xdp_monitor_bpf *skel;

    skel = xdp_monitor_bpf__open_and_load();

    if (!skel) {
        fprintf(stderr,
                "ERROR: failed to open and load BPF skeleton\n");
        return 1;
    }

    /*
     * Get the file descriptor of our XDP program.
     */
    int prog_fd = bpf_program__fd(skel->progs.xdp_pass);

    if (prog_fd < 0) {
        fprintf(stderr,
                "ERROR: failed to get XDP program FD: %s\n",
                strerror(-prog_fd));

        xdp_monitor_bpf__destroy(skel);
        return 1;
    }

    banner("XDP program FD: %d\n", prog_fd);

    /*
     * ---------------------------------------------------------
     * Try NATIVE / DRIVER XDP first, then GENERIC/SKB fallback.
     * ---------------------------------------------------------
     */
    uint32_t flags =
        XDP_FLAGS_UPDATE_IF_NOEXIST |
        XDP_FLAGS_DRV_MODE;

    banner("trying native (driver) XDP on %s...\n", ifname);

    int err = bpf_xdp_attach(
        ifindex,
        prog_fd,
        flags,
        NULL
    );

    if (err) {
        banner(
            "native (driver) XDP unavailable on %s "
            "(error: %s)\n",
            ifname,
            strerror(-err)
        );

        banner(
            "trying generic (SKB) XDP on %s...\n",
            ifname
        );

        flags =
            XDP_FLAGS_UPDATE_IF_NOEXIST |
            XDP_FLAGS_SKB_MODE;

        err = bpf_xdp_attach(
            ifindex,
            prog_fd,
            flags,
            NULL
        );
    }

    if (err) {
        fprintf(
            stderr,
            "ERROR: failed to attach XDP to %s: %s\n",
            ifname,
            strerror(-err)
        );

        xdp_monitor_bpf__destroy(skel);
        return 1;
    }

    if (flags & XDP_FLAGS_SKB_MODE) {
        banner(
            "SUCCESS: attached XDP in generic (SKB) mode "
            "on %s\n",
            ifname
        );
    } else {
        banner(
            "SUCCESS: attached XDP in native (driver) mode "
            "on %s\n",
            ifname
        );
    }

    /*
     * Open the BPF ring buffer.  A failure here is non-fatal: the
     * counters-only monitor still runs.
     */
    struct ring_buffer *rb = NULL;

    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        handle_event,
        NULL,
        NULL
    );

    if (!rb) {
        fprintf(
            stderr,
            "WARNING: failed to open ring buffer (%s); "
            "running counters-only\n",
            strerror(errno)
        );
    } else {
        banner("ring buffer open (consuming packet events)\n");
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    banner("\n");
    banner("XDP monitor is running.\n");
    banner("Press Ctrl+C to stop.\n");
    banner("\n");

    while (!stop) {
        /*
         * Drain any pending ring-buffer events (blocks up to ~250 ms),
         * then periodically refresh the counter view.
         */
        if (rb) {
            int r = ring_buffer__poll(rb, 250);
            if (r < 0 && errno != EINTR)
                fprintf(stderr,
                        "WARNING: ring buffer poll failed: %s\n",
                        strerror(errno));
        }

        print_counters(skel, 1000);
    }

    banner("\nstopping XDP monitor...\n");

    if (rb)
        ring_buffer__free(rb);

    err = bpf_xdp_detach(
        ifindex,
        flags,
        NULL
    );

    if (err) {
        fprintf(
            stderr,
            "ERROR: failed to detach XDP from %s: %s\n",
            ifname,
            strerror(-err)
        );
    } else {
        banner(
            "SUCCESS: XDP detached cleanly from %s\n",
            ifname
        );
    }

    xdp_monitor_bpf__destroy(skel);

    return err ? 1 : 0;
}