# IPsec transport testbed host.
#
# The eBPF monitoring agent (ebpf/xdp_monitor) is staged into the image so
# that the transport hosts' invoke-xdp-monitor lifecycle (see the topology)
# runs the SAME binary that was built and verified on the host.  The image is
# built by scripts/install.sh AFTER the eBPF build so the COPY below always
# finds a fresh ebpf/xdp_monitor artifact.
FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
        iproute2 \
        iputils-ping \
        strongswan-swanctl \
        strongswan-charon \
        python3 \
        tcpdump \
        iptables \
        libbpf1 \
        libelf1 \
        zlib1g \
        libzstd1 \
    && rm -rf /var/lib/apt/lists/*

# Stage the eBPF monitor (built on the host, verified against the same CLANG/
# libbpf toolchain).  It is not recompiled inside the container.
COPY ebpf/xdp_monitor /usr/sbin/xdp_monitor

CMD ["sleep", "infinity"]