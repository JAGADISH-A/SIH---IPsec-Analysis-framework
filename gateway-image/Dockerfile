FROM openeuler/strongswan:6.0.3-oe2403sp4

RUN dnf install -y \
        tcpdump \
        iputils \
        wireshark-cli \
    && dnf clean all \
    && rm -rf /var/cache/dnf
