FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y \
        iproute2 \
        iputils-ping \
        strongswan-swanctl \
        strongswan-charon \
        python3 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
