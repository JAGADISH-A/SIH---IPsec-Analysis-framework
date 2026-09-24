#!/usr/bin/env python3
"""Controlled laboratory traffic generator for the IPsec testbed.

Runs inside a testbed container and produces one of six pre-defined
traffic profiles toward a target IP.  It is meant to emulate shaping
*observable* characteristics of common application classes on an
encrypted (IPsec) link -- nothing more.  It does not implement any real
application protocol.

Two roles:

  --role send   generate a traffic profile for --duration seconds.
  --role recv   run a small echo/drain receiver that must be started on
                the destination host *before* the sender (TCP profiles
                need an active reader so that sends are not throttled).

Only the Python standard library is used.
"""

import argparse
import math
import socket
import subprocess
import sys
import threading
import time

PROFILES = {
    "voip": {
        "kind": "udp",
        "interval_s": 0.020,
        "size": 160,
        "label": "UDP periodic 20ms/160B low-bitrate",
    },
    "video": {
        "kind": "udp",
        "interval_s": 0.004,
        "size": 1200,
        "label": "UDP sustained 4ms/1200B high-bitrate",
    },
    "messaging": {
        "kind": "udp_burst",
        "burst_interval_s": 0.005,
        "burst_packets": 200,
        "idle_s": 3.0,
        "size": 110,
        "label": "UDP bursty 5ms/110B with active-idle",
    },
    "email": {
        "kind": "tcp_burst",
        "burst_size": 8192,
        "inter_burst_s": 0.2,
        "idle_every": 5,
        "idle_s": 1.0,
        "label": "TCP burst-oriented low-moderate bitrate",
    },
    "web": {
        "kind": "tcp_web",
        "request_size": 320,
        "idle_s": 0.5,
        "label": "TCP request/response with idle periods",
    },
    "icmp": {
        "kind": "icmp",
        "interval_s": 0.2,
        "size": 32,
        "label": "ICMP echo regular-interval small packets",
    },
}


class Statistics:
    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.start = time.monotonic()

    def record(self, nbytes):
        self.packets += 1
        self.bytes += nbytes

    def report(self):
        elapsed = max(time.monotonic() - self.start, 1e-6)
        rate = self.bytes * 8.0 / elapsed
        print(
            "STATS packets=%d bytes=%d seconds=%.2f bitrate=%.0f_bps"
            % (self.packets, self.bytes, elapsed, rate)
        )


def paced_udp(profile, target_ip, target_port, duration, stats):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        payload = bytes(profile["size"])
        interval = profile["interval_s"]
        deadline = time.monotonic() + duration
        next_time = time.monotonic()
        while True:
            if interval <= 0:
                if time.monotonic() >= deadline:
                    break
                sock.sendto(payload, (target_ip, target_port))
                stats.record(len(payload))
                continue
            if next_time >= deadline:
                break
            sock.sendto(payload, (target_ip, target_port))
            stats.record(len(payload))
            next_time += interval
            delta = next_time - time.monotonic()
            if delta > 0:
                time.sleep(delta)
    finally:
        sock.close()


def paced_udp_burst(profile, target_ip, target_port, duration, stats):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        payload = bytes(profile["size"])
        interval = profile["burst_interval_s"]
        burst_count = profile["burst_packets"]
        idle_s = profile["idle_s"]
        deadline = time.monotonic() + duration
        while True:
            next_time = time.monotonic()
            for _ in range(burst_count):
                sock.sendto(payload, (target_ip, target_port))
                stats.record(len(payload))
                next_time += interval
                delta = next_time - time.monotonic()
                if delta > 0:
                    time.sleep(delta)
            time.sleep(idle_s)
            if time.monotonic() >= deadline:
                break
    finally:
        sock.close()


def tcp_drain(sock):
    while True:
        try:
            chunk = sock.recv(65536)
        except OSError:
            return
        if not chunk:
            return


def tcp_burst(profile, target_ip, target_port, duration, stats):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((target_ip, target_port))
    except OSError as exc:
        raise RuntimeError("TCP connect to %s:%d failed: %s" % (target_ip, target_port, exc))
    walker = threading.Thread(target=tcp_drain, args=(sock,), daemon=True)
    walker.start()
    try:
        chunk = bytes(profile["burst_size"])
        inter_burst = profile["inter_burst_s"]
        deadline = time.monotonic() + duration
        while True:
            for i in range(profile["idle_every"]):
                if time.monotonic() >= deadline:
                    break
                sock.sendall(chunk)
                stats.record(len(chunk))
                time.sleep(inter_burst)
            if time.monotonic() >= deadline:
                break
            time.sleep(profile["idle_s"])
    finally:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()


def tcp_web(profile, target_ip, target_port, duration, stats):
    family = socket.AF_INET6 if ":" in target_ip else socket.AF_INET
    deadline = time.monotonic() + duration
    request = bytes(profile["request_size"])
    while True:
        if time.monotonic() >= deadline:
            break
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect((target_ip, target_port))
            stats.packets += 1
            stats.bytes += len(request)
            sock.sendall(request)
            received = 0
            while received < len(request):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
            sock.close()
        except OSError as exc:
            sock.close()
            raise RuntimeError("web connection failed: %s" % exc)
        time.sleep(profile["idle_s"])


def icmp_echo(profile, target_ip, duration, stats):
    family_flag = "-6" if ":" in target_ip else "-4"
    cmd = [
        "ping",
        family_flag,
        "-i",
        str(profile["interval_s"]),
        "-s",
        str(profile["size"]),
        "-w",
        str(int(duration)),
        target_ip,
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    last = [0]

    def scanner():
        line_decoder = getattr(proc.stdout, "readline", None)
        if line_decoder is None:
            return
        for raw in iter(line_decoder, b""):
            text = raw.decode(errors="replace").strip()
            print(text)
            if "bytes from" in text:
                last[0] += 1

    collector = threading.Thread(target=scanner, daemon=True)
    collector.start()
    proc.wait()
    collector.join(timeout=1)
    stats.packets = last[0]
    stats.bytes = last[0] * (profile["size"] + 8)
    if last[0] == 0:
        raise RuntimeError("ping produced no replies (no traffic crossed the tunnel)")
    if proc.returncode not in (0, 1):
        raise RuntimeError("ping exited with code %d" % proc.returncode)


def run_send(profile_name, target, port, duration):
    if profile_name not in PROFILES:
        raise SystemExit("unknown profile: %s" % profile_name)
    profile = PROFILES[profile_name]
    print("PROFILE %s: %s" % (profile_name, profile["label"]))
    print("TARGET %s:%d DURATION %.0fs" % (target, port, duration))
    stats = Statistics()
    kind = profile["kind"]
    if kind == "udp":
        paced_udp(profile, target, port, duration, stats)
    elif kind == "udp_burst":
        paced_udp_burst(profile, target, port, duration, stats)
    elif kind == "tcp_burst":
        tcp_burst(profile, target, port, duration, stats)
    elif kind == "tcp_web":
        tcp_web(profile, target, port, duration, stats)
    elif kind == "icmp":
        icmp_echo(profile, target, duration, stats)
    else:
        raise SystemExit("unsupported profile kind: %s" % kind)
    stats.report()


def run_recv(target, port, duration):
    family = socket.AF_INET6 if ":" in target else socket.AF_INET
    stats = Statistics()

    udp_sock = socket.socket(family, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind((target, port))
    print("RECV UDP bound %s:%d" % (target, port))

    def udp_loop():
        try:
            while True:
                data, _addr = udp_sock.recvfrom(65535)
                stats.record(len(data))
        except OSError:
            pass

    threading.Thread(target=udp_loop, daemon=True).start()

    def handle_tcp(client):
        try:
            while True:
                data = client.recv(65536)
                if not data:
                    break
                stats.record(len(data))
                client.sendall(data)
        except OSError:
            pass
        finally:
            client.close()

    tcp_server = socket.socket(family, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    tcp_server.bind(("0.0.0.0" if not family == socket.AF_INET6 else "::", port))
    tcp_server.listen(16)
    tcp_server.settimeout(1.0)
    print("RECV TCP listening %s:%d" % (target, port))

    deadline = time.monotonic() + duration
    while time.monotonic() < deadline:
        try:
            client, _addr = tcp_server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=handle_tcp, args=(client,), daemon=True).start()
    tcp_server.close()
    udp_sock.close()
    stats.report()


def main(argv=None):
    parser = argparse.ArgumentParser(description="IPsec testbed traffic generator")
    parser.add_argument("--role", choices=["send", "recv"], required=True)
    parser.add_argument("--profile", choices=sorted(PROFILES), default="voip")
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=20000)
    parser.add_argument("--duration", type=float, default=30.0)
    args = parser.parse_args(argv)

    if args.role == "send":
        run_send(args.profile, args.target, args.port, args.duration)
    else:
        run_recv(args.target, args.port, args.duration)
    return 0


if __name__ == "__main__":
    sys.exit(main())