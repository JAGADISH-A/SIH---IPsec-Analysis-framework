"""Standard-library-only PCAP reader and encrypted-traffic feature extractor.

Parses raw tcpdump PCAP files deterministically and derives timing/size
statistics that are observable on an encrypted (IPsec/ESP) stream.  No
payload content is ever inspected -- only packet sizes and arrival times
are used, which is everything a traffic classifier can see while the
link is ESP-encrypted.

Supports the classic PCAP format for both microsecond and nanosecond
timestamps in either byte order.

Direction determination
-----------------------
The capture happens on the WAN-facing interface of the source-side gateway
(or the source host itself in transport mode).  Outbound packets are the
encrypted frames whose *outer* IP source address equals the verified capture
point address (the gateway sending the source LAN's traffic to the remote
side); inbound packets are the encrypted frames whose outer IP destination
equals the capture point address (the remote side sending back).  The capture
point address comes from ``CAPTURE_TARGETS`` in ``capture.py`` and is verified
to be present on the resolved interface before every run, so the direction is
anchored to the observed wire, not guessed.  This deliberately does not depend
on the ESP SPI: decrypting or mapping SPIs would require inspecting ESP
header state that is not needed for direction and adds fragility.

Window normalisation
--------------------
``nominal_duration`` is the intended traffic (experiment) duration.  When
provided, all statistics are computed over the ``nominal_duration``-sized
window that contains the most packets (a two-pointer scan over the sorted
timestamps).  This anchors the feature-extraction window to the main traffic
burst and excludes the controlled pre-traffic listener probe (a few ESP
frames exchanged before the sender starts) and any trailing TCP teardown/keep
alive tail that arrives after the last data frame (observed as ~1s of
trailing tail for the "web" profile, which stretched ``flow_duration`` past
the nominal 30s).  It never trims real in-window traffic: the window slides to
the densest location, so sustained profiles keep every data frame.  Without
it, ``flow_duration`` silently exceeds the nominal 30s.
"""

import ipaddress
import math
import statistics
from collections import Counter

DEFAULT_BURST_WINDOW_S = 0.050
SMALL_PACKET_THRESHOLD = 300       # ESP outer-IP total length < 300 bytes
LARGE_PACKET_THRESHOLD = 1400      # ESP outer-IP total length > 1400 bytes
BURST_WINDOWS_S = (0.010, 0.050, 0.200)

# IKE is carried over UDP 500 (and UDP 4500 under NAT-T).  These ports are
# captured alongside ESP so the negotiation is observable in the dataset.
IKE_UDP_PORTS = (500, 4500)
# IKEv2 exchange types (RFC 7296) used for the exchange-type breakdown.
IKEV2_EXCHANGE_IKE_SA_INIT = 34
IKEV2_EXCHANGE_IKE_AUTH = 35
IKEV2_EXCHANGE_CREATE_CHILD_SA = 36
IKEV2_EXCHANGE_INFORMATIONAL = 37


def read_pcap(path):
    """Return [(timestamp_seconds, incl_len, ip_total_len, src, dst), ...].

    ``src``/``dst`` are the packed outer-IP addresses (4 or 16 bytes) of the
    ESP frame as observed on the wire.
    """
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError("truncated pcap global header")

        magic = header[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = "big"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "little"
        else:
            raise ValueError(f"unsupported pcap magic: {magic!r}")
        is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")

        linktype = int.from_bytes(header[20:24], endian)
        if linktype not in (1, 101, 127):
            raise ValueError(f"unsupported linktype: {linktype}")

        packets = []
        while True:
            record = fh.read(16)
            if len(record) < 16:
                break
            ts_sec = int.from_bytes(record[0:4], endian)
            ts_frac = int.from_bytes(record[4:8], endian)
            incl_len = int.from_bytes(record[8:12], endian)
            _orig_len = int.from_bytes(record[12:16], endian)

            data = fh.read(incl_len)
            if len(data) < incl_len:
                break

            parsed = _ip_fields(data, linktype)
            if parsed is None:
                continue
            if is_nano:
                timestamp = ts_sec + ts_frac / 1_000_000_000.0
            else:
                timestamp = ts_sec + ts_frac / 1_000_000.0
            packets.append((timestamp, incl_len) + parsed)

    if not packets:
        return []
    packets.sort(key=lambda p: p[0])
    return packets


def _ip_fields(data, linktype):
    """Return (ip_total_len, src, dst) for an ESP packet, else None."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        if ethertype == 0x0800:
            return _ipv4_fields(data, offset)
        if ethertype == 0x86DD:
            return _ipv6_fields(data, offset)
        return None
    if linktype == 101:  # Raw IPv4
        return _ipv4_fields(data, 0)
    if linktype == 127:  # Raw IPv6
        return _ipv6_fields(data, 0)
    return None


def _ipv4_fields(data, offset):
    if len(data) < offset + 20:
        return None
    protocol = data[offset + 9]
    if protocol != 50:  # ESP
        return None
    ip_total = int.from_bytes(data[offset + 2:offset + 4], "big")
    src = data[offset + 12:offset + 16]
    dst = data[offset + 16:offset + 20]
    return ip_total, src, dst


def _ipv6_fields(data, offset):
    if len(data) < offset + 40:
        return None
    next_header = data[offset + 6]
    if next_header != 50:  # ESP
        return None
    payload_len = int.from_bytes(data[offset + 4:offset + 6], "big")
    ip_total = 40 + payload_len
    src = data[offset + 8:offset + 24]
    dst = data[offset + 24:offset + 40]
    return ip_total, src, dst


def read_pcap_ike(path):
    """Return [(timestamp, incl_len, ip_total, src, dst, udp_port, version,
    exchange_type), ...] for IKE datagrams (UDP 500/4500) in the capture.

    Runs alongside ``read_pcap`` (which continues to return ESP frames only)
    so IKE negotiation frames are never silently dropped: they are a distinct
    record type with their own size/timing/exchange statistics.  Parse
    failures are degraded the same way as the ESP path (frame skipped), never
    raised.
    """
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            raise ValueError("truncated pcap global header")

        magic = header[:4]
        if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            endian = "big"
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            endian = "little"
        else:
            raise ValueError(f"unsupported pcap magic: {magic!r}")
        is_nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")

        linktype = int.from_bytes(header[20:24], endian)
        if linktype not in (1, 101, 127):
            raise ValueError(f"unsupported linktype: {linktype}")

        records = []
        while True:
            record = fh.read(16)
            if len(record) < 16:
                break
            ts_sec = int.from_bytes(record[0:4], endian)
            ts_frac = int.from_bytes(record[4:8], endian)
            incl_len = int.from_bytes(record[8:12], endian)
            _orig_len = int.from_bytes(record[12:16], endian)

            data = fh.read(incl_len)
            if len(data) < incl_len:
                break

            parsed = _ike_fields(data, linktype)
            if parsed is None:
                continue
            if is_nano:
                timestamp = ts_sec + ts_frac / 1_000_000_000.0
            else:
                timestamp = ts_sec + ts_frac / 1_000_000.0
            records.append((timestamp, incl_len) + parsed)

    if not records:
        return []
    records.sort(key=lambda p: p[0])
    return records


def _ike_fields(data, linktype):
    """Return (ip_total, src, dst, udp_port, version, exchange_type) for an
    IKE (UDP 500/4500) datagram, else None."""
    if linktype == 1:  # Ethernet
        if len(data) < 14:
            return None
        ethertype = int.from_bytes(data[12:14], "big")
        offset = 14
        if ethertype == 0x0800:
            return _udp_ike_ipv4(data, offset)
        if ethertype == 0x86DD:
            return _udp_ike_ipv6(data, offset)
        return None
    if linktype == 101:  # Raw IPv4
        return _udp_ike_ipv4(data, 0)
    if linktype == 127:  # Raw IPv6
        return _udp_ike_ipv6(data, 0)
    return None


def _udp_ike_ipv4(data, offset):
    if len(data) < offset + 20:
        return None
    if data[offset + 9] != 17:  # UDP
        return None
    ihl = (data[offset] & 0x0F) * 4
    udp_offset = offset + ihl
    if len(data) < udp_offset + 8:
        return None
    parsed = _ike_udp_common(data, udp_offset)
    if parsed is None:
        return None
    udp_port, version, exchange_type = parsed
    ip_total = int.from_bytes(data[offset + 2:offset + 4], "big")
    src = data[offset + 12:offset + 16]
    dst = data[offset + 16:offset + 20]
    return ip_total, src, dst, udp_port, version, exchange_type


def _udp_ike_ipv6(data, offset):
    if len(data) < offset + 40:
        return None
    if data[offset + 6] != 17:  # UDP
        return None
    udp_offset = offset + 40
    if len(data) < udp_offset + 8:
        return None
    parsed = _ike_udp_common(data, udp_offset)
    if parsed is None:
        return None
    udp_port, version, exchange_type = parsed
    payload_len = int.from_bytes(data[offset + 4:offset + 6], "big")
    ip_total = 40 + payload_len
    src = data[offset + 8:offset + 24]
    dst = data[offset + 24:offset + 40]
    return ip_total, src, dst, udp_port, version, exchange_type


def _ike_udp_common(data, udp_offset):
    """Return (udp_port, version, exchange_type) or None for a UDP payload."""
    sport = int.from_bytes(data[udp_offset:udp_offset + 2], "big")
    dport = int.from_bytes(data[udp_offset + 2:udp_offset + 4], "big")
    if sport not in IKE_UDP_PORTS and dport not in IKE_UDP_PORTS:
        return None
    udp_len = int.from_bytes(data[udp_offset + 4:udp_offset + 6], "big")
    if udp_len < 8:
        return None
    port = dport if dport in IKE_UDP_PORTS else sport

    # Payload after the UDP header.  On UDP 4500 a four-byte zero non-ESP
    # marker may precede the IKE header (NAT-T); skip it when present.
    ike_start = udp_offset + 8
    if port == 4500 and len(data) >= ike_start + 4:
        if int.from_bytes(data[ike_start:ike_start + 4], "big") == 0:
            ike_start += 4
    if len(data) < ike_start + 28:
        return port, 0, 0
    # IKE header layout (RFC 7296): 8-byte initiator SPI + 8-byte responder
    # SPI, then Next Payload (1), Version (1: high nibble = major),
    # Exchange Type (1), Flags (1), Message ID (4), Length (4).
    raw_version = data[ike_start + 17]
    if raw_version >> 4 == 2:
        version = 2
    elif raw_version >> 4 == 1:
        version = 1
    else:
        version = 0
    return port, version, data[ike_start + 18]


def _percentile(sorted_values, p):
    """Linear-interpolation percentile (identical to numpy's default)."""
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    rank = (len(sorted_values) - 1) * p / 100.0
    lo = math.floor(rank)
    hi = math.ceil(rank)
    if lo == hi:
        return float(sorted_values[lo])
    frac = rank - lo
    return sorted_values[lo] + frac * (sorted_values[hi] - sorted_values[lo])


def _densest_window(timestamps, duration):
    """Return (start, end) of the ``duration``-sized window with the most
    packets, anchoring the feature window on the main traffic burst.

    Falls back to ``[first, first + duration]`` when the capture is empty or
    already shorter than the nominal duration.
    """
    n = len(timestamps)
    if not n:
        return (0.0, 0.0)
    if duration <= 0 or timestamps[-1] - timestamps[0] <= duration:
        return (timestamps[0], timestamps[0] + duration)
    best_count = -1
    best_start = timestamps[0]
    left = 0
    for right in range(n):
        while timestamps[right] - timestamps[left] > duration:
            left += 1
        count = right - left + 1
        if count > best_count:
            best_count = count
            best_start = timestamps[left]
    return (best_start, best_start + duration)


def _burst_stats(timestamps, window=DEFAULT_BURST_WINDOW_S):
    """Burst statistics for a single gating window.

    A burst is a maximal run of packets whose consecutive gap is at most
    ``window``.  Only runs of more than one packet count as bursts.
    """
    if len(timestamps) < 2:
        return {"burst_count": 0, "mean_burst_packets": 0.0,
                "mean_burst_duration": 0.0, "burst_packet_ratio": 0.0}
    bursts = []
    current = [timestamps[0]]
    for ts in timestamps[1:]:
        if ts - current[-1] <= window:
            current.append(ts)
        else:
            bursts.append(current)
            current = [ts]
    bursts.append(current)

    burst_packets = [len(b) for b in bursts if len(b) > 1]
    burst_lens = [b[-1] - b[0] for b in bursts if len(b) > 1]
    in_burst = sum(len(b) for b in bursts if len(b) > 1)
    return {
        "burst_count": len(burst_packets),
        "mean_burst_packets": round(statistics.mean(burst_packets), 3) if burst_packets else 0.0,
        "mean_burst_duration": round(statistics.mean(burst_lens), 5) if burst_lens else 0.0,
        "burst_packet_ratio": round(in_burst / len(timestamps), 3),
    }


def extract_features(path, burst_window=DEFAULT_BURST_WINDOW_S,
                     capture_ip=None, nominal_duration=None):
    """Extract the numerical features from an encrypted IPsec capture.

    Parameters
    ----------
    path : str
        PCAP file to parse.
    burst_window : float, optional
        Gating window for the *legacy* single-window burst fields.
    capture_ip : str, optional
        Verified WAN address of the capture point; used to classify each
        frame as outbound (outer src == capture point) or inbound (outer
        dst == capture point).  When omitted, directional fields are zero.
    nominal_duration : float, optional
        Intended experiment (traffic) duration.  When provided the statistics
        are restricted to the ``nominal_duration``-sized window containing the
        most packets (the main traffic burst), discarding pre-traffic listener
        probes and trailing TCP teardown.  When omitted the whole capture is
        used.

    Unreadable/empty/invalid captures are handled safely: the caller receives
    a well-formed feature dict with ``packet_count == 0`` instead of an
    exception, so a trial can fail cleanly at the "no traffic captured" check.
    """
    try:
        packets = read_pcap(path)
    except (ValueError, OSError):
        packets = []
    try:
        ike_records = read_pcap_ike(path)
    except (ValueError, OSError):
        ike_records = []

    count = len(packets)
    if count and nominal_duration:
        timestamps_all = [p[0] for p in packets]
        window_start, window_end = _densest_window(timestamps_all, float(nominal_duration))
        packets = [p for p in packets if window_start <= p[0] <= window_end]
        count = len(packets)

    sizes = [p[2] for p in packets]
    timestamps = [p[0] for p in packets]

    if count:
        total_bytes = sum(sizes)
        duration = max(timestamps[-1] - timestamps[0], 1e-9)
    else:
        total_bytes = 0
        duration = 0.0

    if count > 1:
        iats = [b - a for a, b in zip(timestamps, timestamps[1:])]
        mean_iat = statistics.mean(iats)
        iat_std = statistics.stdev(iats) if len(iats) > 1 else 0.0
        min_iat = min(iats)
        max_iat = max(iats)
    else:
        mean_iat = iat_std = min_iat = max_iat = 0.0

    if count:
        mean_size = statistics.mean(sizes)
        size_std = statistics.stdev(sizes) if count > 1 else 0.0
        min_size = min(sizes)
        max_size = max(sizes)
    else:
        mean_size = size_std = min_size = max_size = 0.0

    out_sizes, in_sizes = _directional_sizes(packets, capture_ip)

    features = {
        "packet_count": count,
        "total_bytes": total_bytes,
        "mean_packet_size": round(mean_size, 3),
        "packet_size_std": round(size_std, 3),
        "min_packet_size": min_size,
        "max_packet_size": max_size,
        "packet_size_p10": round(_percentile(sorted(sizes), 10), 3),
        "packet_size_p50": round(_percentile(sorted(sizes), 50), 3),
        "packet_size_p90": round(_percentile(sorted(sizes), 90), 3),
        "packet_size_p95": round(_percentile(sorted(sizes), 95), 3),
        "packet_size_p99": round(_percentile(sorted(sizes), 99), 3),
        "unique_packet_size_count": len(Counter(sizes)),
        "packet_size_entropy": _size_entropy(sizes),
        "small_packet_ratio": round(_count_gt(sizes, SMALL_PACKET_THRESHOLD, below=True) / count, 3) if count else 0.0,
        "large_packet_ratio": round(_count_gt(sizes, LARGE_PACKET_THRESHOLD, below=False) / count, 3) if count else 0.0,
        "mean_inter_arrival_time": round(mean_iat, 6),
        "inter_arrival_time_std": round(iat_std, 6),
        "min_inter_arrival_time": round(min_iat, 6),
        "max_inter_arrival_time": round(max_iat, 6),
        "packets_per_second": round(count / duration, 3) if count else 0.0,
        "bytes_per_second": round(total_bytes / duration, 3) if count else 0.0,
        "flow_duration": round(duration, 6),
    }
    features.update(_directional_features(out_sizes, in_sizes, duration))
    features.update(_burst_stats(timestamps, window=burst_window))
    for window in BURST_WINDOWS_S:
        ms = int(window * 1000)
        stats = _burst_stats(timestamps, window=window)
        features[f"burst_count_{ms}ms"] = stats["burst_count"]
        features[f"mean_burst_packets_{ms}ms"] = stats["mean_burst_packets"]
    features.update(_ike_summary(ike_records))
    return features


def _ike_summary(records):
    """A distinct IKE record block alongside the ESP features.

    IKE frames are never folded into the ESP statistics: they are reported
    separately (count, bytes, sizes and per-exchange-type counts) so a
    capture that includes the negotiation can be distinguished from an
    ESP-only one and inspected per exchange.  When no IKE frames are present
    every field is zero / the version is 0.
    """
    if not records:
        return {
            "ike_packet_count": 0,
            "ike_datagram_bytes": 0,
            "ike_min_packet_size": 0,
            "ike_max_packet_size": 0,
            "ike_mean_packet_size": 0.0,
            "ike_sa_init_count": 0,
            "ike_auth_count": 0,
            "ike_create_child_sa_count": 0,
            "ike_informational_count": 0,
            "ike_version": 0,
        }
    sizes = [r[2] for r in records]
    versions = {r[6] for r in records if r[6] in (1, 2)}
    version = max(versions) if versions else 0
    exchanges = Counter(r[7] for r in records)
    return {
        "ike_packet_count": len(records),
        "ike_datagram_bytes": sum(sizes),
        "ike_min_packet_size": min(sizes),
        "ike_max_packet_size": max(sizes),
        "ike_mean_packet_size": round(statistics.mean(sizes), 3),
        "ike_sa_init_count": exchanges.get(IKEV2_EXCHANGE_IKE_SA_INIT, 0),
        "ike_auth_count": exchanges.get(IKEV2_EXCHANGE_IKE_AUTH, 0),
        "ike_create_child_sa_count": exchanges.get(IKEV2_EXCHANGE_CREATE_CHILD_SA, 0),
        "ike_informational_count": exchanges.get(IKEV2_EXCHANGE_INFORMATIONAL, 0),
        "ike_version": version,
    }


def _count_gt(sizes, threshold, below):
    if below:
        return sum(1 for s in sizes if s < threshold)
    return sum(1 for s in sizes if s > threshold)


def _directional_sizes(packets, capture_ip):
    """Split observed ESP frames into outbound/inbound size lists."""
    if not packets or not capture_ip:
        return [], []
    cap = ipaddress.ip_address(capture_ip).packed
    out, inbound = [], []
    for _ts, _inc, size, src, dst in packets:
        if src == cap:
            out.append(size)
        elif dst == cap:
            inbound.append(size)
    return out, inbound


def _size_entropy(sizes):
    """Shannon entropy (bits) of the observed packet-size frequency."""
    if not sizes:
        return 0.0
    n = float(len(sizes))
    counts = Counter(sizes).values()
    total = 0.0
    for c in counts:
        p = c / n
        total -= p * math.log2(p)
    return round(total, 3)


def _directional_features(out_sizes, in_sizes, duration):
    out_count = len(out_sizes)
    in_count = len(in_sizes)
    out_bytes = sum(out_sizes)
    in_bytes = sum(in_sizes)
    total = out_count + in_count
    total_bytes = out_bytes + in_bytes

    features = {
        "outbound_packet_count": out_count,
        "inbound_packet_count": in_count,
        "outbound_bytes": out_bytes,
        "inbound_bytes": in_bytes,
        "outbound_packet_ratio": round(out_count / total, 3) if total else 0.0,
        "inbound_packet_ratio": round(in_count / total, 3) if total else 0.0,
        "outbound_byte_ratio": round(out_bytes / total_bytes, 3) if total_bytes else 0.0,
        "inbound_byte_ratio": round(in_bytes / total_bytes, 3) if total_bytes else 0.0,
        "outbound_mean_packet_size": round(statistics.mean(out_sizes), 3) if out_sizes else 0.0,
        "inbound_mean_packet_size": round(statistics.mean(in_sizes), 3) if in_sizes else 0.0,
        "outbound_packets_per_second": round(out_count / duration, 3) if duration else 0.0,
        "inbound_packets_per_second": round(in_count / duration, 3) if duration else 0.0,
        "outbound_packet_size_p10": round(_percentile(sorted(out_sizes), 10), 3),
        "outbound_packet_size_p50": round(_percentile(sorted(out_sizes), 50), 3),
        "outbound_packet_size_p90": round(_percentile(sorted(out_sizes), 90), 3),
        "outbound_packet_size_p95": round(_percentile(sorted(out_sizes), 95), 3),
        "outbound_packet_size_p99": round(_percentile(sorted(out_sizes), 99), 3),
        "inbound_packet_size_p10": round(_percentile(sorted(in_sizes), 10), 3),
        "inbound_packet_size_p50": round(_percentile(sorted(in_sizes), 50), 3),
        "inbound_packet_size_p90": round(_percentile(sorted(in_sizes), 90), 3),
        "inbound_packet_size_p95": round(_percentile(sorted(in_sizes), 95), 3),
        "inbound_packet_size_p99": round(_percentile(sorted(in_sizes), 99), 3),
    }
    return features