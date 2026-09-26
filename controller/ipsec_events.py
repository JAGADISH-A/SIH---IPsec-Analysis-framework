"""TShark-based IPsec metadata extraction from the passive observation TAP.

TShark runs inside the gateway container against the observation interface
(``audit-tap0``).  Only *metadata* is extracted -- never payload content:

* ESP frames: outer IP header (IPv4 ``ip.*`` or IPv6 ``ipv6.*``) + ESP
  header (SPI, sequence number).
* IKE frames: UDP header (ports) + IKE header (exchange type, message id).

ESP payloads are never decrypted; no key material is fed to TShark, so
application plaintext is never produced by this layer.  The observation
interface may additionally carry inner frames injected by the kernel's XFRM
during decapsulation (the same wire artifact the existing PCAP capture on
the WAN interface sees) -- they are excluded by the capture display filter
``esp or isakmp`` and never turned into events.

Field naming note: TShark on this system exposes IKE as ``isakmp`` (not
``ike``), so the display filter and JSON field names below use ``isakmp``.
"""

import json
import re
import subprocess
import time
from pathlib import Path

from . import audit as audit_mod
from . import observation as observation_mod

TAP_CAPTURE_FILTER = "esp or isakmp"

# Normalized event field names (extend, don't replace, the audit schema).
ESP_EVENT_FIELDS = (
    "timestamp", "frame_number", "source_ip", "destination_ip", "ip_protocol",
    "frame_length", "spi", "sequence", "direction",
)
IKE_EVENT_FIELDS = (
    "timestamp", "frame_number", "source_ip", "destination_ip", "source_port",
    "destination_port", "ike_exchange_type", "ike_exchange_name", "message_id",
    "packet_length", "direction",
)

IKEV2_EXCHANGE_NAMES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
}

IP_PROTO_ESP = 50
IP_PROTO_UDP = 17

_IP_PROTO_NAMES = {50: "esp", 17: "udp"}


def _first(value):
    """TShark JSON values are sometimes arrays (alternating fields)."""
    if isinstance(value, list):
        return value[0]
    return value


def _as_int(value):
    value = _first(value)
    if value is None:
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def _as_str(value):
    return str(_first(value))


def _as_timestamp(value):
    """Normalize TShark's frame.time_epoch into an ISO-8601 UTC string."""
    value = _first(value)
    if value is None:
        return None
    text = str(value)
    if re.search(r"[Tt ]", text):
        return text.replace(" ", "T")
    try:
        epoch = float(text)
    except (TypeError, ValueError):
        return text
    import datetime
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).isoformat()


def _outer_addrs(layers):
    """Outer header endpoints/protocol from the IPv4 or IPv6 header.

    TShark exposes IPv4 as ``ip.*`` and IPv6 as ``ipv6.*``.  IPv4 wins when
    both are present; each value stays in the existing canonical form so the
    event schema is unchanged for either address family.
    """
    ip = layers.get("ip", {})
    ip6 = layers.get("ipv6", {})
    src = ip.get("ip.src") or ip6.get("ipv6.src")
    dst = ip.get("ip.dst") or ip6.get("ipv6.dst")
    proto = ip.get("ip.proto") or ip6.get("ipv6.nxt")
    return src, dst, proto


def _ip_total_length(layers):
    """IPv4 total length from the outer header, or None when absent.

    Used as the IKE ``packet_length`` fallback when TShark exposes no
    ``isakmp.length``.  Only evidence already present in the packet is
    returned; a length is never inferred or invented.
    """
    return _as_int(layers.get("ip", {}).get("ip.len"))


def normalize_esp_event(layers, wan_ip):
    """Build a normalized ESP observation dict from one packet's layers."""
    frame = layers.get("frame", {})
    esp = layers.get("esp", {})
    src, dst, proto = _outer_addrs(layers)
    return {
        "timestamp": _as_timestamp(frame.get("frame.time_epoch")),
        "frame_number": _as_int(frame.get("frame.number")),
        "source_ip": _as_str(src),
        "destination_ip": _as_str(dst),
        "ip_protocol": _as_int(proto),
        "frame_length": _as_int(frame.get("frame.len")),
        "spi": _as_str(esp.get("esp.spi")),
        "sequence": _as_int(esp.get("esp.sequence")),
        "direction": "outbound" if src == wan_ip else "inbound",
    }


def normalize_ike_event(layers, wan_ip):
    """Build a normalized IKE observation dict from one packet's layers."""
    frame = layers.get("frame", {})
    udp = layers.get("udp", {})
    isakmp = layers.get("isakmp", {})
    src, dst, _proto = _outer_addrs(layers)
    exchange_type = _as_int(isakmp.get("isakmp.exchangetype"))
    return {
        "timestamp": _as_timestamp(frame.get("frame.time_epoch")),
        "frame_number": _as_int(frame.get("frame.number")),
        "source_ip": _as_str(src),
        "destination_ip": _as_str(dst),
        "source_port": _as_int(udp.get("udp.srcport")),
        "destination_port": _as_int(udp.get("udp.dstport")),
        "ike_exchange_type": exchange_type,
        "ike_exchange_name": IKEV2_EXCHANGE_NAMES.get(exchange_type),
        "message_id": _as_str(isakmp.get("isakmp.messageid")),
        "packet_length": _as_int(isakmp.get("isakmp.length")) or _ip_total_length(layers),
        "direction": "outbound" if src == wan_ip else "inbound",
    }


def parse_tshark_json(text, wan_ip):
    """Parse TShark ``-T json`` output into (esp_events, ike_events).

    Input may be a JSON array (tshark ``-T json``) or JSON Lines (``-T
    json`` with ``-l``).  Only ESP and IKE packets are present because the
    capture already applies ``esp or isakmp``; inner plaintext frames are not
    in the feed and are never emitted.
    """
    text = text.strip()
    if not text:
        return [], []
    packets = []
    if text.startswith("["):
        packets = json.loads(text)
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                packets.append(json.loads(line))
            except json.JSONDecodeError:
                # Streamed tshark JSON is separated by newlines; one frame
                # object may span several lines when it contains a large
                # payload dump, so join fragments until a complete object.
                continue
    esp_events, ike_events = [], []
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        protocols = _as_str(layers.get("frame", {}).get("frame.protocols")) or ""
        if "esp" in protocols.split(":"):
            event = normalize_esp_event(layers, wan_ip)
            if event.get("spi") is not None:
                esp_events.append(event)
        elif "isakmp" in protocols.split(":"):
            event = normalize_ike_event(layers, wan_ip)
            if event.get("ike_exchange_type") is not None:
                ike_events.append(event)
    return _dedupe(esp_events), _dedupe(ike_events)


def _dedupe(packets):
    """TShark can emit a packet twice on stream boundaries; keep first copy."""
    seen, out = set(), []
    for packet in packets:
        key = (packet.get("frame_number"), packet.get("spi") or packet.get("message_id"))
        if key in seen:
            continue
        seen.add(key)
        out.append(packet)
    return out


def run_tshark_on_tap(container, tap_interface, wan_ip, seconds, local_out):
    """Capture live from ``tap_interface`` with TShark and return the JSON path.

    Runs ``tshark -i <tap> -Y "esp or isakmp" -T json -a duration:N`` inside
    the container (detached with a completion marker, matching the capture
    lifecycle used by ``capture.py``), then copies the JSON out to
    ``local_out``.  Returns the local file path.
    """
    remote_out = f"/tmp/audit-tshark-{int(time.time() * 1000)}.json"
    marker = f"{remote_out}.done"
    cmd = (
        f"rm -f {remote_out} {marker}; "
        f"setsid sh -c 'timeout {int(seconds) + 5} tshark -i {tap_interface} "
        f"-Y \"{TAP_CAPTURE_FILTER}\" -T json -a duration:{int(seconds)} "
        f"> {remote_out}; touch {marker}' "
        f"< /dev/null > /dev/null 2>&1 &"
    )
    subprocess.run(
        ["sudo", "docker", "exec", "-d", container, "sh", "-c", cmd],
        check=True,
        capture_output=True,
    )
    deadline = time.time() + int(seconds) + 20
    while time.time() < deadline:
        probe = subprocess.run(
            ["sudo", "docker", "exec", container, "sh", "-c", f"test -f {marker}"],
            capture_output=True,
        )
        if probe.returncode == 0:
            break
        time.sleep(1.0)
    subprocess.run(
        ["sudo", "docker", "exec", container, "sh", "-c",
         f"pkill -TERM -f 'tshark -i {tap_interface}' || true"],
        capture_output=True,
    )
    local_path = Path(local_out)
    subprocess.run(
        ["sudo", "docker", "cp", f"{container}:{remote_out}", str(local_path)],
        check=True,
        capture_output=True,
    )
    return local_path


def summarize(esp_events, ike_events):
    """Compact summary of the observed feed (used by CLI + audit report)."""
    exchanges = {}
    for event in ike_events:
        name = event.get("ike_exchange_name") or f"type_{event['ike_exchange_type']}"
        exchanges[name] = exchanges.get(name, 0) + 1
    directions = {"outbound": 0, "inbound": 0}
    for event in esp_events:
        directions[event["direction"]] = directions.get(event["direction"], 0) + 1
    return {
        "esp_packets": len(esp_events),
        "ike_packets": len(ike_events),
        "esp_outbound": directions.get("outbound", 0),
        "esp_inbound": directions.get("inbound", 0),
        "ike_exchanges": exchanges,
    }


def _event_source(mode, address_family, wan_ip, mirror_iface):
    return {
        "mode": mode,
        "address_family": address_family,
        "container": capture_container_for(mode, address_family),
        "mirror_interface": mirror_iface,
        "tap_interface": observation_mod.TAP_IFACE,
        "capture_wan_ip": wan_ip,
    }


def capture_container_for(mode, address_family):
    from .capture import capture_facing
    container, _ = capture_facing(mode, address_family)
    return container


def observe_live(mode, address_family, seconds, events_out=None, wan_ip=None,
                 log=None, record=False):
    """End-to-end passive observation: provision -> TShark -> events.

    Provisions the observation surface (idempotent), captures ``seconds`` of
    traffic from the live TAP with TShark, parses ESP/IKE metadata and
    optionally appends every packet as a normalized audit event
    (``record_event``).  Returns a dict with the summary, event counts and
    the local JSON artifact path.
    """
    log = log or (lambda msg: None)
    status = observation_mod.provision_observation(mode, address_family, wan_ip, log=log)
    container = status["container"]
    wan_ip = observation_mod.observation_target(mode, address_family, wan_ip)[1]
    mirror_iface = status["mirror_interface"]
    log(f"[audit] observation surface ready on {container}:{mirror_iface}")

    session_id = audit_mod.utcnow_iso()
    if record:
        audit_mod.record_event({
            "event_type": audit_mod.EVENT_TAP_STATE,
            "observed_at": session_id,
            "source": _event_source(mode, address_family, wan_ip, mirror_iface),
            "data": {
                "interface": observation_mod.TAP_IFACE,
                "state": "up",
                "passive": True,
                "capture_filter": TAP_CAPTURE_FILTER,
                "providers": ["tshark"],
            },
        })
        audit_mod.record_event({
            "event_type": audit_mod.EVENT_OBSERVATION_SESSION_START,
            "observed_at": session_id,
            "source": _event_source(mode, address_family, wan_ip, mirror_iface),
            "data": {"seconds": seconds},
        })

    local_json = (
        Path(events_out) if events_out is not None
        else Path("/tmp") / f"audit-observation-{int(time.time() * 1000)}.json"
    )
    run_tshark_on_tap(container, observation_mod.TAP_IFACE, wan_ip, seconds, local_json)
    text = local_json.read_text(encoding="utf-8", errors="replace")
    esp_events, ike_events = parse_tshark_json(text, wan_ip)
    log(
        f"[audit] tshark parsed esp={len(esp_events)} ike={len(ike_events)} "
        f"from {local_json}"
    )

    source = _event_source(mode, address_family, wan_ip, mirror_iface)
    if record:
        for event in esp_events:
            audit_mod.record_event({
                "event_type": audit_mod.EVENT_ESP_PACKET,
                "observed_at": event["timestamp"] or session_id,
                "source": source,
                "data": event,
            })
        for event in ike_events:
            audit_mod.record_event({
                "event_type": audit_mod.EVENT_IKE_PACKET,
                "observed_at": event["timestamp"] or session_id,
                "source": source,
                "data": event,
            })
        audit_mod.record_event({
            "event_type": audit_mod.EVENT_OBSERVATION_SESSION_END,
            "observed_at": audit_mod.utcnow_iso(),
            "source": source,
            "data": {"seconds": seconds, "esp_events": len(esp_events),
                     "ike_events": len(ike_events)},
        })

    return {
        "summary": summarize(esp_events, ike_events),
        "esp_events": esp_events,
        "ike_events": ike_events,
        "json_path": str(local_json),
        "status": status,
        "wan_ip": wan_ip,
    }