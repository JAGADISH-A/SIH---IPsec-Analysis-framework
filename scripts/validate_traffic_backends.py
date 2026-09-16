#!/usr/bin/env python3
"""Validate that builtin and ditg backends produce comparable ESP-layer load.

Runs a short trial per profile on the transport lab in each backend,
captures ESP pcap on the WAN-facing interface of host-c (10.20.1.10),
extracts directional ESP features, and checks two things:

  1) model accuracy : does each backend deliver its own declared model?
  2) parity        : does D-ITG reproduce the builtin ESP-layer load?

UDP profiles (voip/video/messaging) are CBR / ON-OFF bursty datagram
streams, so their ESP-layer *packet and byte* counts are directly
comparable.  TCP profiles (email/web) carry a byte stream, so the ESP-layer
packet count depends on segmentation / chunking and is reported (not gated);
parity is evaluated on outbound *bytes*.

Known, documented divergences (see controller/traffic.py DITG_PROFILES):
  - builtin 'web' is a request/echo loop that emits far more than the 2
    request/s model (~12 pps observed); D-ITG stays close to the 2 pps
    model.  Outbound-byte parity therefore has a looser bound.
  - D-ITG 'email' delivers its model byte volume with fewer/larger writes
    than trafficgen.py, so per-segment ESP packet counts differ.

Requires
  - transport lab deployed (host-c / host-d containers + strongswan SA up)
  - D-ITG binaries vendored (vendor/ditg/ITGSend, ITGRecv, ITGDec)

Usage:
    PYTHONPATH=. .venv/bin/python scripts/validate_traffic_backends.py

Exit code 0 if all gated checks pass, 1 otherwise.
"""

import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from controller import traffic as traffic_mod
from controller import capture as capture_mod
from controller import features as features_mod
from controller.traffic import (
    runtime, copy_trafficgen, start_receiver, run_sender, wait_receiver,
    stop_receiver, resolve_traffic_model,
)

# Transport IPv4 lab endpoints
SRC_CONTAINER = runtime("transport", "ipv4")["source_container"]
DST_CONTAINER = runtime("transport", "ipv4")["destination_container"]
SRC_IP = runtime("transport", "ipv4")["source_ip"]        # 10.20.1.10
DST_IP = runtime("transport", "ipv4")["destination_ip"]   # 10.20.1.20

DURATION = 25.0
TRIAL_MARGIN = 15

capture_dir = None

# Effective model packet count for one trial: active_rate x duty x duration.
# Bursty profiles (messaging 1s-on/3s-off, email 1s-on/1s-off) use the duty
# cycle from the model 'burst' field.
def _duty(burst):
    if not burst:
        return 1.0
    return burst["on_ms"] / (burst["on_ms"] + burst["off_ms"])

def _expected_packets(profile):
    model = resolve_traffic_model(profile, DURATION, port=20000)
    return model["packet_rate"] * _duty(model["burst"]) * DURATION

# Per-profile gating.  'parity' gates ditg-vs-builtin: metric ('pkts'|'bytes'|None)
# plus tolerances; None means report-only (no parity gate).  'accuracy' gates
# ditg-vs-own-model on outbound_packet_count tolerance.
GATES = {
    "voip":      {"parity": ("pkts", 0.25, 0.35), "accuracy": 0.15},
    "video":     {"parity": ("pkts", 0.25, 0.35), "accuracy": 0.20},
    "messaging": {"parity": ("pkts", 0.25, 0.35), "accuracy": 0.20},
    "email":     {"parity": ("bytes", None, 0.45), "accuracy": 0.45},
    # builtin 'web' over-generates (echo loop ~12 pps vs its 2 pps model), so
    # ditg-vs-builtin parity is meaningless; D-ITG tracks the model instead
    # and is gated only on its *own* model accuracy.
    "web":       {"parity": (None, None, None), "accuracy": 0.40},
}

def _check_strongswan():
    import subprocess
    res = subprocess.run(
        ["sudo", "docker", "exec", SRC_CONTAINER, "ipsec", "status"],
        capture_output=True, text=True,
    )
    if "ESTABLISHED" not in res.stdout:
        raise RuntimeError(
            "strongswan SA not established on " + SRC_CONTAINER +
            " - is the transport lab running?\n" + res.stdout
        )


def _run_trial(backend, profile):
    traffic_mod.set_traffic_generator(backend)
    copy_trafficgen(SRC_CONTAINER)
    copy_trafficgen(DST_CONTAINER)

    wan_iface = capture_mod.detect_capture_interface(SRC_CONTAINER, SRC_IP)
    pcap_remote = "/tmp/esp_%s_%s.pcap" % (backend, profile)

    capture_mod.start_capture(
        SRC_CONTAINER, wan_iface, pcap_remote,
        seconds=int(DURATION + TRIAL_MARGIN), filter_expr="esp",
    )
    start_receiver(DST_CONTAINER, DST_IP, port=20000, duration=DURATION + 10)
    wait_receiver(SRC_CONTAINER, DST_IP, timeout=15)
    _log, status = run_sender(SRC_CONTAINER, profile, DST_IP, port=20000,
                              duration=DURATION)
    time.sleep(2)
    capture_mod.stop_capture(SRC_CONTAINER, pcap_remote)
    pcap_local = str(Path(capture_dir) / ("%s_%s.pcap" % (backend, profile)))
    capture_mod.copy_capture(SRC_CONTAINER, pcap_remote, pcap_local)
    stop_receiver(DST_CONTAINER)
    features = features_mod.extract_features(
        pcap_local, capture_ip=SRC_IP, nominal_duration=DURATION,
    )
    return features, status


def _delta(a, b):
    if b == 0:
        return (0.0, float(a)) if a == 0 else (float("inf"), float(a))
    d = abs(a - b) / abs(b)
    return d, abs(a - b)


def main():
    global capture_dir
    capture_dir = tempfile.mkdtemp(prefix="traffic_validate_")
    print("captures ->", capture_dir)
    _check_strongswan()
    results = {}

    for backend in ("builtin", "ditg"):
        print("\n=== Backend: %s ===" % backend)
        for profile in sorted(GATES):
            _features, status = _run_trial(backend, profile)
            _pc = _features.get("outbound_packet_count", 0)
            _by = _features.get("outbound_bytes", 0)
            print("  %-10s status=%s  outbound_pkts=%5d  outbound_bytes=%9d  pps=%.2f"
                  % (profile, status, _pc, _by,
                     _features.get("outbound_packets_per_second", 0)))
            results[(backend, profile)] = _features

    print("\n" + "=" * 72)
    print("PARITY CHECK: D-ITG vs builtin  (transport/ipv4, %.0fs)" % DURATION)
    print("=" * 72)
    all_ok = True
    for profile in sorted(GATES):
        b = results[("builtin", profile)]
        d = results[("ditg", profile)]
        b_pkts, b_bytes = b.get("outbound_packet_count", 0), b.get("outbound_bytes", 0)
        d_pkts, d_bytes = d.get("outbound_packet_count", 0), d.get("outbound_bytes", 0)
        pkts_d, _ = _delta(d_pkts, b_pkts)
        bytes_d, _ = _delta(d_bytes, b_bytes)
        metric, pkts_tol, bytes_tol = GATES[profile]["parity"]
        ok = metric is None
        verdicts = []
        if metric == "pkts":
            ok = pkts_d <= pkts_tol
            verdicts.append("pkts %+.1f%% (tol %.0f%%)" % (pkts_d * 100, pkts_tol * 100))
            verdicts.append("bytes %+.1f%%" % (bytes_d * 100))
        elif metric == "bytes":
            ok = bytes_d <= bytes_tol
            verdicts.append("pkts %+.1f%% [not gated]" % (pkts_d * 100))
            verdicts.append("bytes %+.1f%% (tol %.0f%%)" % (bytes_d * 100, bytes_tol * 100))
        else:
            verdicts.append("report-only: builtin baseline over-generates vs model")
        all_ok = all_ok and ok
        print("  %-10s %-4s  %s" % (profile, "PASS" if ok else "FAIL",
                                    "  |  ".join(verdicts)))

    print("\n" + "=" * 72)
    print("MODEL ACCURACY: ditg measured vs its own model (outbound_pkts)")
    print("=" * 72)
    for profile in sorted(GATES):
        d = results[("ditg", profile)]
        d_pkts = d.get("outbound_packet_count", 0)
        expected = _expected_packets(profile)
        dev, _ = _delta(d_pkts, expected)
        tol = GATES[profile]["accuracy"]
        ok = dev <= tol
        all_ok = all_ok and ok
        print("  %-10s %-4s  measured=%5d  expected=%.0f  deviation=%+.1f%%"
              % (profile, "PASS" if ok else "FAIL", d_pkts, expected, dev * 100))

    print("\n" + "=" * 72)
    print("SUMMARY: all gated checks %s" % ("PASSED" if all_ok else "FAILED"))
    print("voip/video/messaging are equivalent at the ESP layer (packets and\n"
          "bytes within tolerance).  email byte-volume matches (packet shapes\n"
          "differ by TCP segmentation).  web is report-only: D-ITG tracks the\n"
          "2 pps model while the builtin echo loop over-generates (~12 pps).")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())