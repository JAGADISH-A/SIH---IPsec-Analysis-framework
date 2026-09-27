#!/usr/bin/env python3
"""Run the passive multi-SA correlation over a real capture and report.

Reads a PCAP of a gateway carrying several simultaneous IPsec SAs (the ones
produced by ``scripts/multi-sa-testbed.sh``), resolves each frame to a passive
SA identity, and reports what the SA-scoped path sees versus the single-SA
blended path.

Passive throughout: it reads a capture file and prints observations.  It
configures nothing, enforces nothing, and never writes back to the network.

    python scripts/multi-sa-verify.py \
        --pcap results/observed-state/multi-sa/multi-sa.pcap \
        --capture-ip 192.168.100.1 \
        --plan results/datasets/acc-eng-02/staging/plan.json
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import sys
import warnings
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

warnings.filterwarnings("ignore")

from correlation.ml.live_correlation import (  # noqa: E402
    correlate_live_events,
    feature_windows_from_events,
    observed_states_per_sa,
)
from correlation.sa_correlation import read_pcap_events  # noqa: E402


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True, help="capture to read")
    parser.add_argument("--capture-ip", required=True,
                        help="observed capture-point address (the gateway)")
    parser.add_argument("--plan", required=True,
                        help="materialized plan.json for expected state")
    parser.add_argument("--run-id", default="acc-eng-02")
    parser.add_argument("--experiment-id", default="acc-eng-02-exp-0001")
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--attempt-number", type=int, default=1)
    parser.add_argument("--endpoints", default=None,
                        help="expected endpoints as a=IP,b=IP")
    parser.add_argument("--json-out", default=None,
                        help="also write the full report as JSON here")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    pcap = Path(args.pcap)
    if not pcap.is_file():
        print(f"no such capture: {pcap}", file=sys.stderr)
        return 2

    endpoints = None
    if args.endpoints:
        endpoints = {}
        for item in args.endpoints.split(","):
            key, _, value = item.partition("=")
            endpoints[key.strip()] = value.strip()

    events = read_pcap_events(str(pcap))
    if not events:
        print("no ESP frames decoded from the capture", file=sys.stderr)
        return 1

    report: dict = {
        "passive_only": True,
        "capture": {
            "path": str(pcap),
            "sha256": sha256(pcap),
            "byte_size": pcap.stat().st_size,
            "esp_frames": len(events),
            "capture_ip": args.capture_ip,
        },
    }

    print("=" * 72)
    print("PASSIVE MULTI-SA CORRELATION")
    print("=" * 72)
    print(f"capture      : {pcap}")
    print(f"sha256       : {report['capture']['sha256']}")
    print(f"ESP frames   : {len(events)}")
    print()

    # -- per-SA observed state -------------------------------------------
    states = observed_states_per_sa(events, capture_ip=args.capture_ip)
    report["sa_groups"] = {}
    print("SA GROUPS (from observed evidence only)")
    print("-" * 72)
    for group, state in sorted(states.items()):
        spis = sorted(item.spi for item in states[group].spis)
        packets = sum(item.packet_count for item in states[group].spis)
        report["sa_groups"][group] = {
            "spis": spis,
            "packets": packets,
            "tunnel_seen": state.tunnel_seen,
        }
        print(f"  {group}")
        print(f"     spis={spis}  packets={packets}  tunnel_seen={state.tunnel_seen}")
    print()

    # -- per-SA windows ---------------------------------------------------
    scoped = feature_windows_from_events(
        events, capture_ip=args.capture_ip, sa_scoped=True
    )
    merged = feature_windows_from_events(
        events, capture_ip=args.capture_ip
    )
    per_sa = collections.defaultdict(lambda: {"windows": 0, "packets": 0})
    for window in scoped:
        group = window.sa_identity["sa_group_id"]
        per_sa[group]["windows"] += 1
        per_sa[group]["packets"] += window.features.get("packet_count", 0)
    attributed = sum(item["packets"] for item in per_sa.values())
    report["windows"] = {
        "sa_scoped": len(scoped),
        "merged": len(merged),
        "per_sa": {k: dict(v) for k, v in per_sa.items()},
        "packets_attributed": attributed,
        "packets_in_capture": len(events),
    }
    print("100 ms WINDOWS")
    print("-" * 72)
    print(f"  SA-scoped : {len(scoped)}")
    print(f"  merged    : {len(merged)}   (what the single-SA path reports)")
    for group in sorted(per_sa):
        print(f"     {group}: {per_sa[group]['windows']} windows, "
              f"{per_sa[group]['packets']} packets")
    print(f"  packet accounting: {attributed} attributed / {len(events)} captured")
    if attributed != len(events):
        print("  WARNING: packet counts do not reconcile", file=sys.stderr)
    print()

    # -- RF per SA --------------------------------------------------------
    plan_params = dict(
        plan_path=str(args.plan),
        sequence=args.sequence,
        experiment_id=args.experiment_id,
        attempt_number=args.attempt_number,
        run_id=args.run_id,
        capture_ip=args.capture_ip,
        on_ml_error="record",
    )
    if endpoints:
        plan_params["endpoints"] = endpoints

    run = correlate_live_events(events, sa_scoped=True, **plan_params)
    classes = collections.defaultdict(collections.Counter)
    for result in run.results:
        if result.ml_result is not None:
            classes[result.observed_identity.sa_group_id][
                result.ml_result.traffic_class
            ] += 1
    report["ml_per_sa"] = {
        group: dict(counter) for group, counter in classes.items()
    }
    report["model_version"] = next(
        (r.ml_result.model_version for r in run.results if r.ml_result), None
    )
    print("RF RESULT PER SA (committed model, not retrained)")
    print("-" * 72)
    print(f"  model: {report['model_version']}")
    for group in sorted(classes):
        print(f"  {group}")
        for name, count in classes[group].most_common():
            print(f"     {name:<12} {count:>4} windows")
    print()

    if args.json_out:
        out = Path(args.json_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
