"""Live passive-observation runner for the IPsec audit layer.

Drives the end-to-end observation path for the tunnel IPv4 topology:

    provision (idempotent)
        -> TShark on the live TAP (audit-tap0)
        -> parse ESP/IKE metadata
        -> record_event() -> results/audit/events.jsonl (append-only JSONL)

The observation is strictly passive: the existing IPsec forwarding path is
unchanged and no ESP payload is ever decrypted.

Usage::

    python -m controller.audit_observer --duration 20
    python -m controller.audit_observer --duration 20 --events-out /tmp/x.json
    python -m controller.audit_observer --status
"""

import argparse
import json
import sys

from . import audit as audit_mod
from . import observation as observation_mod
from . import ipsec_events as ipsec_events_mod
from . import zeek as zeek_mod


def _log(msg):
    print(msg, flush=True)


def cmd_status(mode, address_family):
    status = observation_mod.observation_status(mode, address_family)
    print(json.dumps(status, indent=2, sort_keys=True))
    print("checks:", json.dumps(observation_mod.verify_observation(status)))


def cmd_observe(mode, address_family, seconds, events_out, record):
    result = ipsec_events_mod.observe_live(
        mode, address_family, seconds,
        events_out=events_out, log=_log, record=record,
    )
    summary = result["summary"]
    print("\n=== Observation summary ===")
    print(f"  ESP packets: {summary['esp_packets']}")
    print(f"    outbound : {summary['esp_outbound']}")
    print(f"    inbound  : {summary['esp_inbound']}")
    print(f"  IKE packets: {summary['ike_packets']}")
    for name, count in summary["ike_exchanges"].items():
        print(f"    {name:16s} {count}")
    print(f"  JSON artifact: {result['json_path']}")
    if record:
        path = audit_mod.default_events_path()
        print(f"  audit events appended to: {path} ({len(audit_mod.read_events(path))} total)")
    if result["esp_events"]:
        print("\n  ESP sample (first 3):")
        for event in result["esp_events"][:3]:
            print("    " + json.dumps(
                {k: event[k] for k in ipsec_events_mod.ESP_EVENT_FIELDS}))
    if result["ike_events"]:
        print("\n  IKE sample (first 3):")
        for event in result["ike_events"][:3]:
            print("    " + json.dumps(
                {k: event[k] for k in ipsec_events_mod.IKE_EVENT_FIELDS}))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Run the passive IPsec audit observation (TAP -> TShark -> events)"
    )
    parser.add_argument("--mode", choices=["tunnel", "transport"], default="tunnel")
    parser.add_argument("--address-family", choices=["ipv4", "ipv6"], default="ipv4")
    parser.add_argument("--duration", type=int, default=15,
                        help="seconds to observe the live TAP (default 15)")
    parser.add_argument("--events-out", default=None,
                        help="local path for the raw TShark JSON artifact")
    parser.add_argument("--no-record", action="store_true",
                        help="do not append audit events to events.jsonl")
    parser.add_argument("--status", action="store_true",
                        help="report observation surface status and exit")
    parser.add_argument("--zeek", action="store_true",
                        help="report Zeek availability (never installs)")
    args = parser.parse_args(argv)

    if args.zeek:
        print(json.dumps(zeek_mod.zeek_availability(), indent=2, sort_keys=True))
        return 0
    if args.status:
        cmd_status(args.mode, args.address_family)
        return 0

    cmd_observe(args.mode, args.address_family, args.duration,
                args.events_out, record=not args.no_record)
    return 0


if __name__ == "__main__":
    sys.exit(main())