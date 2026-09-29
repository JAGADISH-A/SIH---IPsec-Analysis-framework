#!/usr/bin/env python3
"""Deterministic browser-demo replay of the recorded xdp_monitor packet journal.

The sentinel capture feed (``correlation/api/capture_feed.py``) is a read-only
tail of the JSONL journal the gateway's ``xdp_monitor`` writes.  When the live
sensor is unavailable (no ``eth1`` / no lab) there is no writer, so the feed
reports its honest waiting/recorded state and the browser shows no live rows.

This script provides the missing writer for a **browser demo only**: it appends
lines taken verbatim from the repo's shipped recorded capture
(``results/observed-state/live_events_full.jsonl`` -- real ``xdp_monitor_event``
lines from a past lab run) into a demo journal at a steady rate.  The feed sees
an actively-grown journal, so ``current`` flips true and the Packet Analysis
page renders live rows -- using exactly the same code path a real sensor would
drive.  It never fabricates a packet: every packet's identity, addressing,
length and classification are the recorded ones, and the ``current``/waiting
decision stays in the backend.

The one field that is *not* carried over verbatim is the capture time, and it
has to be re-anchored rather than copied.  ``ts`` in a real line is
``bpf_ktime_get_ns()`` -- nanoseconds since the *capturing* host booted -- and
the reader turns it into wall time with its own host's monotonic->realtime
offset (``XdpEventAdapter.realtime_offset_ns``).  That offset is only valid for
packets captured on the same host as the reader, so a recorded reading from the
machine that produced the artifact would render hours away from the real time.
Each line is appended now, so it is stamped with *this* host's
``CLOCK_MONOTONIC`` reading; everything else in the line stays recorded.

Non-goals (with intent): this is NOT a traffic generator for the IPsec testbed
and it does not write into the sensor's live journal
(``results/observed-state/xdp/live_events.jsonl``, which the controller owns and
truncates).  It writes only the demo journal it is told to write, defaulting to
``results/observed-state/demo/live_events.jsonl``.

Usage:
    .venv/bin/python scripts/demo-capture-replay.py --journal results/observed-state/demo/live_events.jsonl

Signals: SIGINT / SIGTERM stop the loop cleanly and exit 0 (the journal stops
growing, so the feed reports ``current: false`` within the freshness window).
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from typing import Any, Dict, List

STOP = [False]


def stamped_line(payload: Dict[str, Any]) -> bytes:
    """The recorded packet, with its capture time re-anchored to this host.

    ``ts`` in a real xdp_monitor line is ``bpf_ktime_get_ns()`` -- nanoseconds
    since the *capturing* host booted.  The reader converts it to wall time with
    its own host's monotonic->realtime offset, which only holds for packets
    captured on the same host; a recorded reading from the machine that produced
    the artifact belongs to a different boot and would render hours away from
    the real time.  The line is appended now, so ``ts`` is this host's current
    ``CLOCK_MONOTONIC`` reading.  Every other field is the recorded one.
    """
    payload["ts"] = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _handle(signum: int, _frame) -> None:
    STOP[0] = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--journal", default=None,
        help="demo journal to append to (default: "
             "results/observed-state/demo/live_events.jsonl)",
    )
    parser.add_argument(
        "--source", default=None,
        help="source of recorded lines (default: "
             "results/observed-state/live_events_full.jsonl)",
    )
    parser.add_argument(
        "--interval", type=float, default=1.0,
        help="seconds between appended lines (default 1.0; the feed's default "
             "freshness window is 8s, so anything < 8 keeps current true)",
    )
    parser.add_argument(
        "--append", action="store_true",
        help="append to an existing journal instead of truncating it",
    )
    args = parser.parse_args()

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    journal = os.path.abspath(args.journal or os.path.join(
        root, "results", "observed-state", "demo", "live_events.jsonl"))
    source = os.path.abspath(args.source or os.path.join(
        root, "results", "observed-state", "live_events_full.jsonl"))

    if not os.path.isfile(source):
        print(f"[demo-replay] source artifact missing: {source}", file=sys.stderr)
        return 2
    with open(source, "r", encoding="utf-8") as handle:
        lines = [line for line in handle.read().splitlines() if line.strip()]
    if not lines:
        print(f"[demo-replay] source artifact is empty: {source}", file=sys.stderr)
        return 2
    payloads: List[Dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        try:
            parsed = json.loads(line)
        except ValueError:
            print(f"[demo-replay] source line {number} is not JSON: {source}",
                  file=sys.stderr)
            return 2
        if not isinstance(parsed, dict):
            print(f"[demo-replay] source line {number} is not an object: {source}",
                  file=sys.stderr)
            return 2
        payloads.append(parsed)

    journal_dir = os.path.dirname(journal)
    os.makedirs(journal_dir, exist_ok=True)
    mode = "a" if args.append else "w"
    with open(journal, mode, encoding="utf-8"):
        pass
    try:
        fd = os.open(journal, os.O_RDWR | os.O_APPEND)
    except OSError as error:
        print(f"[demo-replay] cannot write {journal}: {error}", file=sys.stderr)
        return 2

    signal.signal(signal.SIGINT, _handle)
    signal.signal(signal.SIGTERM, _handle)

    print(f"[demo-replay] appending {len(payloads)} recorded xdp_monitor line(s) "
          f"(capture time re-anchored to this host's monotonic clock)")
    print(f"[demo-replay] source  : {source}")
    print(f"[demo-replay] journal : {journal}")
    print(f"[demo-replay] interval: {args.interval}s  (journal stays 'current' "
          f"while appended)")

    i = 0
    written = 0
    while not STOP[0]:
        os.write(fd, stamped_line(payloads[i % len(payloads)]) + b"\n")
        os.fsync(fd)
        written += 1
        i += 1
        if written % 50 == 0:
            print(f"[demo-replay] {written} line(s) appended so far")
        if STOP[0]:
            break
        try:
            time.sleep(args.interval)
        except KeyboardInterrupt:
            break
    os.close(fd)
    print(f"[demo-replay] stopped after {written} line(s); journal is now "
          f"recorded history (current will go false)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())