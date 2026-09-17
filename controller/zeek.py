"""Zeek integration status + seams for the IPsec audit layer.

Zeek is the optional higher-level monitoring consumer of the *same*
observation interface (``audit-tap0``) that the TShark metadata path uses.
By policy it is deliberately NOT installed here: Zeek is a large dependency
stack and the task explicitly forbids silently installing it.  This module
only reports availability and keeps the integration seam ready so wiring
Zeek in later is a one-line change and never touches the network/TAP layer.

Intended division of labour (unchanged by this module):

    TShark  = packet-level IPsec metadata (ESP SPI/seq, IKE exchange/msg id)
    Zeek    = higher-level network events / state / detection
"""

import shutil

ZEEK_BINARIES = ("zeek", "zeekctl", "bro")


def zeek_availability():
    """Return a report of Zeek's presence on this host (never installs)."""
    found = {name: shutil.which(name) for name in ZEEK_BINARIES}
    present = [name for name, path in found.items() if path]
    return {
        "installed": bool(present),
        "binaries": found,
        "candidates": present,
        "note": (
            "zeek/bro/zeekctl is not installed on this host; not installing "
            "a large dependency stack by policy. The consumer seam is ready "
            "in zeek_observe()."
            if not present else None
        ),
    }


def zeek_observe(tap_interface, mode="tunnel", address_family="ipv4",
                 output_dir=None):
    """Integration seam: run Zeek against the observation interface.

    Never invoked when Zeek is absent.  When available it would read the same
    live ``audit-tap0`` interface the TShark path uses and emit Zeek logs
    plus normalized events into the audit store.  Raises RuntimeError when
    Zeek is not present (no silent installation ever happens here).
    """
    availability = zeek_availability()
    if not availability["installed"]:
        raise RuntimeError(
            "zeek is not installed; refusing to run (no silent install). "
            f"availability={availability}"
        )
    # Seam: run Zeek inside the gateway container against the observation
    # interface and normalize its conn.log/known_hosts into audit events.
    raise NotImplementedError(
        "zeek observation is available but not yet wired; "
        f"would run on tap '{tap_interface}' ({mode}/{address_family})"
    )