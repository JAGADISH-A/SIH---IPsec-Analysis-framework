"""Topology bind-mount portability tests (packaging).

Asserts that both Containerlab topology files (``topology/{tunnel,transport}/
ipsec.clab.yml``) are host-path-portable:

* no bind source is an absolute host path (no ``/home/...``, ``~`` or ``$``),
* every relative bind source resolves, per Containerlab's documented rule
  ("a relative host path is considered relative to the *topology file's
  directory*", ``ResolvePath(source, topo_file_dir)``), to the same repository
  file/directory the previous absolute paths referenced (scripts under
  ``scripts/``, swanctl config under ``configs/``),
* resolved sources exist and stay inside the repository root,
* container-side destinations are unchanged,
* the previously hardcoded host path is gone from both files.

No Containerlab/container runtime is required; the resolution rule is
reimplemented here exactly as documented by Containerlab 0.79.x
(containerlab.dev/manual/nodes/#binds).
"""

import os
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

TUNNEL_TOPO = REPO_ROOT / "topology" / "tunnel" / "ipsec.clab.yml"
TRANSPORT_TOPO = REPO_ROOT / "topology" / "transport" / "ipsec.clab.yml"

# (source relative to the repo root, container destination) per file, in
# binding order.  This is exactly the mapping the previous absolute host
# paths (/home/jagan/ipsec-testbed/...) produced; it must not change.
EXPECTED_TUNNEL_BINDS = [
    ("scripts/gw-entrypoint.sh", "/usr/local/bin/gw-entrypoint.sh"),
    ("configs/gw-a/swanctl", "/usr/local/etc/swanctl"),
    ("scripts/gw-entrypoint.sh", "/usr/local/bin/gw-entrypoint.sh"),
    ("configs/gw-b/swanctl", "/usr/local/etc/swanctl"),
]

EXPECTED_TRANSPORT_BINDS = [
    ("scripts/transport-entrypoint.sh", "/usr/local/bin/transport-entrypoint.sh"),
    ("configs/transport/host-c/swanctl", "/etc/swanctl"),
    ("scripts/transport-entrypoint.sh", "/usr/local/bin/transport-entrypoint.sh"),
    ("configs/transport/host-d/swanctl", "/etc/swanctl"),
]


def parse_binds(path):
    """Return (source, container) for every ``- src:dest`` entry inside a
    ``binds:`` block of one of these canonical topology files."""
    binds = []
    inside_binds = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "binds:":
            inside_binds = True
            continue
        if stripped.startswith("- "):
            if not inside_binds:
                continue
            entry = stripped[2:]
            source, _, container = entry.partition(":")
            if not container:
                raise AssertionError(
                    f"{path}: malformed bind entry (no ':'): {entry!r}"
                )
            binds.append((source, container))
            continue
        if inside_binds and stripped:
            # a new YAML key (e.g. ``exec:``) ends the binds list
            inside_binds = False
    return binds


def resolve_host_path(source, topo_file):
    """Containerlab's documented bind-source resolution: relative sources
    resolve against the topology file's directory (``filepath.Join``, which
    lexically normalizes ``..`` segments)."""
    if source.startswith("/"):
        return Path(source)
    return Path(os.path.abspath(os.path.join(str(topo_file.parent), source)))


class TestTopologyBindPortability(unittest.TestCase):
    def test_no_hardcoded_host_path_remains(self):
        for topo in (TUNNEL_TOPO, TRANSPORT_TOPO):
            text = topo.read_text(encoding="utf-8")
            self.assertNotIn("/home/", text, f"hardcoded host path in {topo}")
            self.assertNotIn(
                "/home/jagan/ipsec-testbed", text,
                f"hardcoded host path in {topo}",
            )

    def test_tunnel_binds_are_portable_and_unchanged(self):
        binds = parse_binds(TUNNEL_TOPO)
        expected = EXPECTED_TUNNEL_BINDS
        self.assertEqual(len(binds), len(expected))
        for (source, _), (expected_rel, _) in zip(binds, expected):
            self.assertFalse(source.startswith("/"),
                             f"absolute bind source not portable: {source}")
            self.assertNotIn("$", source)
            self.assertNotIn("~", source)
            resolved = resolve_host_path(source, TUNNEL_TOPO)
            self.assertTrue(resolved.exists(),
                            f"bind source missing: {resolved}")
            self.assertEqual(resolved, REPO_ROOT / expected_rel,
                             f"{source!r} no longer points at {expected_rel}")
            self.assertTrue(resolved.is_relative_to(REPO_ROOT))

    def test_transport_binds_are_portable_and_unchanged(self):
        binds = parse_binds(TRANSPORT_TOPO)
        expected = EXPECTED_TRANSPORT_BINDS
        self.assertEqual(len(binds), len(expected))
        for (source, _), (expected_rel, _) in zip(binds, expected):
            self.assertFalse(source.startswith("/"),
                             f"absolute bind source not portable: {source}")
            self.assertNotIn("$", source)
            self.assertNotIn("~", source)
            resolved = resolve_host_path(source, TRANSPORT_TOPO)
            self.assertTrue(resolved.exists(),
                            f"bind source missing: {resolved}")
            self.assertEqual(resolved, REPO_ROOT / expected_rel,
                             f"{source!r} no longer points at {expected_rel}")
            self.assertTrue(resolved.is_relative_to(REPO_ROOT))

    def test_container_destinations_are_unchanged(self):
        tunnel = parse_binds(TUNNEL_TOPO)
        self.assertEqual([c for _, c in tunnel],
                         [c for _, c in EXPECTED_TUNNEL_BINDS])
        transport = parse_binds(TRANSPORT_TOPO)
        self.assertEqual([c for _, c in transport],
                         [c for _, c in EXPECTED_TRANSPORT_BINDS])
        for _, container in tunnel + transport:
            self.assertTrue(container.startswith("/"),
                            f"container destination must be absolute: {container}")


if __name__ == "__main__":
    unittest.main()