"""Transport-topology live XDP observation (no lab required).

The transport lab is observed exactly like the tunnel lab: an authoritative
host copies its IPsec interface into a passive sensor container, and the one
``xdp_monitor`` the controller manages writes the SAME shared live journal, so
Packet Analysis never needs to know which mode produced the packets.

These tests lock the wiring in place:

  * ``topology/transport/ipsec.clab.yml``  - sensor node, host-c mirror
    (ingress+egress, copy-only), shared journal bind, data link untouched,
    host-d kept out of the observation path.
  * ``scripts/transport-entrypoint.sh``    - provisions the mirror; it must not
    start a second, container-private observer.
  * ``controller.xdp_observation``         - the declared sensor of every mode
    matches the containerlab container its topology really creates.
  * the continuous run boundary            - tunnel -> transport -> tunnel
    re-anchors and never backfills or fabricates a packet.
"""

import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from controller import executor as executor_mod
from controller import experiment_manifest as manifest_mod
from controller import xdp_observation as xdp_obs
from correlation.api.capture_feed import CaptureFeedService
from correlation.api.run_annex import CurrentRunAnnex

REPO_ROOT = Path(__file__).resolve().parents[1]
TRANSPORT_TOPO = REPO_ROOT / "topology" / "transport" / "ipsec.clab.yml"
TUNNEL_TOPO = REPO_ROOT / "topology" / "tunnel" / "ipsec.clab.yml"
TRANSPORT_ENTRYPOINT = REPO_ROOT / "scripts" / "transport-entrypoint.sh"

SHARED_JOURNAL_BIND = "results/observed-state/xdp"

TUNNEL_CONFIG = {
    "mode": "tunnel",
    "address_family": "ipv4",
    "ike": {"version": 2, "encryption": "aes256",
            "integrity": "sha256", "dh_group": "modp2048"},
    "esp": {"encryption": "aes128gcm16", "integrity": None,
            "dh_group": "modp2048", "pfs": True},
    "traffic": {"profile": "web", "duration": 30},
}
TRANSPORT_CONFIG = dict(
    TUNNEL_CONFIG,
    mode="transport",
    esp={"encryption": "aes256gcm16", "integrity": None,
         "dh_group": "modp2048", "pfs": True},
)


def _node_block(text, node):
    """Return the YAML block of one ``nodes:`` entry, indented-slice."""
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == f"{node}:":
            start = index
            break
    if start is None:
        raise AssertionError(f"node {node!r} not found in topology")
    indent = len(lines[start]) - len(lines[start].lstrip())
    block = [lines[start]]
    for line in lines[start + 1:]:
        if line.strip() and (len(line) - len(line.lstrip())) <= indent:
            break
        block.append(line)
    return "\n".join(block)


def _endpoints(text):
    return re.findall(r"-\s+endpoints:\s+\[\"([^\"]+)\",\s*\"([^\"]+)\"\]", text)


def _event(spi, seq, index=0, classification="ESP", proto=50):
    return {
        "ts": 17260803212308 + index,
        "type": classification,
        "src": "10.20.1.10" if classification == "ESP-T" else "192.168.100.1",
        "dst": "10.20.1.20" if classification == "ESP-T" else "192.168.100.2",
        "proto": proto,
        "len": 154,
        "spi": spi,
        "seq": seq,
    }


class TestTransportTopologyObservation(unittest.TestCase):
    def setUp(self):
        self.text = TRANSPORT_TOPO.read_text(encoding="utf-8")

    def test_transport_lab_has_a_passive_sensor_node(self):
        sensor = _node_block(self.text, "sensor")
        self.assertIn("kind: linux", sensor)
        self.assertIn("sleep infinity", sensor)
        self.assertIn(f"{SHARED_JOURNAL_BIND}:/opt/xdp-journal", sensor)
        # a pure sink: no address, no route
        self.assertNotIn("ip addr add", sensor)
        self.assertNotIn("ip route add", sensor)
        # and it is not privileged (it observes, it never terminates traffic)
        self.assertNotIn("privileged: true", sensor)

    def test_authoritative_transport_host_mirrors_its_ipsec_interface(self):
        host_c = _node_block(self.text, "host-c")
        self.assertIn('AUDIT_TAP_IFACE: "eth1"', host_c)
        self.assertIn('AUDIT_TAP_TARGET: "eth2"', host_c)
        self.assertIn(
            "scripts/audit-tap-setup.sh:/usr/local/bin/audit-tap-setup.sh",
            host_c,
        )

    def test_peer_host_is_not_an_observation_point(self):
        host_d = _node_block(self.text, "host-d")
        self.assertNotIn("AUDIT_TAP_IFACE", host_d)
        self.assertNotIn("audit-tap-setup.sh", host_d)
        self.assertNotIn("xdp-journal", host_d)

    def test_sensor_receives_only_the_mirrored_copy(self):
        links = _endpoints(self.text)
        self.assertIn(("host-c:eth1", "host-d:eth1"), links)
        self.assertIn(("host-c:eth2", "sensor:eth1"), links)
        # the sensor is never inline with the IPsec data path
        data_link = next(l for l in links if "host-d:eth1" in l)
        self.assertNotIn("sensor", " ".join(data_link))
        self.assertEqual(len(links), 2)

    def test_both_topologies_share_one_host_visible_journal(self):
        self.assertIn(
            f"{SHARED_JOURNAL_BIND}:/opt/xdp-journal",
            TUNNEL_TOPO.read_text(encoding="utf-8"),
        )
        self.assertIn(
            f"{SHARED_JOURNAL_BIND}:/opt/xdp-journal", self.text,
        )


class TestTransportEntrypoint(unittest.TestCase):
    def setUp(self):
        self.text = TRANSPORT_ENTRYPOINT.read_text(encoding="utf-8")

    def test_entrypoint_provisions_the_passive_mirror(self):
        self.assertIn('AUDIT_TAP_IFACE:-', self.text)
        self.assertIn("/usr/local/bin/audit-tap-setup.sh", self.text)
        # soft failure: a mirror problem must never block charon
        self.assertIn("WARNING: audit observation not provisioned", self.text)

    def test_entrypoint_starts_no_second_private_observer(self):
        executed = [
            line.strip() for line in self.text.splitlines()
            if line.strip().startswith("xdp_monitor")
        ]
        self.assertEqual(executed, [])
        self.assertNotIn("/var/log/xdp_monitor.jsonl", self.text)


class TestDeclaredSensors(unittest.TestCase):
    """The controller's sensor must be the containerlab container the
    topology really creates (``clab-<topology name>-<node>``)."""

    def _expected(self, topo_path, node):
        name = re.search(r"^name:\s*(\S+)", topo_path.read_text(encoding="utf-8"),
                         re.M).group(1)
        return f"clab-{name}-{node}"

    def test_transport_sensor_matches_the_transport_topology(self):
        self.assertEqual(
            xdp_obs.SENSOR_TARGETS["transport"][0],
            self._expected(TRANSPORT_TOPO, "sensor"),
        )

    def test_tunnel_sensor_matches_the_tunnel_topology(self):
        self.assertEqual(
            xdp_obs.SENSOR_TARGETS["tunnel"][0],
            self._expected(TUNNEL_TOPO, "sensor"),
        )

    def test_both_modes_observe_the_same_interface_and_journal(self):
        self.assertEqual(
            {iface for _, iface in xdp_obs.SENSOR_TARGETS.values()}, {"eth1"},
        )
        self.assertEqual(xdp_obs.MOUNT_DIR, "/opt/xdp-journal")
        self.assertEqual(xdp_obs.JOURNAL_FILE, "live_events.jsonl")
        self.assertEqual(
            xdp_obs.journal_path(), xdp_obs.JOURNAL_DIRECTORY / "live_events.jsonl",
        )

    def test_ensure_live_observation_is_declared_for_both_modes(self):
        for mode in ("tunnel", "transport"):
            self.assertIn(mode, xdp_obs.SENSOR_TARGETS)
        # executor delegates the mode, it never special-cases tunnel
        source = Path(executor_mod.__file__).read_text(encoding="utf-8")
        self.assertIn("ensure_for_mode", source)
        self.assertNotIn("not-applicable", source)


class TestTransportLiveBoundaryAcrossModeSwitch(unittest.TestCase):
    """One continuous run may tunnel -> transport -> tunnel.

    The topology switch destroys the previous sensor, so the new sensor's
    monitor truncates the shared journal (``action == "started"``) and the
    run-spanning boundary must re-anchor: LIVE rows keep flowing, and no
    pre-anchor packet of the previous topology is ever backfilled.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.journal = os.path.join(self.tmp.name, "live_events.jsonl")
        with open(self.journal, "wb"):
            pass
        self.manifest = os.path.join(self.tmp.name, "experiment.json")
        for name, value in (
            ("manifest_path", lambda: self.manifest),
            ("_journal_path", lambda: self.journal),
        ):
            patcher = mock.patch.object(manifest_mod, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(manifest_mod.close_run_session)
        manifest_mod.begin_run_session("dataset-20260930-040000")

    def _append(self, events):
        with open(self.journal, "ab") as handle:
            for event in events:
                handle.write(json.dumps(event).encode("utf-8") + b"\n")

    def _truncate(self):
        with open(self.journal, "wb"):
            pass

    def _feed(self):
        annex = CurrentRunAnnex(
            store=None, feed=None, manifest_path=self.manifest
        )
        return CaptureFeedService(
            self.journal,
            boundary_provider=annex.boundary,
            experiment_gated=True,
            freshness_window_ms=8000,
        )

    def _manifest(self):
        with open(self.manifest, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def test_tunnel_transport_tunnel_keeps_one_live_window(self):
        # -- tunnel sample ------------------------------------------------
        self.assertTrue(manifest_mod.publish_session_boundary(
            TUNNEL_CONFIG, {"status": "live", "action": "started"},
        ))
        self._append([_event(0xA1, 1, 10)])
        tunnel_page = self._feed().poll(cursor=0, limit=200)
        self.assertEqual(tunnel_page["count"], 1)
        self.assertTrue(tunnel_page["current"])

        # -- transport sample: sensor replaced, journal re-truncated ------
        self._truncate()
        self.assertTrue(manifest_mod.publish_session_boundary(
            TRANSPORT_CONFIG, {"status": "live", "action": "started"},
        ))
        self.assertEqual(self._manifest()["config"]["mode"], "transport")
        self._append([_event(0xB2, 1, 20), _event(0xB2, 2, 21)])
        transport_page = self._feed().poll(cursor=0, limit=200)
        self.assertTrue(transport_page["current"])
        self.assertEqual(transport_page["count"], 2)
        self.assertEqual(
            [event["spi"] for event in transport_page["events"]], [0xB2, 0xB2],
        )

        # -- back to tunnel ------------------------------------------------
        self._truncate()
        self.assertTrue(manifest_mod.publish_session_boundary(
            TUNNEL_CONFIG, {"status": "live", "action": "started"},
        ))
        self.assertEqual(self._manifest()["config"]["mode"], "tunnel")
        self._append([_event(0xC3, 1, 30)])
        tunnel_again = self._feed().poll(cursor=0, limit=200)
        self.assertTrue(tunnel_again["current"])
        self.assertEqual(tunnel_again["count"], 1)
        self.assertEqual(tunnel_again["events"][0]["spi"], 0xC3)
        # exactly the rows that were really written after the last anchor
        self.assertEqual(
            len(open(self.journal, "rb").read().splitlines()), 1,
        )

        # -- run ends ------------------------------------------------------
        self.assertTrue(manifest_mod.close_run_session(result={"status": "PASS"}))
        self.assertIn("ended_at_ns", self._manifest()["run"])
        closed = self._feed().poll(cursor=0, limit=200)
        self.assertEqual(closed["count"], 0)
        self.assertFalse(closed["current"])
        # the journal itself is retained as evidence
        self.assertTrue(os.path.isfile(self.journal))

    def test_transport_sample_keeps_the_boundary_open_on_reuse(self):
        """Consecutive transport samples reuse the sensor: no re-anchor."""
        self._append([_event(0xA1, 1, 10)])
        self.assertTrue(manifest_mod.publish_session_boundary(
            TRANSPORT_CONFIG, {"status": "live", "action": "started"},
        ))
        anchor = self._manifest()["journal"]["observation_start_bytes"]
        self._append([_event(0xB2, 1, 20)])
        self.assertFalse(manifest_mod.publish_session_boundary(
            TRANSPORT_CONFIG, {"status": "live", "action": "reuse"},
        ))
        self.assertEqual(
            self._manifest()["journal"]["observation_start_bytes"], anchor,
        )
        page = self._feed().poll(cursor=0, limit=200)
        self.assertTrue(page["current"])
        self.assertEqual(page["count"], 1)
        self.assertEqual(page["events"][0]["spi"], 0xB2)

    def test_transport_observation_is_never_reported_as_missing(self):
        """``ensure_live_observation`` must not degrade to not-applicable."""
        with mock.patch.object(
            xdp_obs, "ensure_xdp_monitor", return_value={"status": "live"},
        ) as ensure:
            for mode in ("tunnel", "transport"):
                self.assertEqual(
                    executor_mod.ensure_live_observation(mode)["status"], "live",
                )
        containers = [call.kwargs["container"] for call in ensure.call_args_list]
        self.assertEqual(containers, ["clab-ipsec-sensor",
                                     "clab-ipsec-transport-sensor"])


if __name__ == "__main__":
    unittest.main()
