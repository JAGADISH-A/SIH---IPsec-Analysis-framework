"""Focused tests for the live XDP observation lifecycle (non-lab).

Covers the idempotent ``ensure_xdp_monitor`` lifecycle (reuse / start /
restart / duplicate prevention / readiness failure / journal growth) and the
pipeline ordering both entry points adopt:

  * ``executor.run_experiment``: DEPLOY -> IPSEC -> OBSERVATION ->
    CONNECTIVITY -> TRAFFIC, observation readiness gates connectivity/traffic.
  * ``campaign.execute_trial_pipeline``: observation readiness runs after the
    deploy-or-reuse + IPsec verification and before connectivity, on BOTH the
    fresh and the reused path.

Everything is mocked; nothing touches the lab.  The ``FakeLab`` simulates the
sensor container: its process table (xdp_monitor pids + argv + stdout target),
interface presence, journal mount, binary presence and attach stderr.
"""

import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from unittest.mock import patch

from controller import xdp_observation as xdp_obs
from controller import executor as executor_mod
from controller import campaign as campaign_mod
from controller import reuse as reuse_mod
from controller import traffic as traffic_mod
from controller import capture as capture_mod
from controller import dataset as dataset_mod
from controller import features as features_mod

VALID_CONFIG = {
    "mode": "tunnel",
    "address_family": "ipv4",
    "ike": {
        "version": 2,
        "encryption": "aes256",
        "integrity": "sha256",
        "dh_group": "modp2048",
    },
    "esp": {
        "encryption": "aes256cbc",
        "integrity": "sha256",
        "dh_group": "modp2048",
        "pfs": True,
    },
    "traffic": {"profile": "web", "duration": 10},
}


class _Result:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class FakeLab:
    """Deterministic stand-in for the sensor container + docker CLI."""

    def __init__(self):
        self.container_alive = True
        self.iface_present = True
        self.mount_present = True
        self.binary_present = True
        self.monitors = []          # list of {"pid", "cmd", "out"}
        self.killed = []            # pids sent pkill -9 -x xdp_monitor
        self.started = []           # docker exec -d start commands
        self.copied = []            # docker cp commands
        self.err_text = ""
        self.fail_start = False     # started monitor does not stay alive
        self.suppress_markers = False  # started monitor never prints attach banner
        self.journal_ready = True   # sensor-side journal exists and is writable
        self._next_pid = 1000

    # -- public helpers ---------------------------------------------------
    def add_monitor(self, cmd=None, out=None, pid=None):
        pid = pid or self._next_pid
        self._next_pid += 1
        self.monitors.append({
            "pid": pid,
            "cmd": cmd or f"{xdp_obs.XDP_BINARY_IN_CONTAINER} {xdp_obs.SENSOR_IFACE} --json",
            "out": out or f"{xdp_obs.MOUNT_DIR}/{xdp_obs.JOURNAL_FILE}",
        })
        if not self.err_text and not self.suppress_markers:
            self.err_text = self._generic_attach_text()

    @staticmethod
    def _sampler_only_text():
        # What the real monitor prints on this veth/MTU lab: native attach is
        # rejected, no generic/native success banner, but the statistics loop
        # is running and reports "total : 0" before any packet exists.
        return (
            f"libbpf: {"Peer MTU is too large to set XDP"}\n"
            "total     : 0\nIKE       : 0\n"
        )

    @staticmethod
    def _generic_attach_text():
        return (
            f"{xdp_obs._NATIVE_REJECTED}\nreal issues: "
            f"{xdp_obs._ATTACH_GENERIC}\n"
        )

    # -- subprocess.run dispatcher ----------------------------------------
    def run(self, command, **kwargs):
        cmd = list(command)
        # The prefix is resolved per-host (sudo -n when available, bare docker
        # when the socket is group-reachable); normalize by the docker token.
        if "docker" not in cmd:
            return _Result(0, "", "")
        base = cmd[cmd.index("docker") + 1:]
        verb = base[0]
        if verb == "cp":
            self.copied.append(cmd)
            return _Result(0, "", "")
        if verb != "exec":
            return _Result(0, "", "")
        if base[1] == "-d":
            # docker exec -d <container> sh -c "<setsid start command>"
            self.started.append(cmd)
            if not self.fail_start:
                self._spawn_from_start(base[5])
            return _Result(0, "", "")
        container, argv = base[1], base[2:]
        return self._dispatch(container, argv)

    def _spawn_from_start(self, command):
        m_iface = re.search(r"xdp_monitor (\S+) --json", command)
        m_journal = re.search(r"> (\S+) ", command)
        iface = m_iface.group(1) if m_iface else xdp_obs.SENSOR_IFACE
        journal = m_journal.group(1) if m_journal else f"{xdp_obs.MOUNT_DIR}/{xdp_obs.JOURNAL_FILE}"
        self.add_monitor(
            cmd=f"{xdp_obs.XDP_BINARY_IN_CONTAINER} {iface} --json",
            out=journal,
        )

    def _dispatch(self, container, argv):
        if argv == ["true"]:
            return _Result(0 if self.container_alive else 1, "", "")
        if argv[:2] == ["sh", "-c"]:
            script = argv[2]
            if script.startswith("test -e /sys/class/net/"):
                return _Result(0 if self.iface_present else 1, "", "")
            if script.startswith("test -d "):
                return _Result(0 if self.mount_present else 1, "", "")
            if script.startswith("test -x "):
                return _Result(0 if self.binary_present else 1, "", "")
            if script.startswith("test -f ") or script.startswith("test -w "):
                if not self.journal_ready:
                    return _Result(1, "", "")
                return _Result(0, "", "")
            if script == xdp_obs._PGREP:
                lines = "".join(
                    f"pid={p['pid']} cmd={p['cmd']} out={p['out']}\n"
                    for p in self.monitors
                )
                return _Result(0, lines, "")
            if script.startswith("pkill "):
                self.killed.extend(m["pid"] for m in self.monitors)
                self.monitors = []
                return _Result(0, "", "")
            return _Result(0, "", "")
        if argv == ["test", "-x", xdp_obs.XDP_BINARY_IN_CONTAINER]:
            return _Result(0 if self.binary_present else 1, "", "")
        if argv == ["cat", f"{xdp_obs.MOUNT_DIR}/{xdp_obs.ERROR_FILE}"]:
            return _Result(0, self.err_text, "")
        return _Result(0, "", "")


class EnsureXdpMonitorTestCase(unittest.TestCase):
    def setUp(self):
        self.lab = FakeLab()
        self.popen = patch.object(
            xdp_obs.subprocess, "run", side_effect=self.lab.run
        )
        self.popen.start()
        self.addCleanup(self.popen.stop)
        self._managed_journals = []

    def tearDown(self):
        for managed in self._managed_journals:
            managed.cleanup()

    def ensure(self, **kwargs):
        journal_dir = kwargs.pop("journal_dir", None)
        if journal_dir is None:
            managed = tempfile.TemporaryDirectory()
            self._managed_journals.append(managed)
            journal_dir = managed.name
        if "ready_timeout" not in kwargs:
            kwargs["ready_timeout"] = 1.0
        return xdp_obs.ensure_xdp_monitor(
            container=xdp_obs.SENSOR_CONTAINER,
            journal_dir=journal_dir,
            **kwargs,
        )

    # -- reuse ---------------------------------------------------------------
    def test_reuses_running_monitor(self):
        self.lab.add_monitor(pid=111)
        with tempfile.TemporaryDirectory() as tmp:
            out = self.ensure(journal_dir=tmp)
            self.assertEqual(out["status"], "live")
            self.assertEqual(out["action"], "reuse")
            self.assertEqual(out["pid"], 111)
            self.assertEqual(out["journal"], str(xdp_obs.journal_path(tmp)))
        # No duplicate start, no copy, no kill.
        self.assertEqual(self.lab.started, [])
        self.assertEqual(self.lab.copied, [])
        self.assertEqual(self.lab.killed, [])

    def test_reuse_is_idempotent_across_calls(self):
        self.lab.add_monitor(pid=111)
        self.ensure()
        again = self.ensure()
        self.assertEqual(again["action"], "reuse")
        self.assertEqual(again["pid"], 111)
        self.assertEqual(self.lab.started, [])

    # -- missing monitor ------------------------------------------------------
    def test_starts_monitor_when_missing(self):
        out = self.ensure()
        self.assertEqual(out["action"], "started")
        self.assertEqual(out["status"], "live")
        self.assertEqual(len(self.lab.started), 1)
        self.assertEqual(self.lab.copied, [])   # binary already present
        self.assertEqual(self.lab.killed, [])
        self.assertEqual(out["attach"]["generic_mode"], True)

    def test_copies_binary_when_missing_from_sensor(self):
        self.lab.binary_present = False
        out = self.ensure()
        self.assertEqual(out["action"], "started")
        self.assertEqual(len(self.lab.copied), 1)
        self.assertEqual(len(self.lab.started), 1)

    # -- foreign / stale monitor ----------------------------------------------
    def test_restarts_foreign_monitor_writing_elsewhere(self):
        self.lab.add_monitor(pid=222, out="/tmp/xdp.jsonl")
        out = self.ensure()
        self.assertEqual(out["action"], "started")
        self.assertEqual(self.lab.killed, [222])
        self.assertEqual(len(self.lab.started), 1)
        self.assertNotEqual(out["pid"], 222)

    def test_restarts_stale_monitor_on_wrong_interface(self):
        self.lab.add_monitor(pid=333, cmd="/usr/sbin/xdp_monitor eth2 --json")
        out = self.ensure()
        self.assertEqual(out["action"], "started")
        self.assertEqual(self.lab.killed, [333])

    # -- duplicate prevention --------------------------------------------------
    def test_never_spawns_second_monitor_while_one_lives(self):
        self.lab.add_monitor(pid=111)
        self.lab.add_monitor(pid=112)
        out = self.ensure()
        self.assertEqual(out["action"], "reuse")
        self.assertIn(out["pid"], (111, 112))
        self.assertEqual(self.lab.started, [])
        self.assertEqual(self.lab.killed, [])

    # -- readiness gate/prereq failures ---------------------------------------
    def test_sensor_down_raises_readiness_error(self):
        self.lab.container_alive = False
        with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
            self.ensure()
        self.assertIn("live XDP observation is unavailable", str(ctx.exception))
        self.assertEqual(self.lab.started, [])

    def test_missing_interface_raises_readiness_error(self):
        self.lab.iface_present = False
        with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
            self.ensure()
        self.assertIn("eth1", str(ctx.exception))
        self.assertEqual(self.lab.started, [])

    def test_missing_journal_mount_raises_readiness_error(self):
        self.lab.mount_present = False
        with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
            self.ensure()
        self.assertIn("journal mount", str(ctx.exception))

    def test_monitor_that_will_not_stay_alive_raises(self):
        self.lab.fail_start = True
        with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
            self.ensure(ready_timeout=0.02)
        self.assertIn("did not attach", str(ctx.exception))

    def test_alive_but_never_attaches_generic_raises(self):
        self.lab.add_monitor(pid=444)
        self.lab.err_text = xdp_obs._NATIVE_REJECTED + "\n"
        with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
            self.ensure(ready_timeout=0.05)
        message = str(ctx.exception)
        self.assertTrue(
            "did not attach" in message or "never attached" in message,
            f"unexpected message: {message}",
        )
        self.assertEqual(self.lab.killed, [])

    def test_attached_sampler_is_ready_before_any_packet_exists(self):
        """Readiness must not require a packet: traffic has not started yet.

        The real lab rejects native XDP on the veth/MTU pair, so no attach
        banner is printed; the monitor's own statistics loop is the only
        traffic-independent proof that it is attached and able to write.
        """
        self.lab.err_text = self.lab._sampler_only_text()
        with tempfile.TemporaryDirectory() as tmp:
            journal_dir = Path(tmp)
            out = self.ensure(journal_dir=str(journal_dir))
            self.assertEqual(out["status"], "live")
            self.assertEqual(out["journal_lines"], 0)
            self.assertTrue(out["attach"]["sampler_running"])
            self.assertFalse(out["attach"]["generic_mode"])

    def test_journal_not_writable_is_not_ready(self):
        self.lab.journal_ready = False
        with self.assertRaises(xdp_obs.ObservationReadinessError):
            self.ensure(ready_timeout=0.05)

    def test_journal_events_alone_prove_liveness_without_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal_dir = Path(tmp)
            xdp_obs.journal_path(journal_dir).write_text(
                '{"ts":1,"type":"OTHER"}\n{"ts":2,"type":"OTHER"}\n'
            )
            self.lab.suppress_markers = True
            out = self.ensure(journal_dir=str(journal_dir))
            self.assertEqual(out["status"], "live")
            self.assertEqual(out["journal_lines"], 2)
            self.assertGreater(out["journal_size"], 0)

    # -- live journal growth helper -------------------------------------------
    def test_journal_summary_tracks_growth(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = Path(tmp)
            first = xdp_obs.journal_summary(journal)
            self.assertFalse(first["exists"])
            target = xdp_obs.journal_path(journal)
            target.write_text("event-1\n")
            second = xdp_obs.journal_summary(journal)
            self.assertTrue(second["exists"])
            self.assertEqual(second["lines"], 1)
            self.assertGreater(second["bytes"], 0)
            target.write_text("event-1\nevent-2\n")
            third = xdp_obs.journal_summary(journal)
            self.assertEqual(third["lines"], 2)
            self.assertGreater(third["bytes"], second["bytes"])

    def test_preconditions_run_before_any_start(self):
        self.lab.mount_present = False
        with self.assertRaises(xdp_obs.ObservationReadinessError):
            self.ensure()
        self.assertEqual(self.lab.started, [])
        self.assertEqual(self.lab.killed, [])

    # -- per-mode sensor selection -------------------------------------------
    def test_transport_mode_is_observed_by_the_transport_sensor(self):
        out = executor_mod.ensure_live_observation("transport")
        self.assertEqual(out["status"], "live")
        self.assertEqual(out["action"], "started")
        self.assertEqual(out["container"], "clab-ipsec-transport-sensor")
        self.assertEqual(out["interface"], "eth1")
        start = self.lab.started[0]
        self.assertIn("clab-ipsec-transport-sensor", start)
        self.assertIn("xdp_monitor eth1 --json", start[-1])
        # no duplicate monitor is left behind in the tunnel sensor
        self.assertEqual(len(self.lab.started), 1)

    def test_tunnel_mode_keeps_using_the_tunnel_sensor(self):
        out = executor_mod.ensure_live_observation("tunnel")
        self.assertEqual(out["container"], "clab-ipsec-sensor")
        self.assertIn("clab-ipsec-sensor", self.lab.started[0])

    def test_transport_reuses_its_running_monitor(self):
        self.lab.add_monitor(
            pid=515,
            cmd=f"{xdp_obs.XDP_BINARY_IN_CONTAINER} eth1 --json",
        )
        out = executor_mod.ensure_live_observation("transport")
        self.assertEqual(out["action"], "reuse")
        self.assertEqual(out["pid"], 515)
        self.assertEqual(out["container"], "clab-ipsec-transport-sensor")
        self.assertEqual(self.lab.started, [])

    def test_both_modes_declare_a_distinct_sensor_on_the_same_interface(self):
        self.assertEqual(set(xdp_obs.SENSOR_TARGETS), {"tunnel", "transport"})
        self.assertEqual(
            {iface for _, iface in xdp_obs.SENSOR_TARGETS.values()}, {"eth1"},
        )
        self.assertNotEqual(
            xdp_obs.SENSOR_TARGETS["tunnel"][0],
            xdp_obs.SENSOR_TARGETS["transport"][0],
        )

    def test_unknown_mode_raises_instead_of_running_unobserved(self):
        with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
            executor_mod.ensure_live_observation("grease")
        self.assertIn("no XDP observation sensor is declared", str(ctx.exception))
        self.assertEqual(self.lab.started, [])


class TestRunExperimentOrdering(unittest.TestCase):
    """DEPLOY -> IPSEC -> OBSERVATION -> CONNECTIVITY -> TRAFFIC."""

    def _run(self, config, ensure_result, on_stage_callback=None):
        # The manifest/journal are redirected into a temp dir so a live
        # observation never touches the repository's real experiment.json.
        manifest_mod = executor_mod.manifest_mod
        records = {"start": [], "current": []}
        real_start = manifest_mod.write_start
        real_current = manifest_mod.write_current

        def _start(*args, **kwargs):
            records["start"].append((args, kwargs))
            return real_start(*args, **kwargs)

        def _current(*args, **kwargs):
            records["current"].append((args, kwargs))
            return real_current(*args, **kwargs)

        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "experiment.json"
            journal = Path(tmp) / "live_events.jsonl"
            journal.write_text("")
            with patch.object(
                manifest_mod, "manifest_path", return_value=manifest
            ), patch.object(
                manifest_mod, "_journal_path", return_value=journal
            ), patch.object(
                manifest_mod, "write_start", _start
            ), patch.object(
                manifest_mod, "write_current", _current
            ), patch.object(
                executor_mod, "reset_and_deploy") as m_deploy, \
                    patch.object(executor_mod, "load_generated_configs") as m_load, \
                    patch.object(executor_mod, "initiate_ipsec") as m_init, \
                    patch.object(
                        executor_mod, "verify_ipsec",
                        return_value={"ike_sa": "ESTABLISHED",
                                      "child_sa": "INSTALLED", "mode": "TUNNEL"},
                    ) as m_verify, \
                    patch.object(
                        executor_mod, "ensure_live_observation",
                        return_value=ensure_result,
                    ) as m_observe, \
                    patch.object(
                        executor_mod, "test_connectivity",
                        return_value={"status": "PASS", "packet_loss": 0},
                    ) as m_connect, \
                    patch.object(
                        executor_mod, "run_traffic",
                        return_value={"status": "PASS"},
                    ) as m_traffic:
                result = executor_mod.run_experiment(
                    config, on_stage=on_stage_callback
                )
        return {
            "result": result,
            "records": records,
            "mocks": (m_deploy, m_load, m_init, m_verify, m_observe,
                      m_connect, m_traffic),
        }

    def test_lifecycle_order_puts_observation_before_connectivity(self):
        order = []
        out = self._run(
            VALID_CONFIG,
            {"status": "live", "action": "reuse", "container": "clab-ipsec-sensor",
             "interface": "eth1", "pid": 1, "journal": "x"},
            on_stage_callback=lambda s: order.append(s),
        )
        self.assertEqual(
            order,
            ["DEPLOY", "IPSEC", "OBSERVATION", "CONNECTIVITY", "TRAFFIC"],
        )
        self.assertEqual(out["result"]["observation"]["status"], "live")
        self.assertEqual(out["result"]["status"], "PASS")

    def test_observation_failure_blocks_connectivity_and_traffic(self):
        with patch.object(executor_mod, "reset_and_deploy"), \
                patch.object(executor_mod, "load_generated_configs"), \
                patch.object(executor_mod, "initiate_ipsec"), \
                patch.object(executor_mod, "verify_ipsec", return_value={}), \
                patch.object(
                    executor_mod, "ensure_live_observation",
                    side_effect=xdp_obs.ObservationReadinessError(
                        "IPsec testbed is running, but live XDP observation "
                        "is unavailable: xdp_monitor did not stay alive"
                    ),
                ) as m_observe, \
                patch.object(executor_mod, "test_connectivity") as m_connect, \
                patch.object(executor_mod, "run_traffic") as m_traffic:
            with self.assertRaises(xdp_obs.ObservationReadinessError):
                executor_mod.run_experiment(VALID_CONFIG)
        m_connect.assert_not_called()
        m_traffic.assert_not_called()

    def test_transport_mode_publishes_its_own_live_boundary(self):
        """A manual transport experiment feeds the same live pipeline."""
        config = dict(VALID_CONFIG, mode="transport")
        out = self._run(
            config,
            {"status": "live", "action": "started",
             "container": "clab-ipsec-transport-sensor",
             "interface": "eth1", "journal_lines": 0},
        )
        self.assertEqual(out["result"]["observation"]["status"], "live")
        self.assertEqual(out["result"]["mode"], "transport")
        self.assertEqual(out["result"]["status"], "PASS")
        # one start boundary (no ended marker) + an open and a closed current
        self.assertEqual(len(out["records"]["start"]), 1)
        self.assertEqual(out["records"]["start"][0][0][1]["mode"], "transport")
        self.assertEqual(len(out["records"]["current"]), 2)
        self.assertIsNone(out["records"]["current"][0][1]["ended_at_ns"])
        self.assertIsNotNone(out["records"]["current"][1][1]["ended_at_ns"])


class TestCampaignObservationOrdering(unittest.TestCase):
    """Observation readiness runs after IPsec verify, before connectivity,
    on both the fresh and the reused dataset path."""

    def _record(self, order, name, value):
        def _side(*args, **kwargs):
            order.append(name)
            return value
        return mock.Mock(side_effect=_side)

    def _run_pipeline(self, reuse_result, ensure_behaviour="live"):
        order = []
        ensure = self._record(
            order, "observation",
            {"status": "live", "action": "reuse",
             "container": "clab-ipsec-sensor", "interface": "eth1"},
        )
        if ensure_behaviour == "raises":
            def _raise(*args, **kwargs):
                order.append("observation")
                raise xdp_obs.ObservationReadinessError(
                    "IPsec testbed is running, but live XDP observation is "
                    "unavailable: xdp_monitor did not stay alive"
                )
            ensure = mock.Mock(side_effect=_raise)

        with tempfile.TemporaryDirectory() as td:
            patchers = [
                patch.object(
                    reuse_mod, "reset_and_deploy_or_reuse",
                    self._record(order, "deploy_or_reuse", reuse_result),
                ),
                patch.object(
                    campaign_mod, "load_generated_configs",
                    self._record(order, "load_cfg", None),
                ),
                patch.object(
                    campaign_mod, "initiate_ipsec",
                    self._record(order, "initiate", None),
                ),
                patch.object(
                    campaign_mod, "verify_ipsec",
                    self._record(order, "verify",
                                 {"ike_sa": "ESTABLISHED",
                                  "child_sa": "INSTALLED", "mode": "TUNNEL"}),
                ),
                patch.object(campaign_mod, "ensure_live_observation", ensure),
                patch.object(
                    campaign_mod, "test_connectivity",
                    self._record(order, "connectivity",
                                 {"status": "PASS", "packet_loss": 0}),
                ),
                patch.object(
                    traffic_mod, "runtime",
                    return_value={"source_container": "clab-ipsec-host-a",
                                  "destination_container": "clab-ipsec-host-b",
                                  "destination_ip": "10.10.2.10"},
                ),
                patch.object(traffic_mod, "copy_trafficgen"),
                patch.object(traffic_mod, "start_receiver"),
                patch.object(traffic_mod, "wait_receiver"),
                patch.object(
                    traffic_mod, "run_sender",
                    self._record(
                        order, "traffic",
                        ("STATS packets=5 bytes=100 seconds=2 bitrate=4000_bps",
                         "PASS"),
                    ),
                ),
                patch.object(traffic_mod, "stop_receiver"),
                patch.object(
                    capture_mod, "capture_facing",
                    return_value=("clab-ipsec-gw-a", "192.168.100.1"),
                ),
                patch.object(
                    capture_mod, "detect_capture_interface",
                    return_value="eth1",
                ),
                patch.object(capture_mod, "start_capture"),
                patch.object(capture_mod, "stop_capture"),
                patch.object(capture_mod, "copy_capture"),
                patch.object(
                    features_mod, "extract_features",
                    return_value={"packet_count": 5},
                ),
                patch.object(dataset_mod, "build_metadata", return_value={}),
            ]
            for patcher in patchers:
                patcher.start()
            try:
                outcome = campaign_mod.execute_trial_pipeline(
                    "run-1-exp-0001-attempt-01", VALID_CONFIG,
                    {"profile": "web", "duration": 10},
                    str(Path(td) / "tmp"),
                    run_id="run-1", log=lambda m: None,
                )
            except xdp_obs.ObservationReadinessError as exc:
                outcome = None
                observation_error = exc
            finally:
                for patcher in reversed(patchers):
                    patcher.stop()
        if outcome is None:
            return order, None, observation_error
        return order, outcome, None

    def test_fresh_deploy_orders_observation_after_ipsec_before_connectivity(self):
        order, outcome, exc = self._run_pipeline(
            {"reused": False, "identity": "tunnel"}
        )
        self.assertIsNone(exc)
        self.assertLess(order.index("deploy_or_reuse"), order.index("verify"))
        self.assertLess(order.index("verify"), order.index("observation"))
        self.assertLess(order.index("observation"), order.index("connectivity"))
        self.assertLess(order.index("connectivity"), order.index("traffic"))
        self.assertEqual(outcome["observation"]["status"], "live")

    def test_reused_attempt_still_verifies_observation_readiness(self):
        order, outcome, exc = self._run_pipeline(
            {"reused": True,
             "ipsec": {"ike_sa": "ESTABLISHED", "child_sa": "INSTALLED",
                       "mode": "TUNNEL"}}
        )
        self.assertIsNone(exc)
        self.assertNotIn("load_cfg", order)
        self.assertNotIn("initiate", order)
        self.assertIn("observation", order)
        self.assertLess(order.index("observation"), order.index("connectivity"))
        self.assertEqual(outcome["observation"]["status"], "live")

    def test_observation_failure_fails_the_attempt_before_connectivity(self):
        order, outcome, exc = self._run_pipeline(
            {"reused": False, "identity": "tunnel"},
            ensure_behaviour="raises",
        )
        self.assertIsNotNone(exc)
        self.assertIsNone(outcome)
        self.assertIn("observation", order)
        self.assertNotIn("connectivity", order)
        self.assertNotIn("traffic", order)


class ObservationEvidenceTestCase(unittest.TestCase):
    """Post-traffic evidence: checked only once traffic has been generated."""

    def test_returns_summary_when_journal_grew(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal_dir = Path(tmp)
            xdp_obs.journal_path(journal_dir).write_text(
                '{"ts":1,"type":"ESP"}\n'
            )
            # baseline 0 == the journal was empty at attach time
            summary = xdp_obs.await_observation_evidence(
                journal_dir=journal_dir, baseline_lines=0, timeout=0.05,
            )
            self.assertEqual(summary["lines"], 1)
            self.assertGreater(summary["bytes"], 0)

    def test_raises_when_no_observation_arrived(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal_dir = Path(tmp)
            xdp_obs.journal_path(journal_dir).write_text("")
            with self.assertRaises(xdp_obs.ObservationReadinessError) as ctx:
                xdp_obs.await_observation_evidence(
                    journal_dir=journal_dir, baseline_lines=0, timeout=0.05,
                )
            self.assertIn("no observations after traffic", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()