"""Tests for the traffic-backend orchestration (builtin vs D-ITG).

Run as:

    .venv/bin/python -m unittest controller.test_traffic

All docker invocations are mocked; no containerlab / network access is
required.  These tests pin the D-ITG command-line construction to the
verified ITGSend vocabulary (see vendor/ditg/VERSION) so a regression in
the emitted options is caught without ever running ITGSend.
"""

import os
import unittest
from unittest.mock import Mock, patch

from controller import traffic as traffic_mod


def _docker_mock(*returncodes):
    """Return a controller.traffic._docker stand-in returning rc codes."""
    mock = Mock(side_effect=[Mock(returncode=rc) for rc in returncodes])
    return mock


class TestGeneratorSelection(unittest.TestCase):
    def tearDown(self):
        traffic_mod._TRAFFIC_GENERATOR = None
        os.environ.pop(traffic_mod.GENERATOR_ENV, None)

    def test_default_generator_is_builtin(self):
        self.assertEqual(traffic_mod.get_traffic_generator(), "builtin")

    def test_env_variable_selects_backend(self):
        os.environ[traffic_mod.GENERATOR_ENV] = "ditg"
        traffic_mod._TRAFFIC_GENERATOR = None
        self.assertEqual(traffic_mod.get_traffic_generator(), "ditg")

    def test_set_traffic_generator_overrides(self):
        traffic_mod.set_traffic_generator("ditg")
        self.assertEqual(traffic_mod.get_traffic_generator(), "ditg")
        traffic_mod.set_traffic_generator("builtin")
        self.assertEqual(traffic_mod.get_traffic_generator(), "builtin")

    def test_unsupported_generator_rejected(self):
        with self.assertRaises(ValueError):
            traffic_mod.set_traffic_generator("netperf")


class TestDitgCommandConstruction(unittest.TestCase):
    def test_voip_command(self):
        argv = traffic_mod.build_ditg_command(
            "voip", "10.20.1.20", port=20000, duration=30.0
        )
        self.assertEqual(argv[0], "/tmp/ITGSend")
        self.assertIn("-a", argv)
        self.assertEqual(argv[argv.index("-a") + 1], "10.20.1.20")
        self.assertEqual(argv[argv.index("-rp") + 1], "20000")
        self.assertEqual(argv[argv.index("-T") + 1], "UDP")
        self.assertEqual(argv[argv.index("-C") + 1], "50")
        self.assertEqual(argv[argv.index("-c") + 1], "160")
        self.assertEqual(argv[argv.index("-t") + 1], "30000")
        self.assertEqual(argv[argv.index("-s") + 1], "0.1001")
        self.assertNotIn("-B", argv)
        self.assertNotIn("-D", argv)

    def test_video_command(self):
        argv = traffic_mod.build_ditg_command("video", "10.20.1.20", duration=20)
        self.assertEqual(argv[argv.index("-C") + 1], "250")
        self.assertEqual(argv[argv.index("-c") + 1], "1200")
        self.assertEqual(argv[argv.index("-t") + 1], "20000")

    def test_messaging_burst_command(self):
        argv = traffic_mod.build_ditg_command(
            "messaging", "10.20.1.20", duration=30.0
        )
        self.assertEqual(argv[argv.index("-C") + 1], "200")
        self.assertEqual(argv[argv.index("-c") + 1], "110")
        b = argv.index("-B")
        self.assertEqual(argv[b:b + 5], ["-B", "C", "1000", "C", "3000"])

    def test_email_burst_and_nagle_command(self):
        argv = traffic_mod.build_ditg_command(
            "email", "10.20.1.20", duration=30.0
        )
        self.assertEqual(argv[argv.index("-T") + 1], "TCP")
        self.assertEqual(argv[argv.index("-C") + 1], "5")
        self.assertEqual(argv[argv.index("-c") + 1], "8192")
        self.assertIn("-D", argv)
        b = argv.index("-B")
        self.assertEqual(argv[b:b + 5], ["-B", "C", "1000", "C", "1000"])

    def test_web_command(self):
        argv = traffic_mod.build_ditg_command("web", "10.20.1.20", duration=30)
        self.assertEqual(argv[argv.index("-T") + 1], "TCP")
        self.assertEqual(argv[argv.index("-C") + 1], "2")
        self.assertEqual(argv[argv.index("-c") + 1], "320")
        self.assertIn("-D", argv)
        self.assertNotIn("-B", argv)

    def test_send_and_recv_logs_requested(self):
        argv = traffic_mod.build_ditg_command("voip", "10.20.1.20", duration=10)
        self.assertEqual(argv[argv.index("-l") + 1], "/tmp/ditg_send.log")
        self.assertEqual(argv[argv.index("-x") + 1], "/tmp/ditg_recv.log")

    def test_icmp_not_supported_via_ditg_cli(self):
        with self.assertRaises(ValueError):
            traffic_mod.build_ditg_command("icmp", "10.20.1.20", duration=10)

    def test_command_is_deterministic(self):
        a = traffic_mod.build_ditg_command("messaging", "10.20.1.20", duration=30)
        b = traffic_mod.build_ditg_command("messaging", "10.20.1.20", duration=30)
        self.assertEqual(a, b)


class TestResolveTrafficModel(unittest.TestCase):
    def tearDown(self):
        traffic_mod._TRAFFIC_GENERATOR = None
        os.environ.pop(traffic_mod.GENERATOR_ENV, None)

    def test_builtin_model_fields(self):
        model = traffic_mod.resolve_traffic_model("voip", 30.0, 20000)
        self.assertEqual(model["generator"], "builtin")
        self.assertEqual(model["profile"], "voip")
        self.assertEqual(model["duration"], 30.0)
        self.assertEqual(model["port"], 20000)
        self.assertEqual(model["protocol"], "udp")
        self.assertEqual(model["packet_rate"], 50.0)
        self.assertEqual(model["packet_size"], 160)
        self.assertIsNone(model["seed"])
        self.assertTrue(model["deterministic"])

    def test_builtin_burst_model_messaging(self):
        model = traffic_mod.resolve_traffic_model("messaging", 30.0)
        self.assertEqual(model["burst"], {"on_ms": 1000, "off_ms": 3000})
        self.assertEqual(model["distribution"]["idt"], "bursty")

    def test_ditg_model_fields_and_seed(self):
        traffic_mod.set_traffic_generator("ditg")
        model = traffic_mod.resolve_traffic_model("email", 30.0, 20000)
        self.assertEqual(model["generator"], "ditg")
        self.assertEqual(model["version"], traffic_mod.DITG_VERSION)
        self.assertEqual(model["protocol"], "TCP")
        self.assertEqual(model["seed"], "0.4004")
        self.assertEqual(model["burst"], {"on_ms": 1000, "off_ms": 1000})
        self.assertEqual(model["distribution"]["idt"], "on-off")

    def test_ditg_constant_distribution(self):
        traffic_mod.set_traffic_generator("ditg")
        model = traffic_mod.resolve_traffic_model("voip", 30.0)
        self.assertEqual(model["distribution"], {"idt": "constant", "ps": "constant"})

    def test_icmp_always_ping_regardless_of_backend(self):
        for generator in ("builtin", "ditg"):
            traffic_mod.set_traffic_generator(generator)
            model = traffic_mod.resolve_traffic_model("icmp", 30.0)
            self.assertEqual(model["generator"], "ping")
            self.assertEqual(model["protocol"], "icmp")
            self.assertEqual(model["packet_rate"], 5.0)

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            traffic_mod.resolve_traffic_model("bittorrent", 30.0)

    def test_model_is_deterministic(self):
        traffic_mod.set_traffic_generator("ditg")
        a = traffic_mod.resolve_traffic_model("web", 30.0, 20000)
        b = traffic_mod.resolve_traffic_model("web", 30.0, 20000)
        self.assertEqual(a, b)


class TestCopyTrafficgenDispatch(unittest.TestCase):
    def tearDown(self):
        traffic_mod._TRAFFIC_GENERATOR = None
        os.environ.pop(traffic_mod.GENERATOR_ENV, None)
    def test_builtin_copies_only_python_generator(self):
        with patch.object(traffic_mod, "_docker") as docker:
            traffic_mod.set_traffic_generator("builtin")
            traffic_mod.copy_trafficgen("clab-c")
            calls = [call.args[0] for call in docker.call_args_list]
            self.assertEqual(len(calls), 1)
            self.assertIn("trafficgen.py", calls[0][-1])

    def test_ditg_copies_python_generator_and_binaries(self):
        with patch.object(traffic_mod, "_docker") as docker:
            traffic_mod.set_traffic_generator("ditg")
            traffic_mod.copy_trafficgen("clab-c")
            calls = [call.args[0] for call in docker.call_args_list]
            self.assertEqual(len(calls), 1 + len(traffic_mod.DITG_BINARIES))
            self.assertTrue(any("trafficgen.py" in c[-1] for c in calls))
            self.assertTrue(any(c[-1].endswith("/ITGSend") for c in calls))
            self.assertTrue(any(c[-1].endswith("/ITGRecv") for c in calls))
            self.assertTrue(any(c[-1].endswith("/ITGDec") for c in calls))

    def test_ditg_missing_binary_fails_fast(self):
        with patch.object(traffic_mod, "_docker") as docker:
            traffic_mod.set_traffic_generator("ditg")
            with patch.object(traffic_mod.Path, "is_file", return_value=False):
                with self.assertRaises(FileNotFoundError):
                    traffic_mod.copy_trafficgen("clab-c")
            self.assertEqual(docker.call_count, 1)  # only trafficgen.py copied


class TestReceiverDispatch(unittest.TestCase):
    def setUp(self):
        self.addCleanup(
            lambda: setattr(traffic_mod, "_TRAFFIC_GENERATOR", None)
        )

    def test_builtin_start_receiver_runs_trafficgen_recv(self):
        with patch.object(traffic_mod, "_docker") as docker:
            traffic_mod.set_traffic_generator("builtin")
            traffic_mod.start_receiver("clab-d", "10.20.1.20", port=20000,
                                       duration=45.0)
            args = docker.call_args_list[-1].args[0]
            self.assertEqual(args[0], "exec")
            self.assertEqual(args[2], "clab-d")
            self.assertIn("--role", args)
            self.assertIn("recv", args)

    def test_ditg_start_receiver_runs_itgrecv_detached(self):
        with patch.object(traffic_mod, "_docker") as docker:
            traffic_mod.set_traffic_generator("ditg")
            traffic_mod.start_receiver("clab-d", "10.20.1.20", port=20000)
            args = [call.args[0] for call in docker.call_args_list]
            self.assertEqual(args[0][0], "exec")  # stale ITGRecv reaped
            detached = args[-1]
            self.assertEqual(detached[0], "exec")
            self.assertEqual(detached[1], "-d")
            self.assertEqual(detached[3], "/tmp/ITGRecv")

    def test_stop_receiver_reaps_both_backends(self):
        with patch.object(traffic_mod, "_docker") as docker:
            traffic_mod.stop_receiver("clab-d")
            args = [call.args[0] for call in docker.call_args_list]
            joined = "".join(str(a) for a in args)
            self.assertIn("[t]rafficgen.py", joined)
            self.assertIn("[I]TGRecv", joined)


class TestSenderDispatch(unittest.TestCase):
    def setUp(self):
        self.addCleanup(
            lambda: setattr(traffic_mod, "_TRAFFIC_GENERATOR", None)
        )

    def test_ditg_sender_runs_itgsend_and_maps_rc(self):
        with patch.object(traffic_mod.subprocess, "run") as run:
            run.return_value = Mock(
                returncode=0,
                stdout="Started sending packets of flow ID: 1\n",
                stderr="",
            )
            traffic_mod.set_traffic_generator("ditg")
            log, status = traffic_mod.run_sender(
                "clab-c", "voip", "10.20.1.20", port=20000, duration=30.0
            )
            self.assertEqual(status, "PASS")
            args = run.call_args.args[0]
            self.assertEqual(args[0:4], ["sudo", "-n", "docker", "exec"])
            self.assertIn("/tmp/ITGSend", args)
            self.assertIn("Started sending", log)

    def test_ditg_sender_failure_maps_to_fail(self):
        with patch.object(traffic_mod.subprocess, "run") as run:
            run.return_value = Mock(
                returncode=1, stdout="", stderr="Connect error ..."
            )
            traffic_mod.set_traffic_generator("ditg")
            _log, status = traffic_mod.run_sender(
                "clab-c", "voip", "10.20.1.20", duration=30.0
            )
            self.assertEqual(status, "FAIL")

    def test_ditg_backend_still_uses_ping_for_icmp(self):
        with patch.object(traffic_mod, "_docker") as docker:
            docker.return_value = Mock(returncode=0, stdout="PING OK\n",
                                       stderr="")
            traffic_mod.set_traffic_generator("ditg")
            log, status = traffic_mod.run_sender(
                "clab-c", "icmp", "10.20.1.20", duration=30.0
            )
            self.assertEqual(status, "PASS")
            args = docker.call_args.args[0]
            self.assertTrue(any("trafficgen.py" in a for a in args))
            self.assertTrue(any("--profile" == a for a in args))

    def test_builtin_sender_runs_trafficgen_send(self):
        with patch.object(traffic_mod, "_docker") as docker:
            docker.return_value = Mock(returncode=0, stdout="STATS ...\n",
                                       stderr="")
            traffic_mod.set_traffic_generator("builtin")
            log, status = traffic_mod.run_sender(
                "clab-c", "voip", "10.20.1.20", port=20000, duration=30.0
            )
            self.assertEqual(status, "PASS")
            args = docker.call_args.args[0]
            self.assertTrue(any("trafficgen.py" in a for a in args))
            self.assertIn("send", args)


class TestWaitReceiverDispatch(unittest.TestCase):
    def setUp(self):
        self.addCleanup(
            lambda: setattr(traffic_mod, "_TRAFFIC_GENERATOR", None)
        )

    def test_ditg_polls_itgrecv_process_on_destination(self):
        with patch.object(traffic_mod, "_docker") as docker:
            docker.return_value = Mock(returncode=0)
            traffic_mod.set_traffic_generator("ditg")
            outcome = traffic_mod.wait_receiver("clab-c", "10.20.1.20", timeout=2)
            self.assertTrue(outcome)
            args = docker.call_args.args[0]
            self.assertEqual(args[0], "exec")
            self.assertEqual(args[1], "clab-ipsec-transport-host-d")
            self.assertIn("[I]TGRecv", args[-1])

    def test_ditg_wait_times_out_when_receiver_never_starts(self):
        with patch.object(traffic_mod, "_docker") as docker:
            docker.return_value = Mock(returncode=1)
            traffic_mod.set_traffic_generator("ditg")
            with self.assertRaises(RuntimeError):
                traffic_mod.wait_receiver("clab-c", "10.20.1.20", timeout=0.6)

    def test_builtin_probes_tcp_listener_from_source(self):
        with patch.object(traffic_mod.subprocess, "run") as run:
            run.return_value = Mock(returncode=0)
            traffic_mod.set_traffic_generator("builtin")
            self.assertTrue(
                traffic_mod.wait_receiver("clab-c", "10.20.1.20", port=20000,
                                          timeout=2)
            )
            args = run.call_args.args[0]
            self.assertEqual(args[0:4], ["sudo", "-n", "docker", "exec"])
            self.assertIn("socket", args[-1])

    def test_unknown_dest_ip_rejected_for_ditg(self):
        traffic_mod.set_traffic_generator("ditg")
        with patch.object(traffic_mod, "_docker") as docker:
            with self.assertRaises(ValueError):
                traffic_mod.wait_receiver("clab-c", "203.0.113.99", timeout=0.1)


if __name__ == "__main__":
    unittest.main()