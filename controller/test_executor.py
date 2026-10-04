"""Unit tests for the executor testbed-lifecycle layer (non-lab).

Covers the host-bridge lifecycle routing (tunnel deploy/destroy go through the
authoritative ``scripts/deploy-ipsec.sh`` wrapper, transport keeps the raw
containerlab calls), the surfacing of real stderr in command errors, the
stage-appropriate bounded subprocess timeout (with full process-group cleanup)
and the fatal-topology error mapping.  Everything is mocked; nothing touches
the lab.

A regression test asserts the non-interactive guarantee: every privileged
testbed subprocess must run under ``sudo -n`` so a background/web worker can
never block on an interactive sudo prompt (the root cause of a dataset run
stuck in RUNNING when non-interactive privilege is unavailable).
"""

import signal
import subprocess
import unittest
from unittest import mock
from unittest.mock import patch

from controller import executor as executor_mod
from controller.executor import (
    FatalTopologyError,
    LIFECYCLE_SCRIPT,
    SUDO,
    deploy,
    destroy,
    reset_and_deploy,
    run,
)


class _FakePopen:
    def __init__(self, command, **kwargs):
        self.command = command
        self.pid = 4242
        self.returncode = 0
        self._out = ""
        self._err = ""
        self._timed_out = None

    def communicate(self, timeout=None):
        if self._timed_out:
            raise subprocess.TimeoutExpired(
                " ".join(self.command), timeout,
                output=self._out, stderr=self._err,
            )
        return self._out, self._err

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


def _popen_side_effect(returncode=0, stdout="", stderr="", timed_out=False):
    # The ``stdout``/``stderr`` kwargs here are the *captured output* the fake
    # should return, NOT the Popen kwargs (which are PIPE == -1).
    def _make(command, **kwargs):
        fake = _FakePopen(command)
        fake.returncode = returncode
        fake._out = stdout
        fake._err = stderr
        fake._timed_out = timed_out
        return fake
    return _make


class TestRunNonInteractiveSudo(unittest.TestCase):
    def test_run_injects_noninteractive_sudo(self):
        """A worker's privileged command must never prompt for a password."""
        with patch.object(executor_mod.subprocess, "Popen",
                          side_effect=_popen_side_effect(stdout="ok\n")) as popen:
            output = run(["sudo", "containerlab", "version"])
        self.assertEqual(output, "ok\n")
        self.assertEqual(popen.call_args[0][0][:2], list(SUDO))

    def test_run_does_not_double_inject_noninteractive_sudo(self):
        with patch.object(executor_mod.subprocess, "Popen",
                          side_effect=_popen_side_effect(stdout="ok\n")) as popen:
            output = run(["sudo", "-n", "containerlab", "version"])
        self.assertEqual(output, "ok\n")
        self.assertEqual(popen.call_args[0][0], ["sudo", "-n", "containerlab", "version"])

    def test_run_timeout_kills_process_group_and_raises(self):
        with patch.object(executor_mod.subprocess, "Popen",
                          side_effect=_popen_side_effect(
                              stderr="containerlab deploy hung", timed_out=True
                          )) as popen, \
                patch.object(executor_mod.os, "killpg") as killpg, \
                patch.object(executor_mod.os, "getpgid", return_value=4242):
            with self.assertRaises(RuntimeError) as ctx:
                run(["sudo", "bash", "deploy-ipsec.sh", "deploy"],
                    timeout=5.0)
        self.assertIn("timed out after 5s", str(ctx.exception))
        self.assertIn("process group killed", str(ctx.exception))
        self.assertIn("containerlab deploy hung", str(ctx.exception))
        killpg.assert_called_once()
        args, kwargs = killpg.call_args
        self.assertEqual(args[0], 4242)
        self.assertEqual(args[1], signal.SIGKILL)


class TestRunErrorDetail(unittest.TestCase):
    def test_nonzero_exit_includes_stderr(self):
        with patch.object(
            executor_mod.subprocess, "Popen",
            side_effect=_popen_side_effect(
                returncode=1,
                stderr="Bridge \"br-wan\" referenced in topology "
                       "but does not exist\n"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                run(["sudo", "containerlab", "deploy", "-t", "x.yml"])
        self.assertIn("Bridge \"br-wan\" referenced", str(ctx.exception))

    def test_nonzero_exit_falls_back_to_stdout(self):
        with patch.object(
            executor_mod.subprocess, "Popen",
            side_effect=_popen_side_effect(
                returncode=1, stdout="some diagnostic"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                run(["sudo", "nope"])
        self.assertIn("some diagnostic", str(ctx.exception))

    def test_zero_exit_returns_stdout(self):
        with patch.object(
            executor_mod.subprocess, "Popen",
            side_effect=_popen_side_effect(stdout="done\n"),
        ):
            self.assertEqual(run(["sudo", "echo", "done"]), "done\n")


class TestSudoAuthFailureIsFatal(unittest.TestCase):
    def test_sudo_auth_failure_maps_to_fatal_topology_error(self):
        """Missing non-interactive privilege must fail the deploy fast and
        surface real sudo stderr, never hang the run in RUNNING."""
        with patch.object(executor_mod, "run", side_effect=RuntimeError(
            "Command failed with exit code 1: sudo: a password is required"
        )):
            with self.assertRaises(FatalTopologyError) as ctx:
                deploy("tunnel")
        self.assertIn("sudo: a password is required", str(ctx.exception))
        self.assertIn("FatalTopologyError", type(ctx.exception).__name__)


class TestDeployLifecycle(unittest.TestCase):
    def test_tunnel_deploy_routes_through_lifecycle_script(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            deploy("tunnel")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["sudo", "-n", "bash",
                                   str(LIFECYCLE_SCRIPT), "deploy"])
        self.assertEqual(kwargs["timeout"], executor_mod.LIFECYCLE_TIMEOUT)

    def test_tunnel_destroy_routes_through_lifecycle_script(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            destroy("tunnel")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0], ["sudo", "-n", "bash",
                                   str(LIFECYCLE_SCRIPT), "destroy"])
        self.assertEqual(kwargs["timeout"], executor_mod.DESTROY_TIMEOUT)

    def test_transport_deploy_stays_on_containerlab(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            deploy("transport")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0][0:3], ["sudo", "-n", "containerlab"])
        self.assertEqual(args[0][3], "deploy")
        self.assertTrue(str(args[0][5]).endswith("transport/ipsec.clab.yml"))
        self.assertEqual(kwargs["timeout"], executor_mod.LIFECYCLE_TIMEOUT)

    def test_transport_destroy_stays_on_containerlab(self):
        with patch.object(executor_mod, "run") as mock_run:
            mock_run.return_value = "ok"
            destroy("transport")
        args, kwargs = mock_run.call_args
        self.assertEqual(args[0][0:3], ["sudo", "-n", "containerlab"])
        self.assertEqual(args[0][3], "destroy")
        self.assertIn("--cleanup", args[0])
        self.assertEqual(kwargs["timeout"], executor_mod.DESTROY_TIMEOUT)

    def test_deploy_failure_raises_fatal_topology_error(self):
        with patch.object(executor_mod, "run", side_effect=RuntimeError(
            "Command failed with exit code 1: Bridge br-wan missing"
        )):
            with self.assertRaises(FatalTopologyError) as ctx:
                deploy("tunnel")
        self.assertIn("Bridge br-wan missing", str(ctx.exception))

    def test_fatal_topology_error_is_runtime_error(self):
        self.assertTrue(issubclass(FatalTopologyError, RuntimeError))

    def test_reset_and_deploy_destroys_both_then_deploys(self):
        # ``wait_for_ipsec_ready`` polls REAL containers via ``docker logs``.
        # Mocking only destroy/deploy left it running against the host, so this
        # test timed out (or passed) depending on whether the tunnel lab
        # happened to be running. The readiness gate is a separate concern with
        # its own tests, so it is stubbed here to keep this one hermetic.
        with patch.object(executor_mod, "destroy") as mock_destroy, \
                patch.object(executor_mod, "deploy") as mock_deploy, \
                patch.object(
                    executor_mod, "wait_for_ipsec_ready",
                    return_value=True,
                ) as mock_ready:
            reset_and_deploy("tunnel")
        mock_destroy.assert_any_call("tunnel")
        mock_destroy.assert_any_call("transport")
        # nat=False is passed explicitly so the deployment key is resolved in
        # one place; the direct tunnel path is still the plain "tunnel" lab.
        mock_deploy.assert_called_once_with("tunnel", nat=False)
        # The NAT lab is a separate deployment and must be torn down too.
        mock_destroy.assert_any_call("transport", nat=True)
        # Readiness is still awaited, and awaited for the deployment being
        # deployed (not the one that was torn down).
        mock_ready.assert_called_once_with("tunnel", nat=False)


class TestTrafficNatPropagation(unittest.TestCase):
    """``run_traffic`` must forward the experiment's NAT axis.

    ``traffic.runtime`` resolves its endpoint table on
    ``mode``/``address_family``/``nat``. A NAT deployment is a *different lab*
    with different container names, so dropping ``nat`` made every NAT sample
    resolve the non-NAT endpoints and copy the traffic payload into containers
    that do not exist there. These tests assert the value that actually
    reaches ``traffic_mod.runtime``: asserting only on the returned result would
    not catch a silently dropped flag.
    """

    @staticmethod
    def _config(**overrides):
        base = {
            "mode": "transport",
            "address_family": "ipv4",
            "nat": False,
            "traffic": {"profile": "voip", "duration": 10},
        }
        base.update(overrides)
        return base

    def _patched(self, endpoints):
        """Patch only the side-effecting traffic calls.

        The module-level tables (``PROFILES``, ``DEFAULT_PORT``) must stay REAL,
        because ``validate_traffic`` reads them; replacing the whole module would
        make every profile look unsupported.
        """
        patches = {
            "runtime": mock.DEFAULT,
            "copy_trafficgen": mock.DEFAULT,
            "start_receiver": mock.DEFAULT,
            "wait_receiver": mock.DEFAULT,
            "stop_receiver": mock.DEFAULT,
        }
        started = {}
        for name in patches:
            started[name] = patch.object(executor_mod.traffic_mod, name)
        started["run_sender"] = patch.object(
            executor_mod.traffic_mod, "run_sender",
            return_value=("traffic log line", "PASS"),
        )
        mocks = {name: p.start() for name, p in started.items()}
        self.addCleanup(lambda: [p.stop() for p in started.values()])
        mocks["runtime"].return_value = endpoints
        return mocks

    @staticmethod
    def _endpoints(source, destination, source_ip, destination_ip):
        return {
            "source_container": source,
            "destination_container": destination,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
        }

    def _run(self, config, endpoints):
        mocks = self._patched(endpoints)
        executor_mod.run_traffic(config)
        return mocks

    def test_nat_true_reaches_traffic_runtime(self):
        eps = self._endpoints("clab-nat-src", "clab-nat-dst", "10.0.0.1", "10.0.0.2")
        mocks = self._run(self._config(nat=True), eps)
        args, kwargs = mocks["runtime"].call_args
        self.assertIs(
            kwargs.get("nat"),
            True,
            "nat=True was dropped before reaching traffic.runtime()",
        )
        self.assertEqual(args, ("transport", "ipv4"))

    def test_nat_false_reaches_traffic_runtime_explicitly(self):
        eps = self._endpoints("clab-src", "clab-dst", "10.0.0.1", "10.0.0.2")
        mocks = self._run(self._config(nat=False), eps)
        self.assertIs(mocks["runtime"].call_args.kwargs.get("nat"), False)

    def test_missing_nat_key_defaults_to_false(self):
        config = self._config()
        config.pop("nat")
        eps = self._endpoints("clab-src", "clab-dst", "10.0.0.1", "10.0.0.2")
        mocks = self._run(config, eps)
        self.assertIs(mocks["runtime"].call_args.kwargs.get("nat"), False)

    def test_non_nat_traffic_config_is_unchanged(self):
        # A non-NAT sample must keep addressing exactly the endpoints the
        # non-NAT endpoint table declares.
        from controller.traffic import runtime as real_runtime

        expected = real_runtime("transport", "ipv4", nat=False)
        self.assertEqual(expected["source_container"], "clab-ipsec-transport-host-c")

        mocks = self._run(self._config(nat=False), expected)
        self.assertEqual(mocks["runtime"].call_args.args, ("transport", "ipv4"))
        self.assertIs(mocks["runtime"].call_args.kwargs.get("nat"), False)
        copied = [c.args[0] for c in mocks["copy_trafficgen"].call_args_list]
        self.assertEqual(copied[0], "clab-ipsec-transport-host-c")
        self.assertEqual(copied[1], "clab-ipsec-transport-host-d")

    def test_nat_traffic_uses_the_nat_lab_endpoints(self):
        # End to end through the real endpoint table: a NAT sample must address
        # the NAT lab's containers and its far-side (translated) address.
        from controller.traffic import runtime as real_runtime

        endpoints = real_runtime("transport", "ipv4", nat=True)
        self.assertEqual(endpoints["source_container"],
                         "clab-ipsec-transport-nat-host-c")
        self.assertEqual(endpoints["destination_container"],
                         "clab-ipsec-transport-nat-host-d")
        self.assertEqual(endpoints["destination_ip"], "10.30.1.20")

        mocks = self._run(self._config(nat=True), endpoints)
        self.assertIs(mocks["runtime"].call_args.kwargs["nat"], True)
        copied = [c.args[0] for c in mocks["copy_trafficgen"].call_args_list]
        self.assertEqual(copied[0], "clab-ipsec-transport-nat-host-c")
        self.assertEqual(copied[1], "clab-ipsec-transport-nat-host-d")
        # The receiver must bind on the far side of the translator.
        self.assertEqual(
            mocks["start_receiver"].call_args.args[1], "10.30.1.20"
        )

    def test_ipv6_nat_is_rejected_before_traffic_is_addressed(self):
        # The NAT rejection path must stay ahead of traffic addressing; the
        # propagation fix must not weaken it.
        from controller.validate import validate_config

        config = self._config(address_family="ipv6", nat=True)
        config.update({
            "ike": {"version": 2, "encryption": "aes256",
                    "integrity": "sha256", "dh_group": "modp2048"},
            "esp": {"encryption": "aes128gcm16", "integrity": None,
                    "dh_group": "modp4096", "pfs": True},
        })
        with self.assertRaises(ValueError) as ctx:
            validate_config(config)
        self.assertIn("No NAT deployment is defined", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()