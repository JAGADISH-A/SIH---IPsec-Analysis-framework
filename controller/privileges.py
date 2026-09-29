"""Non-interactive privilege resolution for testbed subprocesses.

The testbed dataplane (``docker exec``/``docker cp`` against the containerlab
containers) is driven from the controller host.  Execution must NEVER block on
an interactive sudo prompt (a web/background worker would hang mid-run), so
elevation always goes through ``sudo -n`` when privileged sudo is available.
On hosts where the docker CLI is directly reachable (docker group / rootless
docker) the same calls run unprivileged -- the XDP/xdp_monitor path then needs
no host sudo at all.  Root-gated steps that genuinely run in the host network
namespace (containerlab deploy/destroy, the ``br-wan`` lifecycle wrapper) keep
resolving to ``sudo -n``.

The choice is resolved once per tool and cached (safe, non-command probes).
"""

import functools
import subprocess

_SAFE_PROBES = {
    "docker": ["docker", "ps"],
    "containerlab": ["containerlab", "version"],
    "bash": ["bash", "--version"],
}


def _sudo_noninteractive() -> bool:
    try:
        done = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            timeout=5,
        )
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _reachable(binary: str) -> bool:
    probe = _SAFE_PROBES.get(binary)
    if not probe:
        return False
    try:
        done = subprocess.run(probe, capture_output=True, timeout=5)
        return done.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@functools.lru_cache(maxsize=None)
def prefix_for(binary: str) -> tuple:
    """argv prefix for ``binary``: ``("sudo", "-n")`` or ``()`` (bare).

    Falls back to ``("sudo", "-n")`` so the behaviour and error on restricted
    hosts is exactly what it was before this resolver existed.
    """
    if _sudo_noninteractive():
        return ("sudo", "-n")
    if _reachable(binary):
        return ()
    return ("sudo", "-n")


def docker_prefix() -> tuple:
    """argv prefix for ``docker`` (resolved once, cached)."""
    return prefix_for("docker")