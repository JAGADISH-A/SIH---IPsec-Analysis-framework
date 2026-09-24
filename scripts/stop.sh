#!/usr/bin/env bash
#
# stop.sh - tear down the IPsec tunnel testbed.
#
# Reuses the authoritative destroy path (deploy-ipsec.sh destroy), which
# removes the lab containers/networks and the externally-managed br-wan bridge.
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$ROOT_DIR" || exit 1

if [ "$(id -u)" -eq 0 ]; then
    SUDO=""
else
    SUDO="sudo"
fi

echo "=========================================================================="
echo " IPsec testbed - stop / teardown (reuse deploy-ipsec.sh destroy)"
echo "=========================================================================="

if [ "$SUDO" = "sudo" ] && ! sudo -n true >/dev/null 2>&1; then
    echo "[~~] sudo will prompt for a password to remove the br-wan bridge and lab."
fi

if ! $SUDO bash "$SCRIPT_DIR/deploy-ipsec.sh" destroy; then
    echo "[FAIL] teardown did not complete cleanly (see deploy-ipsec.sh output above)."
    exit 1
fi

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "clab-ipsec-"; then
    echo "[FAIL] some clab-ipsec-* containers are still running."
    exit 1
fi

echo
echo "[OK] testbed stopped. Redeploy any time with ./scripts/run.sh"
exit 0