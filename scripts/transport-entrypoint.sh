#!/bin/sh
set -eu

echo "[IPsec] Starting charon..."
/usr/lib/ipsec/charon &

echo "[IPsec] Waiting for VICI..."

i=0
while true; do
    if swanctl --list-conns >/dev/null 2>&1; then
        break
    fi

    i=$((i + 1))

    if [ "$i" -ge 30 ]; then
        echo "[IPsec] ERROR: VICI did not become ready"
        exit 1
    fi

    sleep 1
done

echo "[IPsec] VICI is ready"

echo "[IPsec] Loading StrongSwan configuration..."
swanctl --load-all

echo "[IPsec] StrongSwan ready"

# --- Passive audit observation (authoritative transport host) -------------
# When AUDIT_TAP_IFACE is set (host-c only) provision the passive mirror +
# observation feed used by the audit layer.  This is a pure copy path
# (`tc mirred ... mirror`, ingress + egress) and never alters IPsec
# forwarding.  The mirrored frames are handed to the passive sensor
# (clab-ipsec-transport-sensor) on sensor:eth1, where the ONE xdp_monitor the
# controller manages writes the shared live journal.  Runs here so it is
# reproduced on every containerlab deploy / container (re)create.  A failure
# must not block charon.
if [ -n "${AUDIT_TAP_IFACE:-}" ]; then
    echo "[IPsec] provisioning passive observation on ${AUDIT_TAP_IFACE}"
    if [ -x /usr/local/bin/audit-tap-setup.sh ]; then
        /usr/local/bin/audit-tap-setup.sh "${AUDIT_TAP_IFACE}" || {
            echo "[IPsec] WARNING: audit observation not provisioned" >&2
        }
    else
        echo "[IPsec] WARNING: audit-tap-setup.sh not present in image/bind" >&2
    fi
fi

exec sleep infinity
