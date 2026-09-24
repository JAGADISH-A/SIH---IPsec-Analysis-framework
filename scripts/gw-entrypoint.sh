#!/bin/sh
set -eu

# --- Passive audit observation (source gateway only) -----------------------
# When AUDIT_TAP_IFACE is set (gw-a in the tunnel topology) provision the
# passive mirror + observation interface used by the audit layer.  This is a
# pure copy path (`tc mirred ... mirror`) and never alters IPsec forwarding.
# Runs here so it is reproduced on every containerlab deploy / container
# (re)create.  A failure must not block charon startup.
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

echo "[IPsec] Starting charon..."
/usr/local/libexec/ipsec/charon &

echo "[IPsec] Waiting for VICI to become ready..."

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

exec sleep infinity
