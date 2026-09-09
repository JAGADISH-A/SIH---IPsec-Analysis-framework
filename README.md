# SIH — IPsec Analysis Framework

# IPsec VPN Testbed

A reproducible four-container IPsec VPN testbed built with **Containerlab** and **strongSwan 6.0.3**.

The testbed models two LANs connected through two IPsec gateways:

```text
              IPsec VPN
             ═══════════
Host-A ─── GW-A ───────── GW-B ─── Host-B
          LAN-A    WAN     LAN-B
```

## 1. Testbed Topology

The testbed contains exactly four containers:

| Node     | Role          | Address                            |
| -------- | ------------- | ---------------------------------- |
| `host-a` | LAN-A host    | `10.10.1.10/24`                    |
| `gw-a`   | IPsec gateway | `10.10.1.1/24`, `192.168.100.1/24` |
| `gw-b`   | IPsec gateway | `192.168.100.2/24`, `10.10.2.1/24` |
| `host-b` | LAN-B host    | `10.10.2.10/24`                    |

The WAN link between the gateways uses:

```text
GW-A: 192.168.100.1/24
GW-B: 192.168.100.2/24
```

The LANs are:

```text
LAN-A: 10.10.1.0/24
LAN-B: 10.10.2.0/24
```

The Containerlab management network is separate from the IPsec dataplane.

---

## 2. Requirements

Run the testbed inside the Ubuntu VM.

Required:

* Ubuntu
* Docker
* Containerlab
* Git

Check Containerlab:

```bash
containerlab version
```

Check Docker:

```bash
docker --version
```

---

## 3. Project Structure

The important testbed files are:

```text
ipsec-testbed/
├── .gitignore
├── README.md
├── gateway-image/
│   └── Dockerfile
├── host-image/
│   └── Dockerfile
├── configs/
│   ├── gw-a/
│   │   └── swanctl/
│   └── gw-b/
│       └── swanctl/
├── scripts/
│   └── gw-entrypoint.sh
└── topology/
    └── ipsec.clab.yml
```

Containerlab-generated directories such as:

```text
topology/clab-ipsec/
```

are generated during deployment and are ignored by Git.

---

## 4. Build the Container Images

### Host image

The host image provides basic networking tools such as `ip` and `ping`.

Build it with:

```bash
docker build -t ipsec-test-host:24.04 ./host-image
```

### Gateway image

The gateway image is based on:

```text
openeuler/strongswan:6.0.3-oe2403sp4
```

and includes additional diagnostic tools such as `tcpdump`.

Build it with:

```bash
docker build -t ipsec-test-gateway:6.0.3 ./gateway-image
```

Verify the images:

```bash
docker images | grep -E 'ipsec-test-(host|gateway)'
```

---

## 5. Deploy the Testbed

From the repository root:

```bash
containerlab deploy -t topology/ipsec.clab.yml
```

The topology creates:

```text
clab-ipsec-host-a
clab-ipsec-gw-a
clab-ipsec-gw-b
clab-ipsec-host-b
```

Verify:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

All four containers should be running.

---

## 6. Verify Network Configuration

### GW-A

```bash
docker exec clab-ipsec-gw-a ip addr show eth1
docker exec clab-ipsec-gw-a ip addr show eth2
docker exec clab-ipsec-gw-a ip route
```

Expected addresses:

```text
eth1: 10.10.1.1/24
eth2: 192.168.100.1/24
```

Expected cross-LAN route:

```text
10.10.2.0/24 via 192.168.100.2
```

### GW-B

```bash
docker exec clab-ipsec-gw-b ip addr show eth1
docker exec clab-ipsec-gw-b ip addr show eth2
docker exec clab-ipsec-gw-b ip route
```

Expected:

```text
eth1: 10.10.2.1/24
eth2: 192.168.100.2/24
```

Expected cross-LAN route:

```text
10.10.1.0/24 via 192.168.100.1
```

---

## 7. Verify Automatic strongSwan Startup

The gateway entrypoint automatically:

1. Starts `charon`.
2. Waits for VICI to become available.
3. Loads the strongSwan configuration.
4. Keeps the container running.

Verify `charon`:

```bash
docker exec clab-ipsec-gw-a pgrep -a charon
docker exec clab-ipsec-gw-b pgrep -a charon
```

Expected:

```text
/usr/local/libexec/ipsec/charon
```

Verify the loaded connection:

```bash
docker exec clab-ipsec-gw-a swanctl --list-conns
```

Expected connection:

```text
gw-a-to-gw-b
```

---

## 8. IPsec Configuration

The gateways use:

```text
IKE version:       IKEv2
Authentication:    Pre-shared key
GW-A ID:           gw-a
GW-B ID:           gw-b
```

The IPsec traffic selectors are:

```text
GW-A local:        10.10.1.0/24
GW-A remote:       10.10.2.0/24

GW-B local:        10.10.2.0/24
GW-B remote:       10.10.1.0/24
```

IKE proposal:

```text
AES-256
SHA-256
MODP-2048
```

ESP proposal:

```text
AES-GCM-256
```

The lab uses a shared PSK configured in the gateway `swanctl` configuration.

---

## 9. Establish the IPsec Tunnel

Initiate the tunnel from GW-A:

```bash
docker exec clab-ipsec-gw-a \
  swanctl --initiate --child lan-a-to-lan-b
```

Successful establishment should report:

```text
IKE_SA ... established
CHILD_SA ... established
initiate completed successfully
```

---

## 10. Verify the IPsec Security Association

Run:

```bash
docker exec clab-ipsec-gw-a swanctl --list-sas
```

Expected state:

```text
ESTABLISHED, IKEv2
CHILD_SA ... TUNNEL
```

The CHILD_SA should show:

```text
10.10.1.0/24 === 10.10.2.0/24
```

---

## 11. Test LAN-to-LAN Traffic

From Host-A:

```bash
docker exec clab-ipsec-host-a ping -c 5 10.10.2.10
```

Expected:

```text
5 packets transmitted, 5 received, 0% packet loss
```

Reverse traffic can be tested with:

```bash
docker exec clab-ipsec-host-b ping -c 5 10.10.1.10
```

---

## 12. Verify XFRM/IPsec Processing

On GW-A:

```bash
docker exec clab-ipsec-gw-a ip -s xfrm state
```

Also inspect policies:

```bash
docker exec clab-ipsec-gw-a ip -s xfrm policy
```

After traffic has passed through the tunnel, packet and byte counters should be non-zero.

The same checks can be performed on GW-B:

```bash
docker exec clab-ipsec-gw-b ip -s xfrm state
docker exec clab-ipsec-gw-b ip -s xfrm policy
```

---

## 13. Verify ESP on the WAN

The gateway image includes `tcpdump`.

On GW-A:

```bash
docker exec clab-ipsec-gw-a \
  tcpdump -ni any 'host 192.168.100.2' -c 10
```

After generating traffic, the WAN capture should show ESP packets:

```text
192.168.100.1 > 192.168.100.2: ESP
192.168.100.2 > 192.168.100.1: ESP
```

This verifies that LAN traffic is being carried through the IPsec ESP tunnel across the WAN.

---

# 14. Tunnel Lifecycle Test

Terminate the existing tunnel:

```bash
docker exec clab-ipsec-gw-a \
  swanctl --terminate --ike gw-a-to-gw-b
```

Verify:

```bash
docker exec clab-ipsec-gw-a swanctl --list-sas
```

Re-establish:

```bash
docker exec clab-ipsec-gw-a \
  swanctl --initiate --child lan-a-to-lan-b
```

Then verify traffic:

```bash
docker exec clab-ipsec-host-a ping -c 5 10.10.2.10
```

Expected:

```text
5 packets transmitted, 5 received, 0% packet loss
```

---

# 15. Negative Test — Wrong PSK

The testbed has been validated with an intentionally incorrect PSK.

Procedure:

1. Establish the tunnel with the correct PSK.
2. Temporarily change the PSK on one gateway.
3. Terminate the existing SA.
4. Reload the credentials/configuration.
5. Attempt to initiate the tunnel.
6. Verify that authentication fails.
7. Verify that no CHILD_SA is established.
8. Restore the correct PSK.
9. Reload the configuration.
10. Re-establish the tunnel.
11. Verify LAN traffic again.

Expected result with the wrong PSK:

```text
IKE authentication fails
CHILD_SA is not established
LAN traffic does not pass
```

After restoring the correct PSK:

```text
IKE authentication succeeds
CHILD_SA establishes
LAN traffic recovers
```

---

# 16. Gateway Recovery

A direct Docker restart of a Containerlab node does **not** recreate the Containerlab dataplane links.

For example:

```bash
docker restart clab-ipsec-gw-a
```

may leave the container without the Containerlab-created `eth1` and `eth2` interfaces.

Therefore, the supported recovery procedure for this testbed is to recreate the Containerlab topology:

```bash
containerlab destroy -t topology/ipsec.clab.yml
```

Then:

```bash
containerlab deploy -t topology/ipsec.clab.yml
```

This recreates:

```text
eth1
eth2
IP addresses
routes
Containerlab links
```

The gateway entrypoint then automatically starts `charon` and loads the strongSwan configuration.

Re-establish the tunnel:

```bash
docker exec clab-ipsec-gw-a \
  swanctl --initiate --child lan-a-to-lan-b
```

Verify traffic:

```bash
docker exec clab-ipsec-host-a ping -c 5 10.10.2.10
```

Expected:

```text
5 packets transmitted, 5 received, 0% packet loss
```

This recovery sequence has been successfully validated.

---

# 17. Clean Shutdown

To remove the complete testbed:

```bash
containerlab destroy -t topology/ipsec.clab.yml
```

Verify:

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}'
```

Containerlab-generated files should remain excluded by `.gitignore`.

---

# 18. Final Validation Checklist

A deployment is considered successful when all of the following pass:

```text
[ ] Four containers running
[ ] Host-A LAN address configured
[ ] GW-A LAN/WAN addresses configured
[ ] GW-B WAN/LAN addresses configured
[ ] Host-B LAN address configured
[ ] Cross-LAN routes present
[ ] IPv4 forwarding enabled
[ ] charon running on both gateways
[ ] VICI available
[ ] swanctl configuration loaded
[ ] IKEv2 SA established
[ ] CHILD_SA established
[ ] Correct traffic selectors installed
[ ] XFRM state/policy present
[ ] ESP observed on WAN
[ ] Host-A → Host-B ping successful
[ ] Host-B → Host-A ping successful
[ ] Tunnel terminate/re-establish successful
[ ] Wrong-PSK test fails as expected
[ ] Correct PSK restoration succeeds
[ ] Containerlab recreation restores the testbed
[ ] Traffic recovers after recreation
```

---

# 19. Result

The testbed provides a reproducible four-node environment for IPsec experimentation:

```text
Host-A
  |
  | 10.10.1.0/24
  |
GW-A
  |
  | 192.168.100.0/24
  |       IPsec / ESP
  |
GW-B
  |
  | 10.10.2.0/24
  |
Host-B
```

The validated baseline demonstrates:

```text
Containerlab deployment
        ↓
Network configuration
        ↓
Automatic strongSwan startup
        ↓
VICI readiness
        ↓
Configuration loading
        ↓
IKEv2 negotiation
        ↓
PSK authentication
        ↓
CHILD_SA establishment
        ↓
XFRM policy/state
        ↓
ESP-protected traffic
        ↓
Bidirectional LAN connectivity
        ↓
Lifecycle recovery
        ↓
Negative authentication testing
        ↓
Topology recreation and recovery
```

This is the baseline IPsec testbed for the project.
