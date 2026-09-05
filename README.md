# SIH---IPsec-Analysis-framework

# IPsec Testbed — Setup Steps

## 1. Create the Network Topology

Run the topology setup script:

```bash
chmod +x setup_topology.sh
sudo ./setup_topology.sh
```

This creates four Linux network namespaces:

```text
lan-a
gw-a
gw-b
lan-b
```

Topology:

```text
lan-a ── gw-a ═════ gw-b ── lan-b
              WAN
```

IP addresses:

```text
lan-a  = 10.10.1.10
gw-a   = 10.10.1.1 / 192.168.50.1

gw-b   = 192.168.50.2 / 10.10.2.1
lan-b  = 10.10.2.10
```

---

## 2. Verify Basic Connectivity

Test that the LANs can communicate:

```bash
sudo ip netns exec lan-a ping -c 3 10.10.2.10
```

Expected:

```text
3 packets transmitted, 3 received, 0% packet loss
```

---

## 3. Build and Install strongSwan

We built **strongSwan 6.0.7** separately for each gateway.

GW-A:

```text
/opt/strongswan-gw-a
```

GW-B:

```text
/opt/strongswan-gw-b
```

Each installation has its own configuration and runtime directory.

Verify:

```bash
/opt/strongswan-gw-a/libexec/ipsec/charon --version
```

```bash
/opt/strongswan-gw-b/libexec/ipsec/charon --version
```

---

## 4. Configure the IPsec Gateways

### GW-A

```text
Local address:  192.168.50.1
Remote address: 192.168.50.2

Local ID:       gw-a
Remote ID:      gw-b

Local subnet:   10.10.1.0/24
Remote subnet:  10.10.2.0/24
```

### GW-B

```text
Local address:  192.168.50.2
Remote address: 192.168.50.1

Local ID:       gw-b
Remote ID:      gw-a

Local subnet:   10.10.2.0/24
Remote subnet:  10.10.1.0/24
```

Both gateways use the same PSK.

---

## 5. Start strongSwan in Each Namespace

Run `charon` separately inside `gw-a` and `gw-b`.

Each gateway uses its own VICI socket:

```text
/run/ipsec-testbed/gw-a/charon.vici
/run/ipsec-testbed/gw-b/charon.vici
```

---

## 6. Load the strongSwan Configuration

For example, on GW-B:

```bash
sudo ip netns exec gw-b \
  /opt/strongswan-gw-b/sbin/swanctl \
  --load-all \
  --uri unix:///run/ipsec-testbed/gw-b/charon.vici
```

The connection `net` should load successfully.

---

## 7. Initiate the IPsec Tunnel

From GW-A:

```bash
sudo ip netns exec gw-a \
  /opt/strongswan-gw-a/sbin/swanctl \
  --initiate \
  --child net \
  --uri unix:///run/ipsec-testbed/gw-a/charon.vici
```

Successful output:

```text
[IKE] initiating IKE_SA net...
[IKE] IKE_SA net established
[IKE] CHILD_SA net established
```

This means:

```text
IKEv2 negotiation       ✓
PSK authentication      ✓
CHILD_SA established    ✓
IPsec tunnel ready      ✓
```

---

## 8. Verify the Tunnel

```bash
sudo ip netns exec gw-a \
  /opt/strongswan-gw-a/sbin/swanctl \
  --list-sas \
  --uri unix:///run/ipsec-testbed/gw-a/charon.vici
```

Expected:

```text
ESTABLISHED, IKEv2
INSTALLED, TUNNEL, ESP
```

with:

```text
local   10.10.1.0/24
remote  10.10.2.0/24
```

---

## 9. Test Traffic Through the IPsec Tunnel

Run:

```bash
sudo ip netns exec lan-a ping -c 5 10.10.2.10
```

Expected:

```text
5 packets transmitted, 5 received, 0% packet loss
```

Verify the IPsec counters:

```bash
sudo ip netns exec gw-a ip -s xfrm state
```

The counters should show packets and bytes being processed.

---

## Result

We successfully went from:

```text
setup_topology.sh
        ↓
Linux namespaces
        ↓
gw-a + gw-b
        ↓
strongSwan 6.0.7
        ↓
IKEv2 negotiation
        ↓
PSK authentication
        ↓
CHILD_SA establishment
        ↓
ESP/XFRM state
        ↓
LAN-A → LAN-B traffic
        ↓
5/5 ping packets successful
```

**IPsec tunnel successfully established and carrying traffic.** 🎉
