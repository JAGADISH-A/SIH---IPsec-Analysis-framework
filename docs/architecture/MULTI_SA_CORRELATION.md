# Multi-SA / multi-tunnel passive correlation

A gateway normally holds more than one IPsec SA. Under NAT-T all of them share
UDP/4500, so nothing in the transport tells them apart. This document describes
how the testbed separates them, and — just as importantly — when it refuses to.

Everything here is **passive**. Identity is derived from observed evidence
only. Nothing in this path configures an SA, enforces a policy, or reports back
to the network.

## The problem

The pre-existing pipeline bucketed observed events by timestamp alone:

```
100 ms window 47  →  [every ESP packet, every SA]  →  one feature vector
```

With one SA that is correct, and it is what the committed Random Forest was
trained on. With two SAs it silently produces a blended vector that describes
neither tunnel. On the real capture in
[`../verification/MULTI_SA_VERIFICATION_REPORT.md`](../verification/MULTI_SA_VERIFICATION_REPORT.md),
the blended path reported a mixture of `video` / `web` / `icmp` while the two
tunnels were actually carrying pure `icmp` and pure bulk traffic — including a
`web` class that existed only as an artifact of the blend.

## Identity: two levels, on purpose

`correlation/models/sa_identity.py` defines one immutable `SaIdentity` per
observation, with a resolution state and the evidence behind it.

| Field | Meaning |
|-------|---------|
| `sa_id` | One **child SA** — the RFC 4303 selector `(destination, protocol, SPI)`. A NAT-T SA has a different SPI per direction, so a tunnel has two. |
| `sa_group_id` | The **bidirectional SA/tunnel**. Both directions share it, so one 100 ms window contains both directions exactly as the single-SA baseline did. |
| `state` | `RESOLVED`, `AMBIGUOUS`, or `UNKNOWN`. |
| `reason` | Why it is not `RESOLVED`, in fixed vocabulary. |
| `candidates` | The competing `sa_id`s, when ambiguous. |
| `evidence_fields` | Which observed fields the decision rests on. |
| `transport_port` | Recorded, but **never** part of identity. |

Two rules matter more than the rest:

* **The SPI selects per destination.** RFC 4303 makes an SPI unique for a given
  destination, not globally. One SPI seen on two peers is therefore
  `AMBIGUOUS`, not resolved to whichever peer happened to be indexed first.
* **IKE is a context, not an SA.** IKE carries no SPI. Its strongest honest
  identity is a peer-level context, reported as `kind=IKE_CONTEXT` with
  `joins_spi=false` and reason `ike_carries_no_spi`, so a report can never
  present a negotiation as an established SA.

## The resolver

`correlation/sa_correlation.py` — two passes, both cheap and deterministic:

```python
resolver = SaResolver(capture_ip="192.168.100.1")
resolver.index(events)                     # pass 1: every observable fact
identities = resolver.identities(events)   # pass 2: one identity per event
```

The peer is derived from the observed capture point, not from address order. If
the capture point is unknown, `peer` stays `None` and the group falls back to
the whole canonical endpoint pair — still direction-agnostic, so both directions
still group together, but never guessing which side is remote.

## Where identity is used

| Stage | What changed | Default |
|-------|--------------|---------|
| `controller/ml_inference.iter_window_records` | `sa_scoped=True` buckets by `(window, sa_group_id)` | `False` — merged, byte-identical |
| `correlation/ml/live_correlation` | `sa_scoped=True` builds one `ObservedState` per SA | `False` — aggregate state |
| `ebpf/ipsec_state_builder` | New `sa_snapshots` / `sa_groups` / `outer_endpoint_pairs` / `spi_less_esp_packets` keys | All existing keys unchanged |
| `LiveFeatureWindow`, `MLResult`, `CorrelationIdentity`, `EvidenceRef` | Optional `sa_group_id` / `sa_id` / `sa_identity` | `None` — old artifacts load unchanged |

Feature math is untouched. Every SA-scoped window is produced by the same
`LiveFeatureExtractor` over the events of that one SA, so the RF receives
exactly the kind of vector it was trained on and the committed artifact is used
as-is.

## Uncertainty is preserved, not merged

Uncertain traffic gets its **own** window bucket and its **own** observed state:

| Observation | State | Group key |
|-------------|-------|-----------|
| SPI present, one peer | `RESOLVED` | `sa:esp:<peer>` |
| No SPI, exactly one SA on that peer | `RESOLVED` | `sa:esp:<peer>` |
| No SPI, several SAs on that peer | `AMBIGUOUS` | `sa-ambiguous:<candidate set>` |
| One SPI seen on two peers | `AMBIGUOUS` | `sa-ambiguous:<candidate set>` |
| SPI `0` / absent | `UNKNOWN` `no_spi_available` | `sa-unknown` |
| No outer endpoints | `UNKNOWN` `no_outer_endpoints` | `sa-unknown` |

`AMBIGUOUS` and `UNKNOWN` never join a resolved SA's bucket. They are counted,
carried and reported separately, because silently attributing them would be
worse than admitting the gap.

## Backward compatibility

Everything is additive and the single-SA path is unchanged, which the test
suite pins:

* A record with no `sa_identity` loads as `UNKNOWN`, not as an error.
* `CorrelationIdentity.to_identity_payload()` and `EvidenceRef.to_dict()` emit
  the SA keys **only when set**, so a pre-SA identity keeps its original
  content-addressed `event_id` and a pre-SA reference keeps its original
  `evidence_id`. A persisted audit chain still verifies.
* The state engine's flat `spis` list and every other legacy snapshot key are
  untouched; the SA view is an additional key.

That last point was learned the hard way. The first implementation emitted
`sa_group_id: null` unconditionally, which changed every audit payload that
contained an evidence reference and made a valid journal fail its own integrity
check. The regression is what motivated the "omit when unset" rule.

## Reading a real capture

`correlation.sa_correlation.read_pcap_events` decodes a PCAP into live events,
keeping the SPI. It exists because the general parity harness
(`controller.live_features.iter_capture_as_live_events`) deliberately zeroes the
SPI — the v2 feature vector never reads it — and a NAT-T capture is invisible
to a native-ESP-only reader. Both are correct for their own purpose.

The decoder handles both UDP/4500 framings. RFC 3948 §4.2 allows a four-byte
zero "non-ESP marker" to precede the ESP header; it is optional and peers
differ (strongSwan omits it, others emit it), so the marker is detected rather
than assumed. Getting this wrong is silent: a marker-emitting peer decodes as
SPI 0, which becomes `UNKNOWN no_spi_available`, and the whole tunnel quietly
fails to resolve instead of raising.

`scripts/multi-sa-verify.py` runs the whole path over a capture and prints the
per-SA result next to the blended one:

```
python scripts/multi-sa-verify.py \
    --pcap results/observed-state/multi-sa/multi-sa.pcap \
    --capture-ip 192.168.100.1 \
    --plan results/datasets/acc-eng-02/staging/plan.json
```

## Reproducing the scenario

```bash
scripts/multi-sa-testbed.sh up        # 3 strongSwan gateways, 2 SAs, UDP/4500
scripts/multi-sa-testbed.sh status    # both SAs, their SPIs, the shared socket
scripts/multi-sa-testbed.sh traffic   # one ICMP profile, one bulk profile
scripts/multi-sa-testbed.sh capture
scripts/multi-sa-testbed.sh down
```

## Limits

* Only one capture point. Two gateways on opposite sides of the same tunnel
  each report their own view; the two are not cross-checked.
* A group is derived from observed outer endpoints. A gateway whose peers all
  present identical outer addresses cannot be separated by observation alone
  and is reported ambiguous rather than guessed.
* Rekeying rotates SPIs, so a long capture yields more child `sa_id`s over time
  while the `sa_group_id` stays stable. Window counts are therefore not
  comparable across a rekey without grouping.
* Identity is not durable across restarts: it is rebuilt from each capture.
