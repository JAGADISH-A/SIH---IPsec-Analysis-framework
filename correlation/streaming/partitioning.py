"""Partitioning strategy (documented decision).

Primary correlation identity::

    (run_id, sequence, experiment_id, window_start_ns)

Stable partition key::

    dataset_run_id + experiment_id + attempt_number

Because the key is a function of the attempt identity (NOT the raw random
payload), the same logical flow / window travels to the same partition:

    same flow/window  ->  same partition key  ->  same partition  ->  ordered

Window fields are NOT part of the *key* (a flow spans many windows); ordering
within a partition is the transport's guarantee for the single stream.
Different attempt numbers intentionally map to different keys so repeated
experiment attempts are never merged into one out-of-order stream.
"""

import hashlib
from typing import Optional, Protocol, Union

from .models import StreamEvent

PARTITION_ALGORITHM = "sha256"

_STABLE_SEP = "|"


def partition_key(identity_or_event: Union[StreamEvent, object]) -> str:
    """Stable identity-derived partition key (no UUID / random)."""
    if isinstance(identity_or_event, StreamEvent):
        core = _core_identity(identity_or_event)
    else:
        core = _core_identity_object(identity_or_event)
    return _STABLE_SEP.join(
        str(part) if part is not None else ""
        for part in (core.dataset_run_id, core.experiment_id, core.attempt_number)
    )


def partition_for(identity_or_event: Union[StreamEvent, object], partitions: int) -> int:
    """Partition index in ``[0, partitions)`` derived from the stable key."""
    if not isinstance(partitions, int) or partitions < 1:
        raise ValueError("partitions must be a positive integer")
    digest = hashlib.sha256(partition_key(identity_or_event).encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % partitions


class _HasIdentity(Protocol):
    dataset_run_id: str
    sequence: int
    experiment_id: str
    attempt_number: int
    window_index: Optional[int]
    window_start_ns: Optional[int]
    window_end_ns: Optional[int]


def _core_identity(event: StreamEvent):
    return event


def _core_identity_object(obj: _HasIdentity):
    return obj


def partitioning_notes() -> dict:
    return {
        "algorithm": PARTITION_ALGORITHM,
        "key_fields": ("dataset_run_id", "experiment_id", "attempt_number"),
        "guarantee": (
            "same logical flow/window -> same partition -> ordered processing"
        ),
        "attempts_isolated": True,
        "window_not_in_key": True,
    }