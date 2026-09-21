"""Event producer (transport-agnostic).

``EventProducer`` wraps a ``EventTransport``. The default in-memory transport
is fully deterministic and synchronous; a real Kafka adapter (e.g. wrapping a
confluent-kafka producer) plugs in behind the same interface without changing
pipeline code. Partition assignment is delegated to ``partitioning`` so the
same logical flow/window always reaches the same partition.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol, Tuple

from .models import StreamEvent
from .partitioning import partition_for
from .schema import topic_for_event_type
from .topics import EventTopicMap


class EventTransport(Protocol):
    """Transport interface implemented by memory + Kafka adapters."""

    def send(self, topic: str, partition: int, key: str, event: StreamEvent) -> Tuple[int, int]: ...
    def flush(self) -> None: ...
    def close(self) -> None: ...
    def high_water(self) -> Dict[str, int]: ...


@dataclass
class MemoryTransport:
    """Deterministic in-memory transport (default; no network)."""

    topics: Dict[str, List[Tuple[int, str, StreamEvent]]] = field(default_factory=dict)
    next_offset: Dict[str, int] = field(default_factory=dict)

    def send(self, topic: str, partition: int, key: str, event: StreamEvent) -> Tuple[int, int]:
        offset = self.next_offset.get(topic, 0)
        self.topics.setdefault(topic, []).append((partition, key, event))
        self.next_offset[topic] = offset + 1
        return (partition, offset)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def high_water(self) -> Dict[str, int]:
        return dict(self.next_offset)

    def messages_for(self, topic: str) -> List[StreamEvent]:
        return [event for _partition, _key, event in self.topics.get(topic, [])]


@dataclass
class EventProducer:
    """Producer with partition assignment + flush."""

    transport: EventTransport = field(default_factory=MemoryTransport)
    topic_map: EventTopicMap = field(default_factory=EventTopicMap)
    partitions: int = 8

    def __post_init__(self) -> None:
        if not isinstance(self.partitions, int) or self.partitions < 1:
            raise ValueError("partitions must be a positive integer")

    def produce(self, event: StreamEvent) -> Tuple[int, int]:
        """Send an event; returns (partition, offset) as delivered."""
        topic = topic_for_event_type(event.event_type, self.topic_map.to_mapping())
        partition = partition_for(event, self.partitions)
        key = self._key_for(event)
        return self.transport.send(topic, partition, key, event)

    @staticmethod
    def _key_for(event: StreamEvent) -> str:
        return "|".join(
            (event.dataset_run_id, event.experiment_id, str(event.attempt_number))
        )

    def flush(self) -> None:
        self.transport.flush()

    def close(self) -> None:
        self.transport.close()