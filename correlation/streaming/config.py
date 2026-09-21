"""Streaming configuration (Kafka/consumer/window) from environment.

Every value has a safe default and can be overridden by an environment
variable (SIH_STREAM_*). No secrets are ever stored here; authentication is
delegated to the hosting platform (deployed via .example.env, never committed).
"""

import os
from dataclasses import dataclass, field
from typing import Optional

from .topics import EventTopicMap


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return int(raw)


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name)
    return default if raw is None or raw == "" else raw


@dataclass(frozen=True)
class StreamingConfig:
    """Centralized streaming configuration (safe defaults)."""

    bootstrap_servers: str = "127.0.0.1:9092"
    consumer_group: str = "sih-colayer"
    auto_offset_reset: str = "latest"
    max_poll_interval_ms: int = 300_000
    enable_idempotence: bool = True
    partitions_per_topic: int = 8
    window_ms: int = 100
    window_lookback: int = 2
    emit_every_windows: int = 1
    flush_on_shutdown: bool = True
    flush_on_experiment_completion: bool = True
    max_queue: int = 10_000
    overflow_policy: str = "BLOCK"
    dedup_size: int = 10_000
    retry_max: int = 3
    retry_base_delay_ns: int = 100_000_000
    retry_max_delay_ns: int = 4_000_000_000
    dlq_max: int = 10_000
    topic_prefix: str = ""
    transport: str = "memory"
    kafka_enabled: bool = False

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "StreamingConfig":
        source = dict(os.environ if env is None else env)
        get = source.get
        return cls(
            bootstrap_servers=get("SIH_STREAM_BOOTSTRAP_SERVERS", "127.0.0.1:9092"),
            consumer_group=get("SIH_STREAM_CONSUMER_GROUP", "sih-colayer"),
            auto_offset_reset=get("SIH_STREAM_AUTO_OFFSET_RESET", "latest"),
            max_poll_interval_ms=_env_int("SIH_STREAM_MAX_POLL_INTERVAL_MS", 300_000),
            enable_idempotence=cls._bool(get("SIH_STREAM_ENABLE_IDEMPOTENCE", "true")),
            partitions_per_topic=cls._int(get("SIH_STREAM_PARTITIONS_PER_TOPIC", "8")),
            window_ms=cls._int(get("SIH_STREAM_WINDOW_MS", "100")),
            window_lookback=cls._int(get("SIH_STREAM_WINDOW_LOOKBACK", "2")),
            emit_every_windows=cls._int(get("SIH_STREAM_EMIT_EVERY_WINDOWS", "1")),
            flush_on_shutdown=cls._bool(get("SIH_STREAM_FLUSH_ON_SHUTDOWN", "true")),
            flush_on_experiment_completion=cls._bool(
                get("SIH_STREAM_FLUSH_ON_EXPERIMENT_COMPLETION", "true")
            ),
            max_queue=cls._int(get("SIH_STREAM_MAX_QUEUE", "10000")),
            overflow_policy=get("SIH_STREAM_OVERFLOW_POLICY", "BLOCK"),
            dedup_size=cls._int(get("SIH_STREAM_DEDUP_SIZE", "10000")),
            retry_max=cls._int(get("SIH_STREAM_RETRY_MAX", "3")),
            retry_base_delay_ns=cls._int(get("SIH_STREAM_RETRY_BASE_DELAY_NS", "100000000")),
            retry_max_delay_ns=cls._int(get("SIH_STREAM_RETRY_MAX_DELAY_NS", "4000000000")),
            dlq_max=cls._int(get("SIH_STREAM_DLQ_MAX", "10000")),
            topic_prefix=get("SIH_STREAM_TOPIC_PREFIX", ""),
            transport=get("SIH_STREAM_TRANSPORT", "memory"),
            kafka_enabled=cls._bool(get("SIH_STREAM_KAFKA_ENABLED", "false")),
        )

    @staticmethod
    def _int(raw: str) -> int:
        try:
            return int(raw)
        except (TypeError, ValueError):
            return 8

    @staticmethod
    def _bool(raw: str) -> bool:
        if raw is None or raw == "":
            return False
        return raw.strip().lower() in ("1", "true", "yes", "on")

    def topic_map(self) -> EventTopicMap:
        return EventTopicMap.with_prefix(self.topic_prefix)

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)