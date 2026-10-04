"""Environment-driven configuration for the AI explanation service.

Separate from :mod:`correlation.api.config` on purpose. The analytics plane and
the AI plane are different services with different risk: the analytics plane
serves the assessment, the AI plane reads it. Sharing one config module would
invite a later change to widen the assistant's reach along with the API's, and
these two are not allowed to move together.

Precedence is always: explicit CLI flag > environment variable > default.

Defaults worth stating plainly
------------------------------
* The bind address is loopback only. The service has no authentication, so
  binding every interface would publish an unauthenticated read of the
  assessment to the local network.
* The port is 8082, which is neither the analytics plane's 8081 nor the
  controller's 8000, so "start everything" does not collide.
* The default origins match the analytics plane's development defaults, because
  the analyst surface that calls this is the same one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import FrozenSet, Optional, Tuple

from .llm import (
    ENV_API_KEY,
    ENV_BASE_URL,
    ENV_MAX_TOKENS,
    ENV_MODEL,
    ENV_TIMEOUT,
)

ENV_ALLOWED_ORIGINS = "ANALYTICS_AI_ALLOWED_ORIGINS"
ENV_HOST = "ANALYTICS_AI_HOST"
ENV_PORT = "ANALYTICS_AI_PORT"
ENV_MAX_QUESTION_CHARS = "ANALYTICS_AI_MAX_QUESTION_CHARS"

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8082
DEFAULT_MAX_QUESTION_CHARS = 500

DEFAULT_ALLOWED_ORIGINS: Tuple[str, ...] = (
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)

CORS_ALLOWED_METHODS: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS", "POST")
CORS_ALLOWED_HEADERS: Tuple[str, ...] = ("Accept", "Content-Type")
CORS_EXPOSED_HEADERS: Tuple[str, ...] = ("Content-Length", "X-Request-Id")
DEFAULT_MAX_AGE_SECONDS = 600

_WILDCARD = "*"


def _normalize(origin: str) -> str:
    return origin.strip().rstrip("/").lower()


def _split_origins(raw: Optional[str]) -> Tuple[str, ...]:
    if not raw:
        return ()
    out = []
    for chunk in raw.replace(",", " ").split():
        candidate = chunk.strip().rstrip("/")
        if candidate:
            out.append(candidate.lower())
    return tuple(out)


@dataclass(frozen=True)
class AiCorsPolicy:
    """Resolved origin policy for the AI service.

    Setting the environment variable to the empty string locks cross-origin
    reads off entirely rather than falling back to the development defaults,
    because a cleared allow-list in a deploy manifest must never widen access.
    """

    allowed_origins: FrozenSet[str] = field(default_factory=frozenset)
    allow_all_origins: bool = False
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    allowed_methods: Tuple[str, ...] = CORS_ALLOWED_METHODS
    allowed_headers: Tuple[str, ...] = CORS_ALLOWED_HEADERS
    exposed_headers: Tuple[str, ...] = CORS_EXPOSED_HEADERS

    @classmethod
    def from_env(cls, environ: Optional[dict] = None) -> "AiCorsPolicy":
        env = os.environ if environ is None else environ
        raw = env.get(ENV_ALLOWED_ORIGINS)
        if raw is None:
            return cls(allowed_origins=frozenset(_normalize(o) for o in DEFAULT_ALLOWED_ORIGINS))
        tokens = _split_origins(raw)
        if any(token == _WILDCARD for token in tokens):
            return cls(allow_all_origins=True)
        return cls(allowed_origins=frozenset(tokens))

    def allows(self, origin: Optional[str]) -> bool:
        if not origin:
            return False
        if self.allow_all_origins:
            return True
        return _normalize(origin) in self.allowed_origins


@dataclass(frozen=True)
class AiServerConfig:
    """Everything the AI service needs to start, resolved from env plus flags."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    cors: AiCorsPolicy = field(default_factory=AiCorsPolicy)
    max_question_chars: int = DEFAULT_MAX_QUESTION_CHARS
    plan_path: Optional[str] = None
    analytics_url: Optional[str] = None
    #: Optional control-plane base URL. Only ever used for one read-only GET of
    #: an experiment job's recorded verdict, so that "why did this fail?" can be
    #: answered from what the controller decided. Unset means root cause is not
    #: available to the assistant and it must say so.
    control_url: Optional[str] = None

    @classmethod
    def resolve(
        cls,
        host: Optional[str] = None,
        port: Optional[int] = None,
        allowed_origins: Optional[str] = None,
        plan_path: Optional[str] = None,
        analytics_url: Optional[str] = None,
        control_url: Optional[str] = None,
        environ: Optional[dict] = None,
    ) -> "AiServerConfig":
        env = os.environ if environ is None else environ
        if allowed_origins is not None:
            tokens = _split_origins(allowed_origins)
            if any(token == _WILDCARD for token in tokens):
                cors = AiCorsPolicy(allow_all_origins=True)
            else:
                cors = AiCorsPolicy(allowed_origins=frozenset(tokens))
        else:
            cors = AiCorsPolicy.from_env(env)

        resolved_host = host or env.get(ENV_HOST) or DEFAULT_HOST
        if port is not None:
            resolved_port = port
        else:
            raw_port = env.get(ENV_PORT)
            resolved_port = DEFAULT_PORT
            if raw_port:
                try:
                    resolved_port = int(raw_port)
                except ValueError:
                    raise ValueError(f"{ENV_PORT}={raw_port!r} is not an integer port") from None

        raw_limit = env.get(ENV_MAX_QUESTION_CHARS)
        limit = DEFAULT_MAX_QUESTION_CHARS
        if raw_limit:
            try:
                limit = int(raw_limit)
            except ValueError:
                raise ValueError(
                    f"{ENV_MAX_QUESTION_CHARS}={raw_limit!r} is not an integer"
                ) from None
        return cls(
            host=resolved_host,
            port=resolved_port,
            cors=cors,
            max_question_chars=limit,
            plan_path=plan_path or env.get("ANALYTICS_API_PLAN"),
            analytics_url=analytics_url or env.get("ANALYTICS_API_URL"),
            control_url=control_url or env.get("CONTROL_API_URL"),
        )


def describe(config: AiServerConfig) -> str:
    origins = "* (all origins)" if config.cors.allow_all_origins else (
        ", ".join(sorted(config.cors.allowed_origins)) or "<none>"
    )
    return f"cors allowed origins: {origins}; max question chars: {config.max_question_chars}"
