"""Environment-driven configuration for the analytics API transport.

The server is stdlib-only and has no framework settings object, so every
externally visible knob is resolved here, once, in one place.  Anything that
changes what a browser is allowed to do (origin policy, bind address) is read
from the environment so a deployment can be made explicit without editing code
and without a rebuild.

Precedence is always: explicit CLI flag > environment variable > default.

Why this exists separately from :mod:`correlation.api.app`: the app module is
transport, and transport should not be the place where security policy is
decided.  Keeping the policy in a small, dependency-free, directly testable
module means the CORS decision can be unit tested without opening a socket.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import FrozenSet, List, Optional, Tuple

#: Environment variable names.  Kept as constants so tests and the contract
#: document cannot drift from the implementation.
ENV_ALLOWED_ORIGINS = "ANALYTICS_API_ALLOWED_ORIGINS"
ENV_HOST = "ANALYTICS_API_HOST"
ENV_PORT = "ANALYTICS_API_PORT"

#: Bind address used when nothing is configured.  Loopback only: the analytics
#: API has no authentication, so binding every interface by default would
#: publish an unauthenticated read surface to the local network.
DEFAULT_HOST = "127.0.0.1"

#: Deliberately NOT 8000.  The testbed control API (``controller/api.py``) is a
#: FastAPI app conventionally started with ``uvicorn`` on 8000, and both
#: servers are expected to run side by side during development.  Sharing a
#: default port makes "start both" fail with an opaque EADDRINUSE.
DEFAULT_PORT = 8081

#: Origins permitted when ``ANALYTICS_API_ALLOWED_ORIGINS`` is unset.
#:
#: This is a *development* default and is deliberately narrow: the loopback
#: frontend served by the testbed control API (``controller/api.py`` mounts
#: ``frontend/``) plus the usual Vite dev ports.  It is NOT ``*``.
#:
#: A deployment that serves the dashboard from any other origin MUST set
#: ``ANALYTICS_API_ALLOWED_ORIGINS`` explicitly.  ``allow_all_origins`` exists
#: only so a deliberate, auditable ``*`` can be configured; it is never the
#: default because the API is unauthenticated and ``*`` would let any web page
#: read the evidence and audit surface.
DEFAULT_ALLOWED_ORIGINS: Tuple[str, ...] = (
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
)

#: Methods advertised to a CORS preflight.  Every route is read-only (see
#: ``docs/analytics/ANALYTICS_API_FRONTEND_CONTRACT.md``), so POST/PUT/DELETE
#: are advertised only so the browser receives a clear 405 rather than an
#: opaque preflight failure.
CORS_ALLOWED_METHODS: Tuple[str, ...] = ("GET", "HEAD", "OPTIONS")

CORS_ALLOWED_HEADERS: Tuple[str, ...] = (
    "Accept",
    "Accept-Encoding",
    "Authorization",
    "Content-Type",
    "X-Requested-With",
)

CORS_EXPOSED_HEADERS: Tuple[str, ...] = (
    "Content-Disposition",
    "Content-Length",
    "X-Request-Id",
)

#: Preflight cache lifetime, seconds.  Long enough to avoid a preflight per
#: request, short enough that an origin-policy change takes effect promptly.
DEFAULT_MAX_AGE_SECONDS = 600

_WILDCARD = "*"


def _split_origins(raw: Optional[str]) -> List[str]:
    """Parse a comma/whitespace separated origin list.

    Trailing slashes are stripped and the scheme+host is lowercased so that
    ``HTTP://Localhost:8000/`` and ``http://localhost:8000`` are one origin,
    which is how the browser compares them.
    """
    if not raw:
        return []
    out: List[str] = []
    for chunk in raw.replace(",", " ").split():
        candidate = chunk.strip().rstrip("/")
        if not candidate:
            continue
        out.append(candidate.lower())
    return out


def _normalize(origin: str) -> str:
    return origin.strip().rstrip("/").lower()


@dataclass(frozen=True)
class CorsPolicy:
    """Resolved CORS policy for one server instance.

    ``allow_all_origins`` is a deliberate opt-in escape hatch for a trusted
    same-site deployment.  When it is set the origin is echoed back rather than
    ``*`` being sent, because ``Access-Control-Allow-Credentials`` is never
    enabled and echoing keeps the response compatible with credentialed
    clients if that is ever added.
    """

    allowed_origins: FrozenSet[str] = field(default_factory=frozenset)
    allow_all_origins: bool = False
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS
    allowed_methods: Tuple[str, ...] = CORS_ALLOWED_METHODS
    allowed_headers: Tuple[str, ...] = CORS_ALLOWED_HEADERS
    exposed_headers: Tuple[str, ...] = CORS_EXPOSED_HEADERS

    @classmethod
    def from_env(cls, environ: Optional[dict] = None) -> "CorsPolicy":
        env = os.environ if environ is None else environ
        raw = env.get(ENV_ALLOWED_ORIGINS)
        if raw is None:
            # Unset: the development loopback default.
            origins = tuple(_normalize(o) for o in DEFAULT_ALLOWED_ORIGINS)
            return cls(allowed_origins=frozenset(origins))
        # Set, but possibly empty. An operator who explicitly configures the
        # variable gets exactly what they configured: setting it to "" locks
        # every cross-origin read off rather than silently re-opening the
        # development defaults. (Falling back to defaults here would mean a
        # cleared allow-list in a deploy manifest *widens* access.)
        tokens = _split_origins(raw)
        if any(token == _WILDCARD for token in tokens):
            return cls(allow_all_origins=True)
        return cls(allowed_origins=frozenset(tokens))

    def allows(self, origin: Optional[str]) -> bool:
        """True when a response to ``origin`` may carry CORS headers."""
        if not origin:
            return False
        if self.allow_all_origins:
            return True
        return _normalize(origin) in self.allowed_origins

    def is_configured(self) -> bool:
        """False when running on the development loopback default."""
        return self.allow_all_origins or bool(self.allowed_origins)


@dataclass(frozen=True)
class ServerConfig:
    """Everything the transport needs to start, resolved from env + flags."""

    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    cors: CorsPolicy = field(default_factory=CorsPolicy)

    @classmethod
    def resolve(
        cls,
        host: Optional[str] = None,
        port: Optional[int] = None,
        allowed_origins: Optional[str] = None,
        environ: Optional[dict] = None,
    ) -> "ServerConfig":
        """Resolve configuration.

        ``host``/``port`` are the CLI values (None when not passed).
        ``allowed_origins`` is a CLI override that wins over the environment so
        an operator can test a policy without exporting anything.
        """
        env = os.environ if environ is None else environ
        if allowed_origins is not None:
            tokens = _split_origins(allowed_origins)
            if any(token == _WILDCARD for token in tokens):
                cors = CorsPolicy(allow_all_origins=True)
            else:
                cors = CorsPolicy(allowed_origins=frozenset(tokens))
        else:
            cors = CorsPolicy.from_env(env)

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
                    raise ValueError(
                        f"{ENV_PORT}={raw_port!r} is not an integer port"
                    ) from None
        return cls(host=resolved_host, port=resolved_port, cors=cors)


def describe(config: ServerConfig) -> str:
    """One-line, operator-facing summary of the effective policy."""
    if config.cors.allow_all_origins:
        origins = "* (all origins)"
    elif config.cors.allowed_origins:
        origins = ", ".join(sorted(config.cors.allowed_origins))
    else:
        origins = "<none>"
    return f"cors allowed origins: {origins}"
