"""CORS header computation and preflight handling.

Separated from :mod:`correlation.api.app` so the policy can be tested without
opening a socket: the transport decides *when* to call these, these decide
*what headers* are correct.

Two rules that are easy to get wrong and are therefore encoded here:

* **Never send CORS headers for a disallowed origin.**  A response that omits
  ``Access-Control-Allow-Origin`` is what makes the browser block the read.
  Sending the origin anyway (or sending ``*`` unconditionally) would defeat the
  allow-list.  An unrecognised origin simply gets no CORS headers and the
  browser refuses it, which is the intended outcome, not an error to paper over.
* **A preflight must never 501.**  ``http.server`` has no default
  ``do_OPTIONS``, so before this existed a browser preflight fell through to the
  stdlib's "Unsupported method" HTML response.  That is indistinguishable from a
  broken server in devtools, so ``OPTIONS`` is answered explicitly for every
  path.
"""

from __future__ import annotations

from typing import Dict, Iterable, Optional

from .config import CorsPolicy

#: Response for a preflight.  204 is what browsers expect; the body is empty.
PREFLIGHT_STATUS = 204

#: Status for a preflight from an origin that is not allowed.  403 rather than
#: 204-without-headers so the rejection is visible in server logs and in a
#: ``curl`` reproduction, while still omitting the CORS headers the browser
#: needs (so the browser blocks the real request).
PREFLIGHT_DENIED_STATUS = 403

#: Status for a preflight to a path that is not an API path at all.
PREFLIGHT_UNKNOWN_STATUS = 404

REQUEST_ID_HEADER = "X-Request-Id"


def _join(values: Iterable[str]) -> str:
    return ", ".join(values)


def apply_cors_headers(
    headers: Dict[str, str],
    policy: CorsPolicy,
    origin: Optional[str],
) -> bool:
    """Add CORS response headers to ``headers`` in place.

    Returns True when the origin is allowed (and therefore headers were set),
    False when it is not.  On False the caller still sends a normal response --
    it just carries no CORS headers, so the browser blocks the read.
    """
    if not policy.allows(origin):
        return False
    assert origin is not None  # guaranteed by policy.allows
    headers["Access-Control-Allow-Origin"] = origin.strip()
    headers["Access-Control-Expose-Headers"] = _join(policy.exposed_headers)
    # The response body varies by Origin, so caches must key on it.  Without
    # this a shared cache could serve one origin's allow-header to another.
    headers["Vary"] = "Origin"
    return True


def preflight_headers(
    policy: CorsPolicy,
    origin: Optional[str],
    request_headers: Optional[str] = None,
) -> Dict[str, str]:
    """Headers for a successful preflight (``Access-Control-Allow-*``)."""
    headers: Dict[str, str] = {}
    apply_cors_headers(headers, policy, origin)
    headers["Access-Control-Allow-Methods"] = _join(policy.allowed_methods)
    allowed = list(policy.allowed_headers)
    requested = (request_headers or "").strip()
    if requested:
        # Echo the requested headers when they are all permitted, so a client
        # asking for an extra harmless header is not rejected.  Anything not in
        # the allow-list is dropped rather than echoed.
        for name in (part.strip() for part in requested.split(",")):
            if not name:
                continue
            if name.lower() in {h.lower() for h in policy.allowed_headers}:
                allowed.append(name)
    headers["Access-Control-Allow-Headers"] = _join(dict.fromkeys(allowed))
    headers["Access-Control-Max-Age"] = str(policy.max_age_seconds)
    headers["Cache-Control"] = "no-store"
    headers["Content-Length"] = "0"
    return headers


def summarize_cors(policy: CorsPolicy) -> Dict[str, object]:
    """Machine-readable description of the effective policy.

    Served on the health endpoint so a frontend (or an operator) can discover
    the policy instead of guessing at it from a failed request.  Contains only
    origins the client already knows -- no host paths.
    """
    return {
        "allowed_origins": (
            ["*"] if policy.allow_all_origins else sorted(policy.allowed_origins)
        ),
        "allow_credentials": False,
        "allowed_methods": list(policy.allowed_methods),
        "allowed_headers": list(policy.allowed_headers),
        "exposed_headers": list(policy.exposed_headers),
        "max_age_seconds": policy.max_age_seconds,
        "configured": policy.is_configured(),
    }
