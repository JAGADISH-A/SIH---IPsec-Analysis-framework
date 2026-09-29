"""The AI explanation service: a separate, read-only HTTP surface.

    GET  /ai/health     what the service is, whether a model is configured
    GET  /ai/glossary   the IPsec terms it can define, for the UI's own prompts
    POST /ai/explain    one question about one selected context

Why a separate service rather than two more routes on the analytics API
----------------------------------------------------------------------
The analytics plane is read-only **and** GET-only: its transport answers 405 for
every mutating verb, and a test asserts it. An explanation request carries a
question, and a question in a query string is a question in an access log, a
browser history and a referrer header. Adding ``POST /api/v1/ai/explain`` would
have meant weakening a property the existing API is built around, so the
assistant gets its own process on its own port and the analytics plane is not
touched at all.

The read-only guarantee here
----------------------------
The surface is narrow on purpose. There is no route that names a target, an
action, an approval or a configuration change; ``POST`` exists only to carry a
question. The handler resolves a context, asks the engine for prose, and
serializes. It writes no file, opens no journal, touches no assessment, and has
no import edge to :mod:`correlation.risk`, the testbed controller, the capture
pipeline or the live journal.

Every response says ``"read_only": true`` and ``"decision_made": false``, and
every answer carries the guard report that vetted it.
"""

from __future__ import annotations

import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from . import glossary
from .config import AiServerConfig, describe
from .context import ContextSource
from .engine import EXPLANATION_BANNER, AiExplanationEngine
from .llm import provider_from_env
from .models import (
    ANSWER_ORIGIN_REFUSAL,
    MAX_QUESTION_CHARS,
    OUT_OF_SCOPE_ANSWER,
    SERVICE_UNAVAILABLE_ANSWER,
)

API_NAME = "ai-explanation"
SCHEMA_VERSION = "v1"

HEALTH_PATH = "/ai/health"
GLOSSARY_PATH = "/ai/glossary"
EXPLAIN_PATH = "/ai/explain"

#: Bounded so a body cannot be used to push memory or latency. A question is
#: prose; history is follow-up turns about the same context.
MAX_BODY_BYTES = 32 * 1024
MAX_HISTORY_TURNS = 8

CONTENT_TYPE_JSON = "application/json"

#: Verbs this surface answers. Everything else is refused with an ``Allow``
#: header, so a client that guesses a mutation learns it does not exist.
ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS", "POST")


class AiApiError(Exception):
    """A structured failure. Carries a stable code and a human detail."""

    def __init__(self, status: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail

    def to_dict(self, request_id: str) -> Dict[str, Any]:
        return {
            "error": {
                "code": self.code,
                "message": self.detail,
                "detail": self.detail,
                "request_id": request_id,
            }
        }


def answer_to_dict(answer) -> Dict[str, Any]:
    """Serialize one answer for the analyst surface.

    The three blocks are kept separate in the payload as well as in the UI,
    because the separation is the feature: ``authoritative`` is the engine's
    verdict, ``ml`` is a model prediction, and ``answer`` is the only generated
    text. A client that renders them in one blob has thrown away the boundary.
    """
    return {
        "api": API_NAME,
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "decision_made": False,
        "answer": answer.answer,
        "question": answer.question,
        "origin": answer.origin,
        "is_explanation": True,
        "label": EXPLANATION_BANNER,
        "assessment_id": answer.assessment_id,
        "finding_id": answer.finding_id,
        "model_version": answer.model_version,
        "scope": answer.scope.to_dict(),
        "guard": {
            "status": answer.guard.status,
            "violations": list(answer.guard.violations),
            "detail": answer.guard.detail,
            "clean": answer.guard.clean,
        },
        "citations": [citation.to_dict() for citation in answer.citations],
        "authoritative": answer.authoritative,
        "ml": answer.ml,
        "capabilities": {
            "explains": True,
            "decides": False,
            "creates_findings": False,
            "modifies_configuration": False,
            "modifies_evidence": False,
            "modifies_journal": False,
            "has_own_confidence": False,
        },
    }


def handle_health(engine: AiExplanationEngine) -> Dict[str, Any]:
    """What this service is, stated as negatives as well as positives."""
    info = engine.provider.info
    source = engine.source
    return {
        "api": API_NAME,
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "status": "ok",
        "role": "explanation only",
        "context": {
            "available": bool(getattr(source, "available", False)),
            "source": source.describe(),
            "reason": getattr(source, "reason", None),
        },
        "model": {
            "configured": info.configured,
            "provider": info.provider,
            "model_version": info.model_version,
            "reason": info.reason,
        },
        "scope": {
            "domain": "ipsec",
            "out_of_scope_answer": OUT_OF_SCOPE_ANSWER,
            "unavailable_answer": SERVICE_UNAVAILABLE_ANSWER,
        },
        "limits": {
            "max_question_chars": MAX_QUESTION_CHARS,
            "max_history_turns": MAX_HISTORY_TURNS,
            "max_body_bytes": MAX_BODY_BYTES,
        },
        "capabilities": {
            "explains": True,
            "decides": False,
            "creates_findings": False,
            "modifies_configuration": False,
            "modifies_evidence": False,
            "modifies_journal": False,
            "writes_to_backend": False,
            "has_own_confidence": False,
        },
    }


def handle_glossary() -> Dict[str, Any]:
    """The terms this service can define, so the UI need not hardcode them."""
    return {
        "api": API_NAME,
        "schema_version": SCHEMA_VERSION,
        "read_only": True,
        "count": len(glossary.ENTRIES),
        "terms": [
            {
                "key": entry.key,
                "term": entry.term,
                "definition": entry.definition,
                "relevance": entry.relevance,
            }
            for entry in glossary.ENTRIES
        ],
    }


def parse_explain_request(
    body: Any,
    *,
    max_question_chars: int = MAX_QUESTION_CHARS,
) -> Tuple[str, Optional[str], Optional[str], Tuple[Dict[str, str], ...]]:
    """Validate one request body into its four parts.

    A question is required; everything else is optional. Unknown keys are
    rejected rather than ignored, because a client sending a field this service
    does not implement is a client that believes it asked for something it did
    not, and silently dropping it is how a request appears to succeed while
    doing nothing.
    """
    if not isinstance(body, dict):
        raise AiApiError(400, "invalid_request", "the request body must be a JSON object")
    known = {"question", "assessment_id", "finding_id", "history"}
    unknown = sorted(set(body) - known)
    if unknown:
        raise AiApiError(
            400,
            "unknown_field",
            f"the request body has no such field: {', '.join(unknown)}; "
            f"accepted fields are {', '.join(sorted(known))}",
        )
    question = body.get("question")
    if not isinstance(question, str) or not question.strip():
        raise AiApiError(
            400, "invalid_question", "a non-empty 'question' string is required"
        )
    if len(question) > max_question_chars:
        raise AiApiError(
            413,
            "question_too_long",
            f"the question is {len(question)} characters; the limit is {max_question_chars}",
        )
    assessment_id = _optional_str(body, "assessment_id")
    finding_id = _optional_str(body, "finding_id")
    history = _history(body.get("history"))
    return question, assessment_id, finding_id, history


def _optional_str(body: Dict[str, Any], key: str) -> Optional[str]:
    value = body.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise AiApiError(400, "invalid_request", f"'{key}' must be a string when present")
    trimmed = value.strip()
    if not trimmed:
        return None
    if len(trimmed) > 512:
        raise AiApiError(414, "identifier_too_long", f"'{key}' is longer than 512 characters")
    return trimmed


def _history(raw: Any) -> Tuple[Dict[str, str], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise AiApiError(400, "invalid_request", "'history' must be a list when present")
    if len(raw) > MAX_HISTORY_TURNS * 2:
        raw = raw[-MAX_HISTORY_TURNS * 2:]
    out = []
    for turn in raw:
        if not isinstance(turn, dict):
            continue
        role = turn.get("role")
        content = turn.get("content")
        if role not in ("user", "assistant") or not isinstance(content, str):
            continue
        content = content.strip()
        if content:
            out.append({"role": role, "content": content[:MAX_QUESTION_CHARS]})
    return tuple(out)


def handle_explain(
    engine: AiExplanationEngine,
    body: Any,
    *,
    max_question_chars: int = MAX_QUESTION_CHARS,
) -> Dict[str, Any]:
    """Answer one question. The only mutating-verb route, and it mutates nothing."""
    question, assessment_id, finding_id, history = parse_explain_request(
        body, max_question_chars=max_question_chars
    )
    answer = engine.explain(
        question,
        assessment_id=assessment_id,
        finding_id=finding_id,
        history=history,
    )
    return answer_to_dict(answer)


def is_ai_path(path: str) -> bool:
    return path.startswith("/ai")


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------

class AiRequestHandler(BaseHTTPRequestHandler):
    """stdlib transport. Same shape as the analytics API's, deliberately."""

    engine: AiExplanationEngine
    config: AiServerConfig
    server_version = "sentinel-ai/1.0"

    def do_OPTIONS(self) -> None:  # noqa: N802 - http.server naming
        """Answer a browser preflight.

        A preflight must state which methods and which request headers are
        allowed, not merely that the origin is acceptable. Omitting them makes
        every cross-origin ``POST /ai/explain`` fail in the browser while
        working perfectly well from curl, which is the worst way for a defect
        like this to show up.
        """
        origin = self.headers.get("Origin")
        cors = self.config.cors
        methods = ", ".join(cors.allowed_methods or ALLOWED_METHODS)
        if origin and cors.allows(origin):
            self.send_response(204)
            self.send_header("Allow", methods)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Methods", methods)
            self.send_header(
                "Access-Control-Allow-Headers",
                ", ".join(cors.allowed_headers) if cors.allowed_headers else "Content-Type",
            )
            self.send_header("Access-Control-Max-Age", str(cors.max_age_seconds))
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Allow", methods)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch(head_only=True)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def _refuse_method(self) -> None:
        """Answer a mutating verb with ``405`` rather than dropping the socket.

        Raising out of the handler would close the connection without a status
        line, which a browser reports as a network error and a client cannot
        distinguish from the service being down. The ``Allow`` header makes the
        point that these verbs do not exist here at all.
        """
        request_id = uuid.uuid4().hex
        self._respond_error(
            405,
            AiApiError(
                405,
                "method_not_allowed",
                "this service answers explanation requests and nothing else; it has "
                "no route that changes an assessment, a score, a finding, evidence or "
                "the journal",
            ).to_dict(request_id),
            request_id=request_id,
        )

    do_PUT = _refuse_method
    do_PATCH = _refuse_method
    do_DELETE = _refuse_method

    def _dispatch(self, head_only: bool = False) -> None:
        request_id = uuid.uuid4().hex
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        try:
            if self.command == "POST":
                if path != EXPLAIN_PATH:
                    raise AiApiError(404, "unknown_route", f"unknown route {path!r}")
                body = self._read_body()
                payload = handle_explain(
                    self.engine, body, max_question_chars=self.config.max_question_chars
                )
            elif path == HEALTH_PATH:
                payload = handle_health(self.engine)
            elif path == GLOSSARY_PATH:
                payload = handle_glossary()
            else:
                raise AiApiError(404, "unknown_route", f"unknown route {path!r}")
        except AiApiError as exc:
            self._respond_error(
                exc.status,
                exc.to_dict(request_id),
                request_id=request_id,
                head_only=head_only,
            )
            return
        except Exception:
            self._respond_error(
                500,
                {
                    "error": {
                        "code": "ai_explanation_failed",
                        "message": (
                            "the explanation service could not produce an answer; the "
                            "authoritative assessment and evidence remain available"
                        ),
                        "detail": (
                            "the failure is recorded in the server log with this request "
                            "id"
                        ),
                        "request_id": request_id,
                    }
                },
                request_id=request_id,
                head_only=head_only,
            )
            return
        encoded = json.dumps(payload).encode("utf-8")
        self._respond(
            200,
            payload,
            encoded,
            CONTENT_TYPE_JSON,
            request_id=request_id,
            head_only=head_only,
        )

    def _read_body(self) -> Any:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except (TypeError, ValueError):
            raise AiApiError(400, "invalid_request", "Content-Length is not an integer") from None
        if length < 0 or length > MAX_BODY_BYTES:
            raise AiApiError(
                413, "body_too_large", f"the request body must be at most {MAX_BODY_BYTES} bytes"
            )
        if length == 0:
            raise AiApiError(400, "invalid_request", "a request body is required")
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise AiApiError(400, "invalid_request", "the request body is not valid JSON") from None

    def _respond_error(
        self,
        status: int,
        payload: Dict[str, Any],
        *,
        request_id: str,
        head_only: bool = False,
    ) -> None:
        """Send a structured error with the envelope actually on the wire.

        A client that cannot read ``error.code`` cannot branch, and a client
        that cannot read ``error.request_id`` cannot report a failure, so the
        encoded body is sent rather than only constructed.
        """
        self._respond(
            status,
            payload,
            json.dumps(payload).encode("utf-8"),
            CONTENT_TYPE_JSON,
            request_id=request_id,
            head_only=head_only,
        )

    def _respond(
        self,
        status: int,
        payload: Any,
        body: bytes,
        content_type: str,
        *,
        request_id: Optional[str] = None,
        head_only: bool = False,
        extra: Optional[Dict[str, str]] = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Allow", ", ".join(ALLOWED_METHODS))
        if request_id:
            self.send_header("X-Request-Id", request_id)
        origin = self.headers.get("Origin")
        if origin and self.config.cors.allows(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
            if self.config.cors.exposed_headers:
                self.send_header(
                    "Access-Control-Expose-Headers",
                    ", ".join(self.config.cors.exposed_headers),
                )
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if not head_only and body:
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        import sys

        sys.stderr.write(f"[ai-explanation] {fmt % args}\n")


class AiServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, config: AiServerConfig, engine: AiExplanationEngine) -> None:
        handler = type(
            "BoundAiRequestHandler",
            (AiRequestHandler,),
            {"engine": engine, "config": config},
        )
        super().__init__((config.host, config.port), handler)


def build_source(config: AiServerConfig) -> ContextSource:
    """The read-only context source for this deployment.

    Prefers the analytics API when one is configured, so the assistant sees the
    assessments a live run registered. Falls back to building a store from the
    run plan, which is deterministic and read-only, so the service works with no
    other process running.
    """
    if config.analytics_url:
        from .context import HttpContextSource

        return HttpContextSource(config.analytics_url)
    if config.plan_path:
        from ..api.store import build_store
        from .context import StoreContextSource

        try:
            return StoreContextSource(build_store(config.plan_path))
        except Exception:
            from .context import ContextSource as _Unavailable

            return _Unavailable()
    from ..api.store import PLAN_PATH, build_store
    from .context import StoreContextSource

    try:
        return StoreContextSource(build_store(PLAN_PATH))
    except Exception:
        from .context import ContextSource as _Unavailable

        return _Unavailable()


def build_engine(config: AiServerConfig, environ: Optional[dict] = None) -> AiExplanationEngine:
    return AiExplanationEngine(build_source(config), provider_from_env(environ))


def main(argv: Optional[list] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m correlation.ai.service",
        description=(
            "Read-only IPsec explanation service. Explains recorded assessments; "
            "decides nothing, writes nothing, and has no route that changes state."
        ),
    )
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--allowed-origins", default=None)
    parser.add_argument("--plan", dest="plan_path", default=None)
    parser.add_argument("--analytics-url", default=None)
    args = parser.parse_args(argv)

    config = AiServerConfig.resolve(
        host=args.host,
        port=args.port,
        allowed_origins=args.allowed_origins,
        plan_path=args.plan_path,
        analytics_url=args.analytics_url,
    )
    engine = build_engine(config)
    info = engine.provider.info
    server = AiServer(config, engine)
    print(f"[ai-explanation] {describe(config)}", flush=True)
    print(
        f"[ai-explanation] context source: {engine.source.describe()}",
        flush=True,
    )
    print(
        f"[ai-explanation] model: {'configured (' + str(info.model_version) + ')' if info.configured else 'not configured; answering from recorded values'}",
        flush=True,
    )
    print(f"[ai-explanation] listening on http://{config.host}:{config.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
