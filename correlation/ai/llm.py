"""The model provider seam.

The assistant is useful with no model configured: the engine answers from a
deterministic template built out of recorded values. This module exists so that
a deployment can add natural-language prose without the engine, the guard, the
context builder or the service changing at all.

There is deliberately no ``openai`` or ``anthropic`` import. The repository
declares no LLM dependency and the analytics plane is stdlib-only, so the client
speaks the OpenAI-compatible chat-completions wire format over ``urllib``. Any
provider that serves that shape -- a hosted API, a local gateway, Ollama, vLLM
-- works by pointing the base URL at it.

What a provider may not do
--------------------------
* Return a value it did not generate. A provider returns text; the guard decides
  whether that text may be shown.
* See anything the context builder did not put in the message list. The provider
  receives exactly :func:`correlation.ai.prompt.build_messages` output.
* Retry indefinitely or hide a failure. A provider error becomes a grounded
  template answer, and the response says which one it is.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

ENV_BASE_URL = "ANALYTICS_AI_BASE_URL"
ENV_API_KEY = "ANALYTICS_AI_API_KEY"
ENV_MODEL = "ANALYTICS_AI_MODEL"
ENV_TIMEOUT = "ANALYTICS_AI_TIMEOUT_S"
ENV_MAX_TOKENS = "ANALYTICS_AI_MAX_TOKENS"

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_TOKENS = 700
DEFAULT_TEMPERATURE = 0.0


class ProviderError(RuntimeError):
    """The provider could not produce an answer. Never a substitute for one."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class ProviderInfo:
    """What the service reports about its model, and nothing more."""

    configured: bool
    provider: str
    model_version: Optional[str] = None
    reason: Optional[str] = None
    base_url: Optional[str] = None
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "configured": self.configured,
            "provider": self.provider,
            "model_version": self.model_version,
            "reason": self.reason,
            "base_url": self.base_url,
            "detail": dict(self.detail),
        }


class LlmProvider:
    """The provider contract. ``complete`` returns text or raises."""

    @property
    def info(self) -> ProviderInfo:
        raise NotImplementedError

    def complete(self, messages: Sequence[Dict[str, str]]) -> str:
        raise NotImplementedError


class NullProvider(LlmProvider):
    """No model configured.

    The engine treats this as the normal case rather than an error, and answers
    from its deterministic template. ``reason`` is what the UI shows so the
    absence of a model is visible instead of silently looking like a model
    answered.
    """

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            configured=False,
            provider="none",
            model_version=None,
            reason=(
                "no language model is configured; explanations are rendered from "
                "recorded values by the deterministic template, which is why this "
                "response carries no model version"
            ),
            base_url=None,
        )

    def complete(self, messages: Sequence[Dict[str, str]]) -> str:
        raise ProviderError(self.info.reason or "no language model is configured")


class OpenAiCompatProvider(LlmProvider):
    """A chat-completions client over ``urllib``.

    The API key is read once at construction and never logged, echoed in a
    response, or placed in an error message. :meth:`info` reports the base URL
    with any userinfo stripped, because a base URL can carry a credential in the
    ``user:password@host`` form.
    """

    def __init__(
        self,
        base_url: str,
        *,
        model: str,
        api_key: Optional[str] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        transport=None,
    ) -> None:
        self._base = str(base_url or "").rstrip("/")
        self._model = str(model or "").strip()
        self._api_key = api_key or None
        self._timeout = float(timeout)
        self._max_tokens = int(max_tokens)
        self._transport = transport or _post_json

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(
            configured=bool(self._base and self._model),
            provider="openai-compatible",
            model_version=self._model or None,
            reason=None if (self._base and self._model) else (
                "a base URL and a model name are both required"
            ),
            base_url=_redact_userinfo(self._base) or None,
            detail={
                "max_tokens": self._max_tokens,
                "timeout_seconds": self._timeout,
                "temperature": DEFAULT_TEMPERATURE,
                "authenticated": self._api_key is not None,
            },
        )

    def complete(self, messages: Sequence[Dict[str, str]]) -> str:
        payload: Dict[str, Any] = {
            "model": self._model,
            "messages": list(messages),
            "temperature": DEFAULT_TEMPERATURE,
            "max_tokens": self._max_tokens,
        }
        try:
            body = self._transport(
                f"{self._base}/chat/completions",
                payload,
                self._api_key,
                self._timeout,
            )
        except ProviderError:
            raise
        except Exception as exc:
            raise ProviderError(
                f"the model endpoint could not be reached ({type(exc).__name__})"
            ) from None
        return _extract_message(body)


def _post_json(
    url: str,
    payload: Dict[str, Any],
    api_key: Optional[str],
    timeout: float,
) -> Dict[str, Any]:
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen

    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - operator-configured URL
            raw = response.read()
    except HTTPError as exc:
        raise ProviderError(f"the model endpoint returned HTTP {exc.code}") from None
    except (URLError, OSError) as exc:
        raise ProviderError(
            f"the model endpoint is unreachable ({type(exc).__name__})"
        ) from None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProviderError("the model endpoint returned a non-JSON body") from None
    if not isinstance(parsed, dict):
        raise ProviderError("the model endpoint returned an unexpected body shape")
    return parsed


def _extract_message(body: Dict[str, Any]) -> str:
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("the model endpoint returned no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError("the model endpoint returned a malformed choice")
    message = first.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, list):
        parts = [
            str(part.get("text") or "")
            for part in content
            if isinstance(part, dict)
        ]
        content = "".join(parts)
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("the model endpoint returned an empty message")
    return content.strip()


def _redact_userinfo(base_url: str) -> str:
    if "@" not in base_url:
        return base_url
    scheme, _, rest = base_url.partition("://")
    if not rest:
        return base_url
    _, _, host = rest.rpartition("@")
    return f"{scheme}://{host}" if scheme else host


def provider_from_env(environ: Optional[dict] = None) -> LlmProvider:
    """Resolve a provider from the environment. Precedence: env, then default.

    No configuration means :class:`NullProvider`, which is a working
    configuration: the assistant explains from recorded values without a model.
    """
    env = os.environ if environ is None else environ
    base_url = (env.get(ENV_BASE_URL) or "").strip()
    model = (env.get(ENV_MODEL) or "").strip()
    if not base_url or not model:
        return NullProvider()
    try:
        timeout = float(env.get(ENV_TIMEOUT) or DEFAULT_TIMEOUT_SECONDS)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT_SECONDS
    try:
        max_tokens = int(env.get(ENV_MAX_TOKENS) or DEFAULT_MAX_TOKENS)
    except (TypeError, ValueError):
        max_tokens = DEFAULT_MAX_TOKENS
    return OpenAiCompatProvider(
        base_url,
        model=model,
        api_key=(env.get(ENV_API_KEY) or "").strip() or None,
        timeout=timeout,
        max_tokens=max_tokens,
    )


def history_from_turns(turns: Sequence[Dict[str, str]]) -> Tuple[Dict[str, str], ...]:
    """Normalize prior turns, dropping anything that is not a question or answer.

    Bounds are applied by the caller; this only sanitizes. Anything a client can
    put in a turn is untrusted, so a "turn" claiming to be a system message is
    dropped rather than honoured.
    """
    out: List[Dict[str, str]] = []
    for turn in turns or ():
        if not isinstance(turn, dict):
            continue
        role = str(turn.get("role") or "").strip().lower()
        content = str(turn.get("content") or "").strip()
        if role in ("user", "assistant") and content:
            out.append({"role": role, "content": content})
    return tuple(out)
