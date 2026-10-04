"""Quota protection for the model call.

The Gemini key this service is configured with is a free-tier key with an
approximately 20 requests-per-minute ceiling. That number is a property of the
credential, not of this code, and it is the single constraint that decides how
the assistant has to behave under load.

Two failure modes matter, and they are different:

* A burst. One analyst double-clicks "Explain", or a browser retries, or two
  panels ask at once. Each request is an independent model call, so a burst
  spends the quota in seconds and the requests after the twentieth fail with a
  provider error the analyst sees as "AI is broken".
* Waste. The same question about the same unchanged assessment is asked again,
  and the answer is already known. Paying for it again is pure waste of a
  scarce resource.

So: an exact-match cache answers a repeat without spending anything, and a
sliding-window limiter refuses to exceed the ceiling. Both sit here, as a
provider decorator, for one reason -- the engine already knows how to answer
from recorded values when a provider fails, so a throttled request degrades into
a grounded deterministic answer instead of an error. The analyst still gets the
recorded severity and evidence; they simply do not get model prose for it, and
the response says which of the two happened.

What this deliberately does not do
----------------------------------
* It does not retry, queue or sleep. A queued burst would answer every request
  minutes later and hold sockets open; refusing immediately is honest.
* It does not raise the ceiling, and it has no "development" bypass. A limit
  that can be disabled is not a limit.
* It does not cache a refusal or an error. Only a real model answer is reused.
* It is not a security control. It paces spend; it does not authorise anyone.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .llm import LlmProvider, ProviderError, ProviderInfo

#: The free-tier ceiling this deployment is built against. Conservative on
#: purpose: the provider's real limit is not published as a number we can rely
#: on, and a burst that overshoots it costs the analyst every later question in
#: the window, not just the one that overshot.
DEFAULT_MAX_CALLS_PER_WINDOW = 18

#: Sliding window length. Sixty seconds matches the "per minute" in the quota.
DEFAULT_WINDOW_SECONDS = 60.0

#: How long a model answer stays reusable. Short by design: an assessment is
#: immutable once recorded, but a cached answer outliving the analyst's session
#: is a stale explanation presented as current, and the memory cost of keeping
#: one is trivial next to the quota.
DEFAULT_CACHE_TTL_SECONDS = 300.0

DEFAULT_CACHE_ENTRIES = 128

THROTTLED_REASON = (
    "the explanation quota for this minute is used up, so this answer was built "
    "from the recorded values instead of a model"
)


class SlidingWindowLimiter:
    """At most ``limit`` calls per ``window`` seconds, across all threads.

    A fixed window would allow a double burst across the boundary -- twenty at
    59.9s and twenty more at 60.1s -- so this keeps the timestamps of recent
    calls and drops the ones that have aged out.
    """

    def __init__(
        self,
        limit: int = DEFAULT_MAX_CALLS_PER_WINDOW,
        window: float = DEFAULT_WINDOW_SECONDS,
        *,
        clock=time.monotonic,
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window <= 0:
            raise ValueError("window must be positive")
        self._limit = limit
        self._window = float(window)
        self._clock = clock
        self._stamps: List[float] = []
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        cutoff = now - self._window
        # The list is append-ordered, so everything at the front has aged out.
        while self._stamps and self._stamps[0] <= cutoff:
            self._stamps.pop(0)

    def acquire(self) -> bool:
        """Reserve one call. ``False`` means the ceiling is already reached."""
        with self._lock:
            now = self._clock()
            self._prune(now)
            if len(self._stamps) >= self._limit:
                return False
            self._stamps.append(now)
            return True

    def remaining(self) -> int:
        with self._lock:
            self._prune(self._clock())
            return max(0, self._limit - len(self._stamps))

    @property
    def limit(self) -> int:
        return self._limit


class AnswerCache:
    """Exact-match memo of model answers, keyed by the whole request shape.

    The key covers the question, the selected assessment/finding/job and the
    conversation history, because two of those changing can legitimately change
    the answer. Anything not in the key is not in the answer either: the model
    only ever saw the messages this request produced, and those are fully
    determined by these fields.
    """

    def __init__(
        self,
        ttl: float = DEFAULT_CACHE_TTL_SECONDS,
        max_entries: int = DEFAULT_CACHE_ENTRIES,
        *,
        clock=time.monotonic,
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be at least 1")
        self._ttl = float(ttl)
        self._max = max_entries
        self._clock = clock
        self._entries: "Dict[str, Tuple[float, str]]" = {}
        self._lock = threading.Lock()

    @staticmethod
    def key_for(
        question: str,
        *,
        assessment_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        experiment_id: Optional[str] = None,
        history: Sequence[Dict[str, str]] = (),
    ) -> str:
        payload = json.dumps(
            {
                "question": str(question or "").strip(),
                "assessment_id": assessment_id,
                "finding_id": finding_id,
                "experiment_id": experiment_id,
                "history": [
                    [str(turn.get("role") or ""), str(turn.get("content") or "")]
                    for turn in history
                    if isinstance(turn, dict)
                ],
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[str]:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            stored_at, text = entry
            if self._clock() - stored_at > self._ttl:
                # Expired. Dropping it here rather than at write time keeps the
                # read path honest about what is still reusable.
                del self._entries[key]
                return None
            return text

    def put(self, key: str, text: str) -> None:
        with self._lock:
            if len(self._entries) >= self._max:
                self._evict_locked()
            self._entries[key] = (self._clock(), text)

    def _evict_locked(self) -> None:
        now = self._clock()
        stale = [k for k, (at, _) in self._entries.items() if now - at > self._ttl]
        for key in stale:
            del self._entries[key]
        if len(self._entries) < self._max:
            return
        # Still full: drop the oldest insertions. Dict order is insertion order.
        for key in list(self._entries)[: max(1, self._max // 4)]:
            del self._entries[key]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class BudgetedProvider(LlmProvider):
    """Wraps a provider so a scarce quota is spent once, not once per click.

    On a hit, no call is made and no quota is spent -- the analyst gets model
    prose. On a refusal, the wrapper raises :class:`ProviderError`, which the
    engine already handles by building its deterministic answer from recorded
    values. That is the whole fallback contract: throttling degrades the answer's
    prose, never its grounding.
    """

    def __init__(
        self,
        inner: LlmProvider,
        *,
        limiter: Optional[SlidingWindowLimiter] = None,
        cache: Optional[AnswerCache] = None,
        request_key: Optional[str] = None,
    ) -> None:
        self._inner = inner
        self._limiter = limiter if limiter is not None else SlidingWindowLimiter()
        self._cache = cache if cache is not None else AnswerCache()
        #: Optional explicit cache key. When absent, the key is derived from the
        #: messages, which is the honest thing to key on: it is exactly what the
        #: model was shown.
        self._request_key = request_key
        self.served_from_cache = 0
        self.throttled = 0

    @property
    def info(self) -> ProviderInfo:
        info = self._inner.info
        detail = dict(info.detail)
        detail.update(
            {
                "quota_limit_per_window": self._limiter.limit,
                "quota_remaining": self._limiter.remaining(),
                "cached_answers": len(self._cache),
                "served_from_cache": self.served_from_cache,
                "throttled": self.throttled,
            }
        )
        return ProviderInfo(
            configured=info.configured,
            provider=info.provider,
            model_version=info.model_version,
            reason=info.reason,
            base_url=info.base_url,
            detail=detail,
        )

    def build_messages(self, question, context, scope, *, history=()) -> List[Dict[str, str]]:
        return self._inner.build_messages(question, context, scope, history=history)

    def complete(self, messages: Sequence[Dict[str, str]]) -> str:
        key = _key_for_call(messages, self._request_key)
        cached = self._cache.get(key)
        if cached is not None:
            self.served_from_cache += 1
            return cached
        if not self._limiter.acquire():
            self.throttled += 1
            raise ProviderError(THROTTLED_REASON)
        text = self._inner.complete(messages)
        self._cache.put(key, text)
        return text


class _MessageKey:
    """Derives the cache key from the messages actually sent to the model.

    Falls back to the full message list when the caller set no explicit key, so
    a repeated identical request hits and a request whose context changed does
    not.
    """

    @staticmethod
    def resolve(messages: Sequence[Dict[str, str]]) -> str:
        payload = json.dumps(list(messages), sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _key_for_call(
    messages: Sequence[Dict[str, str]],
    override: Optional[str],
) -> str:
    if isinstance(override, str) and override:
        return override
    return _MessageKey.resolve(messages)


# ---------------------------------------------------------------------------
# wiring
# ---------------------------------------------------------------------------

ENV_MAX_CALLS = "AI_MAX_CALLS_PER_WINDOW"
ENV_WINDOW_SECONDS = "AI_QUOTA_WINDOW_S"
ENV_CACHE_TTL = "AI_CACHE_TTL_S"
ENV_DISABLE_CACHE = "AI_CACHE_DISABLED"


def budgeted_provider_from_env(environ: Optional[dict] = None) -> LlmProvider:
    """The provider the environment names, wrapped in its quota.

    ``llm.provider_from_env`` delegates here. ``NullProvider`` is returned
    unwrapped, because a provider that cannot call a model has nothing to pace.
    """
    from .llm import NullProvider, _provider_from_env_uncapped

    env = os.environ if environ is None else environ
    provider = _provider_from_env_uncapped(env)
    if isinstance(provider, NullProvider) or isinstance(provider, BudgetedProvider):
        return provider
    return BudgetedProvider(provider, **_quota_from_env(env))


def _quota_from_env(env) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "limiter": SlidingWindowLimiter(
            _int_env(env, ENV_MAX_CALLS, DEFAULT_MAX_CALLS_PER_WINDOW),
            _float_env(env, ENV_WINDOW_SECONDS, DEFAULT_WINDOW_SECONDS),
        ),
    }
    if _bool_env(env, ENV_DISABLE_CACHE):
        # A very short TTL rather than no cache: the key still collapses a
        # genuine double-submit, which is the burst this actually needs to stop.
        kwargs["cache"] = AnswerCache(ttl=1.0)
    else:
        kwargs["cache"] = AnswerCache(
            _float_env(env, ENV_CACHE_TTL, DEFAULT_CACHE_TTL_SECONDS)
        )
    return kwargs


def _int_env(env, key: str, default: int) -> int:
    raw = (env.get(key) or "").strip() if hasattr(env, "get") else ""
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value >= 1 else default


def _float_env(env, key: str, default: float) -> float:
    raw = (env.get(key) or "").strip() if hasattr(env, "get") else ""
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _bool_env(env, key: str) -> bool:
    raw = (env.get(key) or "").strip().lower() if hasattr(env, "get") else ""
    return raw in ("1", "true", "yes", "on")