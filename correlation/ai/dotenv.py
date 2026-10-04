"""Load backend configuration from a ``.env`` file.

Why this exists
---------------
``GEMINI_API_KEY`` is a secret, so it does not belong in a shell history, in a
unit file, in ``.example.env``, or in anything committed. The usual place for a
local secret is a gitignored ``.env`` file next to the code. The AI service
reads its configuration from the process environment, so something has to read
that file; doing it here keeps the secret out of the start command line.

Rules, in order
---------------
1. A variable already present in the real environment wins. An operator who
   exports ``GEMINI_MODEL`` to override a stale file must not be overruled by
   the file.
2. Only the keys this service owns are considered, so an unrelated ``.env``
   cannot quietly reconfigure the analytics plane or the controller.
3. The file is never written, never echoed and never logged. Only the *names*
   of the keys that were applied are returned, and the caller logs nothing
   about a value.

The format is the ordinary ``KEY=value`` one, with optional ``export``, optional
blank lines, ``#`` comments, and single or double quoted values.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterable, List, Optional

#: The only variables the AI service will take from a ``.env`` file. Deliberately
#: a closed list rather than a prefix match: a prefix match would let the file
#: set anything that starts with ``GEMINI_`` and this module's whole value is
#: that it sets only what it was asked to.
AI_ENV_KEYS: tuple = (
    "GEMINI_API_KEY",
    "GEMINI_MODEL",
    "GEMINI_TIMEOUT_S",
    "GEMINI_MAX_TOKENS",
    "ANALYTICS_AI_HOST",
    "ANALYTICS_AI_PORT",
    "ANALYTICS_AI_ALLOWED_ORIGINS",
    "ANALYTICS_AI_MAX_QUESTION_CHARS",
    "ANALYTICS_API_URL",
    "SIH_PLAN_PATH",
)

#: Where the file is looked for, in order, relative to the repository root.
DEFAULT_ENV_FILENAMES: tuple = (".env",)


def parse_env_file(text: str) -> Dict[str, str]:
    """Parse ``KEY=value`` lines into a mapping.

    Later assignments win, matching how a shell re-sourcing a file behaves, and
    a malformed line is skipped rather than raised: a typo in an unrelated part
    of a shared ``.env`` must not stop the service from starting.
    """
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


def find_env_file(
    root: Optional[Path] = None,
    names: Iterable[str] = DEFAULT_ENV_FILENAMES,
) -> Optional[Path]:
    """Return the first ``.env`` that exists, searching up from ``start``."""
    here = Path(root).resolve() if root else Path(__file__).resolve()
    for directory in [here, *here.parents]:
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load_backend_env(
    root: Optional[Path] = None,
    environ: Optional[Dict[str, str]] = None,
    keys: Iterable[str] = AI_ENV_KEYS,
) -> List[str]:
    """Apply a ``.env`` file to ``environ``; return the key names applied.

    Existing values are left untouched, so this is safe to call on every
    startup and safe to call in tests.
    """
    env = os.environ if environ is None else environ
    path = find_env_file(root)
    if path is None:
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    allowed = set(keys)
    applied: List[str] = []
    for key, value in parse_env_file(text).items():
        if key not in allowed:
            continue
        # An empty value means "not configured". Applying it would overwrite a
        # real key from the environment with nothing.
        if not value:
            continue
        if key in env and env[key]:
            continue
        env[key] = value
        applied.append(key)
    return applied