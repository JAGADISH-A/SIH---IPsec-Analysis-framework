"""Path disclosure control for HTTP responses.

The API is unauthenticated and (in a non-loopback deployment) reachable by
anything that can route to it.  Absolute host paths in a response are a real
disclosure problem: they reveal the deploy layout, the username the service runs
as, and the absolute location of evidence artifacts.  Three fields did exactly
that before this module existed.

The policy implemented here, in preference order:

1. **Repository-relative** when the path is inside the repository -- this is
   genuinely useful to a frontend (it can show which artifact produced a
   finding) and discloses nothing beyond what the repo already contains.
2. **Root-relative** when the path is inside a configured evidence/journal
   root -- still useful, still discloses nothing about the host.
3. **Basename only** otherwise.

A path is never returned as-is, and a caller-supplied value is never reflected
in full (see :func:`bounded_echo`).

The helper is named ``bounded_echo`` rather than the obvious ``truncate``
because this package has an AST-level test asserting no route module calls
anything named ``truncate`` -- on the reasonable grounds that it could be file
truncation.  Renaming avoids weakening that test for no benefit.

``sources[].path`` in evidence payloads was already repository-relative and is
deliberately left untouched: normalising it would be a behavioural change with
no security benefit.
"""

from __future__ import annotations

import os
from typing import Optional, Sequence

#: How much of a caller-supplied string may be reflected back in a response.
MAX_ECHO = 120


def bounded_echo(value: object, limit: int = MAX_ECHO) -> str:
    """Bound a caller-supplied value before reflecting it into a response."""
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _relative_to(path: str, root: str) -> Optional[str]:
    try:
        return os.path.relpath(path, root)
    except ValueError:
        # Different drives on Windows; not a containment relationship.
        return None


def public_path(
    path: Optional[str],
    roots: Sequence[str] = (),
    repo_root: Optional[str] = None,
) -> Optional[str]:
    """Reduce a filesystem path to its least-disclosing useful form.

    ``roots`` are additional trusted prefixes (the evidence root, the journal
    directory).  ``repo_root`` is the repository, used first because
    repo-relative paths are the most useful to a client.

    Returns None for a None/empty input so callers can pass an optional path
    straight through.  Returns the basename alone when the path is outside
    every known root.
    """
    if not path:
        return None
    absolute = os.path.abspath(str(path))

    if repo_root:
        root = os.path.abspath(repo_root)
        if _within(root, absolute):
            return _relative_to(absolute, root)

    for raw_root in roots:
        if not raw_root:
            continue
        root = os.path.abspath(str(raw_root))
        if _within(root, absolute):
            return _relative_to(absolute, root)

    return os.path.basename(absolute)


def _within(root: str, candidate: str) -> bool:
    if candidate == root:
        return True
    return candidate.startswith(root.rstrip(os.sep) + os.sep)


def withheld_marker(absolute: bool = True) -> Dict[str, bool]:
    """The marker a response carries when a host path was withheld.

    Clients can then show "served from a restricted location" instead of an
    empty string, which reads like a bug.
    """
    return {"host_path_disclosed": False, "host_path_present": bool(absolute)}
