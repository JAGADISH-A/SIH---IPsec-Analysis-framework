"""Where validated baselines live.

The milestone's persistence instruction is explicit: the smallest thing that
could possibly work. This repository stores its data as JSON and JSONL files,
has no database and no migration tooling, so a baseline registry is a
JSONL file of append-only records plus a dict lookup.

Two properties this deliberately does not have:

* **No implicit promotion.** There is no "get me the latest baseline" shortcut
  and no auto-validation. A baseline appears in the registry only by
  :func:`register`, which requires a record that already passed
  :meth:`ValidatedBaseline.from_dict` (and therefore its integrity seal).
* **No overwrite.** ``baseline_id`` is unique. Re-registering an existing id is
  rejected rather than replacing a historical record, because a baseline that
  can be silently replaced is not a baseline.
"""

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..models.observed import ObservedState
from .baseline import BaselineIntegrityError, ValidatedBaseline

#: A registry that holds baselines in memory only. This is the default, so a
#: caller that has not opted into persistence still gets real baseline
#: semantics (uniqueness, integrity verification) without touching the disk.
IN_MEMORY_REGISTRY_NAME = ":memory:"


class BaselineRegistry:
    """Append-only collection of validated baselines, optionally file-backed."""

    def __init__(self, path: Optional[os.PathLike] = None) -> None:
        self._path = Path(path) if path is not None else None
        self._records: Dict[str, ValidatedBaseline] = {}
        if self._path is not None and self._path.exists():
            self._load()

    # -- properties ----------------------------------------------------------

    @property
    def path(self) -> Optional[Path]:
        return self._path

    @property
    def persistent(self) -> bool:
        return self._path is not None

    # -- mutation ------------------------------------------------------------

    def register(self, baseline: ValidatedBaseline) -> ValidatedBaseline:
        """Add ``baseline``; refuse to replace an existing id."""
        if not isinstance(baseline, ValidatedBaseline):
            raise TypeError(
                f"only a ValidatedBaseline can be registered, got "
                f"{type(baseline).__name__}"
            )
        # Re-verify on the way in: a record that reached the registry by any
        # other route (a hand-edited file, another process) is checked here too.
        ok, reason = baseline.verify()
        if not ok:
            raise BaselineIntegrityError(
                f"baseline {baseline.baseline_id!r} failed its integrity check: "
                f"{reason}"
            )
        if baseline.baseline_id in self._records:
            raise ValueError(
                f"baseline_id {baseline.baseline_id!r} is already registered; a "
                "validated baseline is historical and is never replaced in place"
            )
        self._records[baseline.baseline_id] = baseline
        if self._path is not None:
            self._append(baseline)
        return baseline

    def get(self, baseline_id: Optional[str]) -> Optional[ValidatedBaseline]:
        """The baseline with this id, or ``None``.

        ``None`` is the documented "not configured" result; callers decide what
        to do with it (:func:`assess_drift` reports ``not_configured``). There is
        no fallback to "some other baseline".
        """
        if baseline_id is None:
            return None
        return self._records.get(baseline_id)

    def remove(self, baseline_id: str) -> None:
        """Remove a baseline from the in-memory view.

        The registry is append-only on disk; removal here is for test isolation
        and for a caller discarding an untrusted record, and it is refused for a
        persistent registry because the file is the durable record.
        """
        if self._path is not None:
            raise ValueError(
                "a file-backed baseline registry is append-only; refusing to "
                "remove a validated baseline from persistent storage"
            )
        self._records.pop(baseline_id, None)

    # -- views ---------------------------------------------------------------

    def ids(self) -> Tuple[str, ...]:
        """Registered baseline ids, sorted, so iteration order is stable."""
        return tuple(sorted(self._records))

    def all(self) -> Tuple[ValidatedBaseline, ...]:
        return tuple(self._records[key] for key in self.ids())

    def for_asset(self, asset_id: str) -> Tuple[ValidatedBaseline, ...]:
        """Every validated baseline for one asset, sorted by id.

        An explicit asset filter, not an inference: a baseline with no
        ``asset_id`` is not returned for any asset.
        """
        return tuple(
            record for record in self.all() if record.asset_id == asset_id
        )

    def __len__(self) -> int:
        return len(self._records)

    def __contains__(self, baseline_id: object) -> bool:
        return baseline_id in self._records

    def to_dict(self) -> Dict[str, Any]:
        return {
            "persistent": self.persistent,
            "path": str(self._path) if self._path is not None else None,
            "baseline_ids": list(self.ids()),
            "baselines": [record.to_dict() for record in self.all()],
        }

    # -- persistence ---------------------------------------------------------

    def _load(self) -> None:
        assert self._path is not None
        with self._path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise BaselineIntegrityError(
                        f"{self._path}:{line_number} is not valid JSON: {exc}"
                    ) from exc
                try:
                    record = ValidatedBaseline.from_dict(payload)
                except (ValueError, BaselineIntegrityError) as exc:
                    raise BaselineIntegrityError(
                        f"{self._path}:{line_number} could not be loaded: {exc}"
                    ) from exc
                if record.baseline_id in self._records:
                    raise BaselineIntegrityError(
                        f"{self._path}:{line_number} repeats baseline_id "
                        f"{record.baseline_id!r}"
                    )
                self._records[record.baseline_id] = record

    def _append(self, baseline: ValidatedBaseline) -> None:
        assert self._path is not None
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(baseline.to_dict(), sort_keys=True) + "\n"
        # Atomic append-and-flush: a reader either sees the complete record or
        # not at all, and a crash cannot leave a half-written baseline behind a
        # valid-looking file.
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(self._path.parent),
            prefix=self._path.name + ".",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        if self._path.exists():
            existing = self._path.read_text(encoding="utf-8")
            temp_path.write_text(existing + line, encoding="utf-8")
        os.replace(temp_path, self._path)


def registry_from_dicts(payloads: Iterable[Dict[str, Any]]) -> BaselineRegistry:
    """Rebuild an in-memory registry from serialised baseline records.

    Every record goes through :meth:`ValidatedBaseline.from_dict`, so a
    tampered record raises rather than entering the comparison path.
    """
    registry = BaselineRegistry()
    for payload in payloads:
        registry.register(ValidatedBaseline.from_dict(payload))
    return registry


def registry_from_observations(
    observed_states: Iterable[ObservedState],
    **baseline_kwargs: Any,
) -> Tuple[BaselineRegistry, List[Optional[ValidatedBaseline]]]:
    """Convenience for tests and demos: validate each observation explicitly.

    Returns the registry plus, per input observation, the baseline it produced
    (or ``None`` if that observation could not be validated). This is still an
    explicit act per baseline: the caller passes the id/validator/timestamp.
    """
    from .comparison import validate_baseline

    registry = BaselineRegistry()
    produced: List[Optional[ValidatedBaseline]] = []
    for observed in observed_states:
        try:
            record = validate_baseline(observed, **baseline_kwargs)
        except (TypeError, ValueError):
            produced.append(None)
            continue
        try:
            registry.register(record)
        except ValueError:
            produced.append(None)
            continue
        produced.append(record)
    return registry, produced
