"""Asset mission profiles: the configured, operator-supplied assessment context.

A :class:`AssetMissionProfile` is four small declarations about one named testbed
asset. It carries no measurement, no timestamp and no evidence, and nothing here
can derive one from a capture.

The profile file is the prototype's stand-in for the systems a real deployment
would use instead:

* an asset inventory / CMDB,
* a security-classification or mission-impact register,
* a network-management platform,
* an operator-approved assessment profile.

The important property is not *which* of those is used, but that the value
travels into the assessment as declared input. A consumer must always be able to
tell that ``criticality: high`` was declared rather than discovered, which is why
every profile carries :data:`CONTEXT_SOURCE` and the book carries the source
file's digest.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..artifacts import REPO_ROOT
from .models import (
    CONTEXT_SOURCE,
    MISSION_CONTEXT_SCHEMA_VERSION,
    validate_criticality,
    validate_mission_impact,
    validate_role,
)

#: Repository-relative location of the shipped profile file.
MISSION_PROFILES_RELATIVE_PATH = "configs/mission/asset_mission_profiles.json"

#: Absolute default location.
DEFAULT_MISSION_PROFILES_PATH = os.path.join(REPO_ROOT, MISSION_PROFILES_RELATIVE_PATH)

#: Top-level keys the file may carry. Anything else is a typo and is rejected
#: rather than ignored, so a misspelled ``criticalty`` cannot silently disable a
#: declared context.
_ALLOWED_TOP_LEVEL = frozenset({"schema_version", "assets"})
_ALLOWED_PROFILE_KEYS = frozenset({"asset_id", "role", "criticality", "mission_impact"})


def _relative(path: str) -> str:
    """Repository-relative form of ``path``, so no host layout is disclosed."""
    try:
        relative = os.path.relpath(os.path.abspath(path), REPO_ROOT)
    except ValueError:
        return os.path.basename(path)
    return os.path.basename(path) if relative.startswith("..") else relative


@dataclass(frozen=True)
class AssetMissionProfile:
    """One asset's declared role, criticality and mission impact.

    Every field is bounded and validated. ``role`` is descriptive and never
    enters the contextualisation formula.
    """

    asset_id: str
    role: str
    criticality: str
    mission_impact: str

    def __post_init__(self) -> None:
        if not isinstance(self.asset_id, str) or not self.asset_id.strip():
            raise ValueError("asset_id must be a non-empty string")
        if (
            ".." in self.asset_id
            or os.path.isabs(self.asset_id)
            or os.sep in self.asset_id
            or "/" in self.asset_id
        ):
            raise ValueError("asset_id must be a bare name, not a path")
        validate_role(self.role)
        validate_criticality(self.criticality)
        validate_mission_impact(self.mission_impact)

    @classmethod
    def from_dict(cls, payload: Any) -> "AssetMissionProfile":
        if not isinstance(payload, dict):
            raise ValueError("an asset profile must be a JSON object")
        unknown = sorted(set(payload) - _ALLOWED_PROFILE_KEYS)
        if unknown:
            raise ValueError(
                f"unknown asset profile field(s) {unknown}; allowed: "
                f"{sorted(_ALLOWED_PROFILE_KEYS)}"
            )
        missing = sorted(_ALLOWED_PROFILE_KEYS - set(payload))
        if missing:
            raise ValueError(
                f"asset profile is missing required field(s) {missing}; mission "
                f"context is never defaulted"
            )
        return cls(
            asset_id=payload["asset_id"],
            role=payload["role"],
            criticality=payload["criticality"],
            mission_impact=payload["mission_impact"],
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "role": self.role,
            "criticality": self.criticality,
            "mission_impact": self.mission_impact,
        }


class MissionProfileBook:
    """A validated, immutable set of profiles plus the provenance of the file.

    An asset with no profile is simply absent: :meth:`get` returns ``None`` and
    the caller reports ``not_configured``. There is deliberately no default
    profile, no wildcard and no "assume medium" behaviour.
    """

    def __init__(
        self,
        profiles: Dict[str, AssetMissionProfile],
        *,
        source: str,
        source_sha256: str,
        schema_version: str = MISSION_CONTEXT_SCHEMA_VERSION,
    ) -> None:
        if not isinstance(profiles, dict):
            raise ValueError("profiles must be a dict")
        for asset_id, profile in profiles.items():
            if asset_id != profile.asset_id:
                raise ValueError(
                    f"profile key {asset_id!r} does not match its asset_id "
                    f"{profile.asset_id!r}"
                )
        if not isinstance(source, str) or not source.strip():
            raise ValueError("source must be a non-empty string")
        if not isinstance(source_sha256, str) or len(source_sha256) != 64:
            raise ValueError("source_sha256 must be a 64-character hex digest")
        self._profiles = dict(sorted(profiles.items()))
        self._source = source
        self._source_sha256 = source_sha256
        self._schema_version = schema_version

    @property
    def source(self) -> str:
        """Repository-relative path of the profile file (never absolute)."""
        return self._source

    @property
    def source_sha256(self) -> str:
        return self._source_sha256

    @property
    def schema_version(self) -> str:
        return self._schema_version

    def get(self, asset_id: Optional[str]) -> Optional[AssetMissionProfile]:
        """The profile for ``asset_id``, or ``None`` when none is declared."""
        if not asset_id or not isinstance(asset_id, str):
            return None
        return self._profiles.get(asset_id)

    def asset_ids(self) -> Tuple[str, ...]:
        """Every declared asset id, sorted, for deterministic iteration."""
        return tuple(sorted(self._profiles))

    def __len__(self) -> int:
        return len(self._profiles)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self._schema_version,
            "context_source": CONTEXT_SOURCE,
            "source": self._source,
            "source_sha256": self._source_sha256,
            "assets": [self._profiles[key].to_dict() for key in sorted(self._profiles)],
        }


def load_mission_profiles(path: Optional[str] = None) -> MissionProfileBook:
    """Read and validate the static profile file.

    Validation is total: a malformed file raises rather than yielding a
    half-populated book, because a silently-ignored profile would be a silently
    absent mission context.
    """
    resolved = os.path.abspath(path or DEFAULT_MISSION_PROFILES_PATH)
    with open(resolved, "rb") as handle:
        raw = handle.read()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{_relative(resolved)} is not valid JSON: {error}") from None
    if not isinstance(payload, dict):
        raise ValueError(f"{_relative(resolved)} must contain a JSON object")
    unknown = sorted(set(payload) - _ALLOWED_TOP_LEVEL)
    if unknown:
        raise ValueError(
            f"{_relative(resolved)} has unknown top-level field(s) {unknown}"
        )
    schema_version = payload.get("schema_version", MISSION_CONTEXT_SCHEMA_VERSION)
    if schema_version != MISSION_CONTEXT_SCHEMA_VERSION:
        raise ValueError(
            f"unsupported mission profile schema_version {schema_version!r}; "
            f"expected {MISSION_CONTEXT_SCHEMA_VERSION!r}"
        )
    assets = payload.get("assets")
    if not isinstance(assets, dict) or not assets:
        raise ValueError(
            f"{_relative(resolved)} must declare a non-empty 'assets' object"
        )
    profiles: Dict[str, AssetMissionProfile] = {}
    for asset_id in sorted(assets):
        profiles[asset_id] = AssetMissionProfile.from_dict(assets[asset_id])
    return MissionProfileBook(
        profiles,
        source=_relative(resolved),
        source_sha256=digest,
        schema_version=schema_version,
    )
