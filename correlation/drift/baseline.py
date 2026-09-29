"""The validated baseline: an explicitly established historical state.

The distinction this model exists to enforce is between

    "a state somebody declared valid at a known time"

and

    "the most recent thing the sensor happened to see".

Only the first is a baseline. A baseline is never produced implicitly: it comes
from :func:`correlation.drift.comparison.validate_baseline`, which requires a
caller to state the baseline id, who validated it and when. Nothing in the
observation path can turn itself into a trusted baseline.

Two digests, two jobs
---------------------

``state_digest``
    SHA-256 over the canonical comparable security state (see
    :mod:`correlation.drift.canonical`). This is the *fingerprint* two
    observations are compared by, and it is reproducible by any client that
    receives the canonical state.

``baseline_digest``
    SHA-256 over this whole record, including ``validated_at``. This is the
    *seal*: it makes tampering detectable, including a change to the metadata
    that the state digest does not cover. It is deterministic for a given set of
    inputs, so the timestamp is supplied explicitly by the caller rather than
    read from a clock inside this module.
"""

from dataclasses import dataclass, field as dataclass_field
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    BASELINE_SOURCE,
    DRIFT_COMPONENT,
    DRIFT_COMPONENT_VERSION,
    DRIFT_MODEL_VERSION,
    DRIFT_SCHEMA_VERSION,
    VALIDATION_STATUS_VALIDATED,
)


def _require_text(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class ValidatedBaseline:
    """A previously validated IPsec security state, with its provenance.

    ``canonical_state`` is retained rather than only its digest so a later
    comparison can report *which field* changed and *from what value*, which a
    digest alone cannot do.
    """

    baseline_id: str
    state_digest: str
    canonical_state: Dict[str, Any]
    validation_status: str = VALIDATION_STATUS_VALIDATED
    asset_id: Optional[str] = None
    source_run_id: Optional[str] = None
    source_observation_ref: Optional[str] = None
    captured_at: Optional[str] = None
    validated_at: Optional[str] = None
    validated_by: Optional[str] = None
    notes: Optional[str] = None
    schema_version: str = DRIFT_SCHEMA_VERSION
    model_version: str = DRIFT_MODEL_VERSION
    component: str = DRIFT_COMPONENT
    component_version: str = DRIFT_COMPONENT_VERSION
    source: str = BASELINE_SOURCE
    #: Evidence that supported the observation this baseline was validated from.
    #: Serialised dicts, so the record round-trips through JSON unchanged and
    #: never holds an absolute path or a payload.
    evidence_refs: Tuple[Dict[str, Any], ...] = dataclass_field(default_factory=tuple)

    def __post_init__(self) -> None:
        _require_text(self.baseline_id, "baseline_id")
        if self.validation_status != VALIDATION_STATUS_VALIDATED:
            raise ValueError(
                "a baseline's validation_status must be "
                f"{VALIDATION_STATUS_VALIDATED!r}; there is no implicit or "
                "provisional baseline in this system"
            )
        if self.schema_version != DRIFT_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version must be {DRIFT_SCHEMA_VERSION!r}, "
                f"got {self.schema_version!r}"
            )
        if not isinstance(self.canonical_state, dict) or not self.canonical_state:
            raise ValueError(
                "canonical_state must be a non-empty mapping; an empty baseline "
                "has nothing to compare against"
            )
        # Who validated the baseline, and when, is what makes the record
        # historical rather than inferred, so both are required rather than
        # optional provenance. A baseline that cannot say who approved it is not
        # attributable and is refused.
        _require_text(self.validated_at, "validated_at")
        _require_text(self.validated_by, "validated_by")
        for name in ("asset_id", "source_run_id", "source_observation_ref",
                     "captured_at", "notes"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{name} must be a non-empty string or None")
        if not isinstance(self.state_digest, str) or len(self.state_digest) != 64:
            raise ValueError("state_digest must be a 64-character hex digest")
        if not isinstance(self.evidence_refs, tuple):
            raise ValueError("evidence_refs must be a tuple")
        for ref in self.evidence_refs:
            if not isinstance(ref, dict):
                raise ValueError("evidence_refs entries must be serialised dicts")

    # -- identity -----------------------------------------------------------

    def seal_payload(self) -> Dict[str, Any]:
        """Exactly the fields the baseline seal covers, in canonical form.

        ``baseline_digest`` itself is excluded because it is the output of the
        seal. Everything else is covered, including the provenance metadata, so
        a later edit to any part of the record is detectable.
        """
        return {
            "baseline_id": self.baseline_id,
            "state_digest": self.state_digest,
            # Copied, not shared: a caller that mutates the returned mapping
            # must not be able to reach through it and edit the record.
            "canonical_state": dict(self.canonical_state),
            "validation_status": self.validation_status,
            "asset_id": self.asset_id,
            "source_run_id": self.source_run_id,
            "source_observation_ref": self.source_observation_ref,
            "captured_at": self.captured_at,
            "validated_at": self.validated_at,
            "validated_by": self.validated_by,
            "notes": self.notes,
            "schema_version": self.schema_version,
            "model_version": self.model_version,
            "component": self.component,
            "component_version": self.component_version,
            "source": self.source,
            "evidence_refs": [dict(ref) for ref in self.evidence_refs],
        }

    @property
    def baseline_digest(self) -> str:
        """The tamper-evident seal over :meth:`seal_payload`."""
        from ..custody.builder import canonical_digest

        return canonical_digest(self.seal_payload())

    def verify(self) -> Tuple[bool, Optional[str]]:
        """``(ok, reason)`` for the record's own integrity.

        Both digests are re-derived from the content: the seal, and the
        fingerprint of the canonical state. A mismatch means the record was
        altered after validation, or was built inconsistently.
        """
        from .canonical import canonical_state_digest

        if self.state_digest != canonical_state_digest(self.canonical_state):
            return False, (
                "state_digest does not match canonical_state; the baseline's "
                "comparable state was altered after it was sealed"
            )
        return True, None

    def comparable_variables(self) -> Tuple[str, ...]:
        return tuple(sorted(self.canonical_state))

    def to_dict(self) -> Dict[str, Any]:
        data = self.seal_payload()
        data["baseline_digest"] = self.baseline_digest
        return data

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "ValidatedBaseline":
        if not isinstance(payload, dict):
            raise ValueError("a baseline record must be a JSON object")
        known = {
            "baseline_id", "state_digest", "canonical_state", "validation_status",
            "asset_id", "source_run_id", "source_observation_ref", "captured_at",
            "validated_at", "validated_by", "notes", "schema_version",
            "model_version", "component", "component_version", "source",
            "evidence_refs", "baseline_digest",
        }
        unknown = sorted(set(payload) - known)
        if unknown:
            raise ValueError(f"unknown baseline field(s) {unknown}")
        missing = sorted(
            {"baseline_id", "state_digest", "canonical_state"} - set(payload)
        )
        if missing:
            raise ValueError(f"baseline record is missing required field(s) {missing}")
        record = cls(
            baseline_id=payload["baseline_id"],
            state_digest=payload["state_digest"],
            canonical_state=dict(payload["canonical_state"]),
            validation_status=payload.get("validation_status",
                                          VALIDATION_STATUS_VALIDATED),
            asset_id=payload.get("asset_id"),
            source_run_id=payload.get("source_run_id"),
            source_observation_ref=payload.get("source_observation_ref"),
            captured_at=payload.get("captured_at"),
            validated_at=payload.get("validated_at"),
            validated_by=payload.get("validated_by"),
            notes=payload.get("notes"),
            schema_version=payload.get("schema_version", DRIFT_SCHEMA_VERSION),
            model_version=payload.get("model_version", DRIFT_MODEL_VERSION),
            component=payload.get("component", DRIFT_COMPONENT),
            component_version=payload.get("component_version", DRIFT_COMPONENT_VERSION),
            source=payload.get("source", BASELINE_SOURCE),
            evidence_refs=tuple(
                dict(ref) for ref in payload.get("evidence_refs") or ()
            ),
        )
        # A record that arrives with a seal is checked against it, so a
        # tampered or hand-edited file is rejected at load time rather than
        # being trusted into a comparison.
        declared = payload.get("baseline_digest")
        if declared is not None and declared != record.baseline_digest:
            raise BaselineIntegrityError(
                f"baseline {record.baseline_id!r} failed its integrity check: the "
                "recorded baseline_digest does not match the record's content"
            )
        ok, reason = record.verify()
        if not ok:
            raise BaselineIntegrityError(
                f"baseline {record.baseline_id!r} failed its integrity check: {reason}"
            )
        return record


class BaselineIntegrityError(ValueError):
    """A baseline record is invalid, corrupt or has been tampered with."""


class BaselineNotConfigured(Exception):
    """No baseline was supplied for a comparison; reported, never defaulted."""


def sorted_baseline_ids(records: List[ValidatedBaseline]) -> Tuple[str, ...]:
    """Deterministic iteration order for a collection of baselines."""
    return tuple(sorted(record.baseline_id for record in records))
