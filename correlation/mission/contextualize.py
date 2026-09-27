"""The contextualisation model: technical risk placed in declared asset context.

This is deliberately *not* a risk engine. It is a bounded, deterministic
multiplier over the technical score the existing Phase 6 engine already
computed, using the existing 0-100 range and the existing severity bands.

The formula
-----------
Technical risk in this project is an integer in ``[0, 100]`` (``RiskPolicy``
caps it at 100, bands at 0/1/10/20/40). That range is retained.

Each bounded category maps to a whole-percent weight, on the scale the
milestone suggests::

    low = 33   medium = 66   high = 100

    context_index      = (criticality_weight + mission_impact_weight) / 2
    excess_bp          = (context_index - 33) * 10000 / 67
    multiplier_bp      = 10000 + 5000 * excess_bp / 10000
    contextualized     = min(cap, technical_risk * multiplier_bp / 10000)

Read plainly: the two declared categories are averaged into a 33-100 index, the
distance above the *lowest* declared value becomes a 0-10000 basis-point
excess, and that excess buys at most a 50% uplift. ``bp`` is basis points, and
every division is integer floor division, so the result is exact, reproducible
and identical on any machine.

Consequences, all deliberate:

* **A low/low profile does not inflate anything.** The excess is measured from
  the minimum, so the multiplier is exactly 1.0000 and the contextualized score
  equals the technical score. A "low" asset is never made to look worse.
* **The result cannot exceed the existing range.** The product is clamped to the
  same cap the technical score already uses, so no new scale is introduced.
* **A low score stays low.** The model is multiplicative, so a finding with no
  technical weight gains none from context: 0 stays 0.
* **The exact multiplier is reported** with the result, so nothing about the
  arithmetic is hidden from the consumer.

What it deliberately does not do: it never *lowers* a technical risk, never
converts a model output into a risk contribution, and never uses ``role``.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from ..risk.policy import RiskPolicy
from .models import (
    CONTEXT_SOURCE,
    CRITICALITY_HIGH,
    CRITICALITY_LOW,
    CRITICALITY_MEDIUM,
    MISSION_CONTEXT_MODEL_VERSION,
    MISSION_IMPACT_HIGH,
    MISSION_IMPACT_LOW,
    MISSION_IMPACT_MEDIUM,
    STATUS_CONFIGURED,
    STATUS_NOT_CONFIGURED,
    validate_criticality,
    validate_mission_impact,
)
from .profiles import AssetMissionProfile, MissionProfileBook

#: Category -> whole-percent weight.
CATEGORY_WEIGHTS: Dict[str, int] = {
    CRITICALITY_LOW: 33,
    CRITICALITY_MEDIUM: 66,
    CRITICALITY_HIGH: 100,
    MISSION_IMPACT_LOW: 33,
    MISSION_IMPACT_MEDIUM: 66,
    MISSION_IMPACT_HIGH: 100,
}

#: The weight a lowest-criticality asset carries; the uplift is measured from here.
WEIGHT_FLOOR = CATEGORY_WEIGHTS[CRITICALITY_LOW]
#: The weight a highest-criticality asset carries.
WEIGHT_CEILING = CATEGORY_WEIGHTS[CRITICALITY_HIGH]
WEIGHT_SPAN = WEIGHT_CEILING - WEIGHT_FLOOR  # 67

#: Basis points of the neutral multiplier.
NEUTRAL_BP = 10_000
#: Maximum uplift, in basis points (50%). The ceiling of the model.
MAX_UPLIFT_BP = 5_000

#: The existing technical cap. Reused, not redefined.
TECHNICAL_SCORE_CAP = 100

#: One-line statement of the arithmetic, emitted with every result.
FORMULA = (
    "contextualized = min(100, technical_risk * (1 + 0.5 * "
    "(context_index - 33) / 67)), context_index = "
    "(criticality_weight + mission_impact_weight) / 2, "
    "low=33 medium=66 high=100"
)


def weight_of(value: str) -> int:
    """The whole-percent weight of one declared category."""
    if value not in CATEGORY_WEIGHTS:
        raise ValueError(f"no weight configured for {value!r}")
    return CATEGORY_WEIGHTS[value]


def context_multiplier_bp(
    criticality: str,
    mission_impact: str,
) -> Tuple[int, int]:
    """``(context_index, multiplier_bp)`` for a declared criticality/impact.

    Pure integer arithmetic; the two returned values are exactly what the
    consumer needs to reproduce the score by hand.
    """
    validate_criticality(criticality)
    validate_mission_impact(mission_impact)
    index = (weight_of(criticality) + weight_of(mission_impact)) // 2
    excess_bp = ((index - WEIGHT_FLOOR) * NEUTRAL_BP) // WEIGHT_SPAN
    multiplier = NEUTRAL_BP + (MAX_UPLIFT_BP * excess_bp) // NEUTRAL_BP
    return index, multiplier


@dataclass(frozen=True)
class ContextualizedRisk:
    """The technical risk plus the declared context that contextualises it.

    Both numbers are always present. ``technical_risk`` is the Phase 6 engine's
    own value, untouched, and is never recomputed here.
    """

    technical_risk: int
    technical_severity: str
    contextualized_risk: int
    contextualized_severity: str
    context_index: int
    multiplier_bp: int
    criticality_weight: int
    mission_impact_weight: int
    model_version: str = MISSION_CONTEXT_MODEL_VERSION
    formula: str = FORMULA
    score_cap: int = TECHNICAL_SCORE_CAP

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technical_risk": self.technical_risk,
            "technical_severity": self.technical_severity,
            "contextualized_risk": self.contextualized_risk,
            "contextualized_severity": self.contextualized_severity,
            "context_index": self.context_index,
            "multiplier_bp": self.multiplier_bp,
            "criticality_weight": self.criticality_weight,
            "mission_impact_weight": self.mission_impact_weight,
            "model_version": self.model_version,
            "formula": self.formula,
            "score_cap": self.score_cap,
            "inferred_from_traffic": False,
        }


def contextualize(
    technical_risk: int,
    technical_severity: str,
    profile: AssetMissionProfile,
    *,
    score_cap: int = TECHNICAL_SCORE_CAP,
) -> ContextualizedRisk:
    """Place one technical risk in one declared asset context.

    ``technical_risk`` and ``technical_severity`` are passed through verbatim:
    this function only ever *adds* a separately labelled contextualized view.
    """
    if not isinstance(technical_risk, int) or isinstance(technical_risk, bool):
        raise ValueError(f"technical_risk must be an int, got {technical_risk!r}")
    if not 0 <= technical_risk <= score_cap:
        raise ValueError(
            f"technical_risk must be in [0, {score_cap}], got {technical_risk}"
        )
    index, multiplier = context_multiplier_bp(
        profile.criticality, profile.mission_impact
    )
    # The only arithmetic in the model, in one readable expression.
    score = min(score_cap, (technical_risk * multiplier) // NEUTRAL_BP)
    return ContextualizedRisk(
        technical_risk=technical_risk,
        technical_severity=technical_severity,
        contextualized_risk=score,
        contextualized_severity=RiskPolicy.default().band_for(score)[0],
        context_index=index,
        multiplier_bp=multiplier,
        criticality_weight=weight_of(profile.criticality),
        mission_impact_weight=weight_of(profile.mission_impact),
        score_cap=score_cap,
    )


@dataclass(frozen=True)
class MissionContext:
    """Declared asset context for one assessment, and what it produced.

    ``status`` is the whole point of this object: when it is
    :data:`STATUS_NOT_CONFIGURED` there is no ``profile`` and no ``risk``, so a
    consumer cannot mistake absent context for a benign one.
    """

    status: str
    asset_id: Optional[str] = None
    profile: Optional[AssetMissionProfile] = None
    risk: Optional[ContextualizedRisk] = None
    #: Provenance label of the context. ``None`` when nothing was supplied, so
    #: an absent context never appears to have come from a source.
    context_source: Optional[str] = None
    context_source_path: Optional[str] = None
    context_source_sha256: Optional[str] = None
    reason: Optional[str] = None
    model_version: str = MISSION_CONTEXT_MODEL_VERSION

    @property
    def configured(self) -> bool:
        return self.status == STATUS_CONFIGURED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "configured": self.configured,
            "asset_id": self.asset_id,
            "profile": self.profile.to_dict() if self.profile is not None else None,
            "risk": self.risk.to_dict() if self.risk is not None else None,
            "context_source": self.context_source,
            "context_source_path": self.context_source_path,
            "context_source_sha256": self.context_source_sha256,
            "reason": self.reason,
            "model_version": self.model_version,
            "derived_from_observation": False,
        }


def not_configured(
    reason: str,
    *,
    asset_id: Optional[str] = None,
) -> MissionContext:
    """The honest empty context: no profile, no risk, no assumed criticality."""
    return MissionContext(
        status=STATUS_NOT_CONFIGURED,
        asset_id=asset_id,
        profile=None,
        risk=None,
        reason=reason,
    )


def mission_context(
    technical_risk: int,
    technical_severity: str,
    asset_id: Optional[str],
    profiles: Optional[MissionProfileBook],
) -> MissionContext:
    """Resolve declared context for ``asset_id`` and contextualise the risk.

    Every path that cannot find a usable profile returns
    :func:`not_configured` — an unknown asset, a missing file, a store built
    without an asset. No default criticality, no wildcard profile, no "medium"
    fallback.
    """
    if not asset_id:
        return not_configured(
            "no asset_id was declared for this assessment, so no mission "
            "context was supplied; technical risk is unchanged",
        )
    if profiles is None:
        return not_configured(
            f"asset {asset_id!r} has no loaded mission profile file, so no "
            f"mission context was supplied; technical risk is unchanged",
            asset_id=asset_id,
        )
    profile = profiles.get(asset_id)
    if profile is None:
        return not_configured(
            f"no mission profile is declared for asset {asset_id!r} in "
            f"{profiles.source}, so no mission context was supplied; technical "
            f"risk is unchanged",
            asset_id=asset_id,
        )
    return MissionContext(
        status=STATUS_CONFIGURED,
        asset_id=asset_id,
        profile=profile,
        risk=contextualize(technical_risk, technical_severity, profile),
        context_source=CONTEXT_SOURCE,
        context_source_path=profiles.source,
        context_source_sha256=profiles.source_sha256,
        reason=(
            f"mission context declared for asset {asset_id!r} by an operator; "
            f"it is assessment input, not an observation"
        ),
    )
