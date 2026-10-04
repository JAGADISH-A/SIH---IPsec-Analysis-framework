"""Read-only asset selection: which assets are declared, and one asset's context.

Why this module exists
----------------------
Asset mission context is already computed by
:func:`correlation.mission.contextualize.mission_context`, and the custody
route already publishes it -- but only for the single asset the store was
*started* with (``--asset-id``). ``GET
/api/v1/assessments/{id}/findings/{fid}/explanation`` therefore always answers
about that one bound asset, and the frontend has no way to ask about any other
declared asset.

This module exposes the existing capability to a caller that selects an asset,
and it is deliberately the thinnest possible layer:

* ``handle_asset_context`` performs **no calculation of its own**. It reads a
  technical risk/severity from the assessment store and then calls
  :func:`mission_context`, the same function
  :meth:`correlation.api.store.AssessmentStore.chain_of_custody` calls, passing
  the caller-supplied ``asset_id`` in the argument that function already
  accepts. The contextualisation arithmetic, the severity banding, the score cap
  and the ``not_configured`` empty state all stay in one place.
* ``handle_assets`` lists what the operator declared by reading
  :meth:`~correlation.mission.profiles.MissionProfileBook.asset_ids`. It does
  not rank, filter or synthesise an asset list, so a client can populate a
  selector from the backend instead of hardcoding ``gw-a``/``gw-b``.

Authority boundary
------------------
This is a QUERY layer, like every other ``/api/v1`` route. It decides nothing,
changes nothing and writes nothing:

* There is no POST/PUT/PATCH/DELETE here. Selecting an asset does not create an
  assessment, retune a risk policy or re-score anything; it only changes which
  declared profile is used to contextualise risk that was already computed.
* The store's own ``asset_id`` binding is never mutated. The ``asset_id`` in the
  path is a *question*, not a reconfiguration -- the custody explanation still
  reports the startup-bound asset.
* An asset with no declared profile is not an error here. It is reported with
  ``status: "not_configured"`` by ``mission_context`` itself, which is the same
  honest empty state the custody route publishes, so a client cannot mistake
  "absent context" for "benign context".

See ``tests/test_asset_context_route.py`` for the contract, including the test
that fails if this handler ever stops delegating.
"""

from typing import Any, Dict, Mapping, Optional

from ..mission import mission_context
from .routes import ApiError

API_ASSETS = "assets"
API_ASSET_CONTEXT = "asset-context"

#: Declared assets, as the operator configured them.
ASSETS_PATH = "/api/v1/assets"
#: One declared asset's mission context, addressed by the asset id.
ASSET_CONTEXT_SUFFIX = "/context"


def _store_or_503(store):
    """The assessment store, or a structured 503 when it is not attached.

    Same rule as the rest of the ``/api/v1`` assessment surface: a missing store
    is reported as unavailable rather than as an empty asset list, which would
    read as "the operator declared no assets".
    """
    if store is None:
        raise ApiError(
            503, "assessments_unavailable",
            "no assessment store is attached to the /api/v1 surface",
        )
    return store


def _overview(store):
    """The store's own overview block.

    ``highest_risk``/``highest_severity`` are computed by
    :meth:`AssessmentStore._build_overview` from the assessment headers, so
    using them here reuses an authoritative value instead of re-deriving a
    "worst assessment" here.
    """
    overview = getattr(store, "overview", None)
    return dict(overview) if isinstance(overview, Mapping) else {}


def _technical_risk(store, assessment_id: Optional[str]):
    """The (technical_risk, technical_severity, source) triple to contextualise.

    With ``assessment_id`` the pair is read from that assessment's own header, so
    the caller controls which assessment the asset is judged against. Without it
    the store's already-computed highest-risk assessment is used, and the choice
    is reported in ``technical_risk_source`` rather than applied silently.
    """
    overview = _overview(store)
    if assessment_id:
        for header in getattr(store, "headers", ()) or ():
            if str(header.get("assessment_id")) == assessment_id:
                return (
                    header.get("risk_score"),
                    header.get("severity"),
                    "assessment_header",
                )
        raise ApiError(
            404, "assessment_not_found",
            f"no assessment {assessment_id!r} in this store",
        )
    if not getattr(store, "headers", None):
        raise ApiError(
            503, "assessments_unavailable",
            "the store holds no assessment, so there is no technical risk to "
            "contextualise",
        )
    return (
        overview.get("highest_risk"),
        overview.get("highest_severity"),
        "store_highest_risk",
    )


def handle_assets(store) -> Dict[str, Any]:
    """Every asset the operator declared a mission profile for.

    The list is the selector's only legitimate source: a client that hardcodes
    ``gw-a``/``gw-b`` would show assets this deployment never declared, and
    would miss assets it did.
    """
    _store_or_503(store)
    profiles = getattr(store, "mission_profiles", None)
    if profiles is None:
        return {
            "api": API_ASSETS,
            "read_only": True,
            "configured": False,
            "reason": (
                "no mission profile file was supplied to this store, so no "
                "asset is declared; assets are declared explicitly and are "
                "never inferred from traffic"
            ),
            "store_asset_id": getattr(store, "asset_id", None),
            "count": 0,
            "total": 0,
            "assets": [],
        }
    body: Dict[str, Any] = {
        "api": API_ASSETS,
        "read_only": True,
        "configured": True,
        "reason": None,
        # The asset the custody route will report, so a client can tell which
        # profile is bound to this dataset run.
        "store_asset_id": getattr(store, "asset_id", None),
        "count": len(profiles.asset_ids()),
        "total": len(profiles.asset_ids()),
        "assets": list(profiles.asset_ids()),
    }
    book = profiles.to_dict()
    body["schema_version"] = book.get("schema_version")
    body["context_source"] = book.get("context_source")
    body["source"] = book.get("source")
    body["source_sha256"] = book.get("source_sha256")
    return body


def handle_asset_context(
    store,
    asset_id: str,
    params: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Mission context for one declared asset, at a stated technical risk.

    All mission-context behaviour belongs to :func:`mission_context`: the
    returned ``mission_context`` block is that function's ``to_dict()``, so the
    criticality, mission impact, contextualised risk and provenance here are the
    same values, from the same function, with the same ``not_configured``
    behaviour as the custody route.
    """
    _store_or_503(store)
    if not asset_id or "/" in asset_id:
        raise ApiError(404, "invalid_asset_id", f"invalid asset id {asset_id!r}")
    assessment_id = (params or {}).get("assessment_id") or None
    technical_risk, technical_severity, source = _technical_risk(store, assessment_id)
    if technical_risk is None:
        raise ApiError(
            503, "assessments_unavailable",
            "the store published no technical risk, so there is nothing to "
            "contextualise",
        )
    context = mission_context(
        technical_risk=technical_risk,
        technical_severity=technical_severity,
        asset_id=asset_id,
        profiles=getattr(store, "mission_profiles", None),
    )
    return {
        "api": API_ASSET_CONTEXT,
        "read_only": True,
        # Which risk was contextualised, and how that risk was chosen. The
        # answer is not complete without it: the same asset contextualises a
        # different score against a different assessment.
        "asset_id": asset_id,
        "assessment_id": assessment_id,
        "technical_risk_source": source,
        "technical_risk": technical_risk,
        "technical_severity": technical_severity,
        "mission_context": context.to_dict(),
    }