"""Phase 9 shared deterministic fixtures (REAL Phase-3/4/6/7 style objects).

Every recommendation/plan here is derived from the ACTUAL committed upstream
pipeline — by reusing the SAME real fixture helpers the committed Phase-4/6/7
tests already use — never fabricated:

* ``expected_for_posture``          REAL Phase-3 ``ExpectedState`` from a REAL
  committed plan sample (Phase 3 stays green);
* ``correlation_result``            REAL Phase-4 ``CorrelationResult`` from the
  REAL Phase-4 comparison engine via ``run_comparison`` (Phase 4 green);
* ``assessment_for_posture``        REAL Phase-6 ``RiskAssessment`` from the
  REAL Phase-6 ``RiskEngine.assess`` (Phase 6 green);
* ``xai_for``                       REAL Phase-7 ``ExplainabilityResult`` (via
  the REAL Phase-7 ``ExplainabilityEngine.explain``).

The ONLY crafted artifact is ``synthetic_correlation`` — and it is built with
the REAL Phase-4 ``ComparisonEngine`` default options and the REAL committed
``expected_from_plan_sample`` builder, so it is a genuine Phase-4
``CorrelationResult`` model instance (the exact same technique the committed
``test_risk_engine`` uses for satisfying rule-shape conditions the real engine
cannot deterministically produce).

Everything is deterministic: injected deterministic clock, no ``datetime.now``,
``random``, ``time.time`` or network access anywhere.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "risk"))

from risk_fixtures import (  # noqa: F401,E402
    expected_from_plan_sample,
    make_correlation,
    observed_values_for,
    plan_samples,
    run_comparison,
)

from correlation.models import (  # noqa: F401,E402
    CorrelationIdentity,
    CorrelationResult,
)
from correlation.risk import (  # noqa: F401,E402
    RiskAssessment,
    RiskEngine,
)
from correlation.xai import (  # noqa: F401,E402
    ExplainabilityEngine,
    ExplainabilityResult,
)

from correlation.response import (  # noqa: F401,E402
    DEFAULT_RESPONSE_POLICY_VERSION,
    ResponseEngine,
    ResponsePolicy,
)

DEMO_CLOCK_NS = 1_800_000_000_000_000_000
EXPIRY_NS = 3600 * 1_000_000_000  # one simulated demo hour
FINDING_EXPIRY_SLACK_NS = 1_000_000_000


def demo_clock() -> int:
    return DEMO_CLOCK_NS


def demo_clock_after(seconds: int) -> int:
    return DEMO_CLOCK_NS + seconds * 1_000_000_000


def policy(**updates) -> ResponsePolicy:
    kwargs = dict(
        policy_version=DEFAULT_RESPONSE_POLICY_VERSION,
    )
    kwargs.update(updates)
    return ResponsePolicy(**kwargs)


def engine(*, policy=None, clock=demo_clock, ledger=None, executor=None):
    return ResponseEngine(
        policy=policy,
        clock=clock,
        ledger=ledger,
        executor=executor,
    )


# -- REAL Phase-3 ----------------------------------------------------------

def plan_sample_by_posture(posture: str) -> dict:
    return next(s for s in plan_samples() if s["security_posture"] == posture)


def expected_for_posture(posture: str, **overrides) -> "ExpectedState":
    """REAL Phase-3 ExpectedState from a REAL committed plan sample."""
    return expected_from_plan_sample(
        plan_sample_by_posture(posture), **overrides,
    )


# -- REAL Phase-4 ----------------------------------------------------------

def real_correlation_for(expected, *, observed=None, observed_values=None,
                         identity=None, observed_identity=None,
                         **options) -> CorrelationResult:
    """REAL Phase-4 CorrelationResult through the REAL Phase-4 engine."""
    return run_comparison(
        expected,
        observed=observed,
        observed_values=(observed_values
                         or observed_values_for(expected)),
        identity=identity,
        observed_identity=observed_identity,
        **options,
    )


def synthetic_correlation(
    identity: CorrelationIdentity,
    *,
    unknowns=(),
    mismatches=(),
    not_applicable=(),
    matches=(),
) -> CorrelationResult:
    """Phase-4 CorrelationResult crafted from REAL committed plan artifacts.

    Uses the exact same "crafted but REAL model object" technique documented in
    the committed ``test_risk_engine``/``test_comparison_engine`` suites: a
    genuine ``CorrelationResult`` model instance is built with explicit
    outcome payloads ONLY where the REAL Phase-4 engine cannot deterministically
    author that exact outcome shape. Every such scenario is documented in the
    calling test as a synthetic unit fixture.
    """
    return make_correlation(
        identity,
        unknowns=unknowns,
        mismatches=mismatches,
        not_applicable=not_applicable,
        matches=matches,
    )


# -- REAL Phase-6 ----------------------------------------------------------

def assessment_for_posture(posture: str, **overrides):
    """REAL Phase-6 RiskAssessment for a REAL plan sample via REAL engine."""
    expected = expected_for_posture(posture)
    return assess(expected, **overrides)


def assess(expected, *, correlation=None, ml_result=None, evidence_refs=(),
           **options) -> RiskAssessment:
    """REAL Phase-6 RiskAssessment via the REAL Phase-6 RiskEngine."""
    if correlation is None:
        correlation = real_correlation_for(expected)
    return RiskEngine().assess(
        expected,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
        **options,
    )


def clean_assessment() -> RiskAssessment:
    """REAL clean assessment with no findings (STRONG secure posture)."""
    return assessment_for_posture("STRONG")


# -- REAL Phase-7 ----------------------------------------------------------

def xai_for(assessment: RiskAssessment, *, correlation=None,
            ml_result=None, evidence_refs=(), **options) -> ExplainabilityResult:
    """REAL Phase-7 ExplainabilityResult via the REAL Phase-7 engine."""
    return ExplainabilityEngine().explain(
        assessment,
        correlation=correlation,
        ml_result=ml_result,
        evidence_refs=evidence_refs,
        **options,
    )
