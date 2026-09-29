"""The scoped IPsec reasoning assistant.

An explanatory layer over the existing assessment pipeline, and nothing else.

    correlation.ai
      scope      the domain boundary, enforced before any model is called
      glossary   IPsec terminology, authored here so a definition cannot drift
      context    the only reader of authoritative state, and read-only
      prompt     the scoped prompt, built solely from a grounding context
      llm        an optional model provider, with no dependency
      guard      the gate that decides whether generated text may be shown
      engine     the orchestrator, and the grounded template answer
      service    a separate read-only HTTP surface

Authority boundary
------------------
This package does not decide anything. It does not assign or change severity,
does not calculate or override a score, does not create findings, does not
touch configuration, evidence, the journal, the testbed or the capture
pipeline, and it has no import edge to :mod:`correlation.risk` or to the
controller. It reads what the deterministic pipeline produced and restates it.

:data:`READ_ONLY_SURFACE` states that contract in one importable place so a
test can assert it rather than a reader having to infer it.
"""

from __future__ import annotations

from .context import ContextSource, HttpContextSource, StoreContextSource, build_grounding_context
from .engine import EXPLANATION_BANNER, AiExplanationEngine
from .guard import Guard, enforce
from .llm import LlmProvider, NullProvider, OpenAiCompatProvider, ProviderError, provider_from_env
from .models import (
    ORIGIN_AI,
    ORIGIN_DETERMINISTIC,
    ORIGIN_ML,
    ORIGIN_OBSERVED,
    ORIGINS,
    AiAnswer,
    GroundedFinding,
    GroundingContext,
    GuardReport,
    ScopeDecision,
)
from .scope import classify, out_of_scope_answer

#: The contract this package holds itself to, in one place.
READ_ONLY_SURFACE = {
    "decides_severity": False,
    "assigns_risk_score": False,
    "recomputes_scores": False,
    "creates_findings": False,
    "modifies_configuration": False,
    "modifies_assessments": False,
    "modifies_evidence": False,
    "writes_journal": False,
    "starts_or_configures_testbed": False,
    "replaces_risk_engine": False,
    "replaces_ml_layer": False,
    "has_own_confidence": False,
    "reads_whole_journals": False,
    "executes_shell": False,
}

__all__ = [
    "READ_ONLY_SURFACE",
    "EXPLANATION_BANNER",
    "ORIGINS",
    "ORIGIN_AI",
    "ORIGIN_DETERMINISTIC",
    "ORIGIN_ML",
    "ORIGIN_OBSERVED",
    "AiAnswer",
    "AiExplanationEngine",
    "ContextSource",
    "GroundedFinding",
    "GroundingContext",
    "Guard",
    "GuardReport",
    "HttpContextSource",
    "LlmProvider",
    "NullProvider",
    "OpenAiCompatProvider",
    "ProviderError",
    "ScopeDecision",
    "StoreContextSource",
    "build_grounding_context",
    "classify",
    "enforce",
    "out_of_scope_answer",
    "provider_from_env",
]
