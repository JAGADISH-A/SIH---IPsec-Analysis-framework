"""Phase-11 analytical products built on top of the existing pipeline.

This package is the home of every NEW analytical value the backend produces
for the security-analysis brief. It deliberately contains no second pipeline:
nothing here re-runs a comparison, re-scores a finding or re-classifies a
window. Each module is a pure producer that consumes artifacts the existing
producers already emitted (``ObservedState``, ``ExpectedState``,
``CorrelationResult``, ``RiskAssessment``, ``MLResult``) and returns a
structured, JSON-serialisable product that states, for every value:

* ``state``   -- one of :data:`correlation.analysis.states.VALID_STATES`
* ``source``  -- the producer/artifact the value came from
* ``reason``  -- why that state and not another

Module map (kept flat so a reader can find a producer without a package
index):

``states``           the evidence-state vocabulary shared by every producer
``sa``               complete Security Association analysis (brief area 1)
``crypto_evidence``  runtime crypto evidence classification (area 2)
``replay``           replay/sequence analysis (area 3)
``metadata``         metadata exposure analysis (area 4)
``threat_matrix``    threat matrix derived from findings (area 7)
``reports``          technical + executive reports (areas 8 and 9)

Sub-modules are imported by path (``from correlation.analysis import sa``)
rather than eagerly re-exported, because two of them consume ``RiskAssessment``
while ``correlation.risk`` consumes ``replay``: an eager package-level import
would create an import cycle.
"""

__all__ = (
    "crypto_evidence",
    "metadata",
    "replay",
    "reports",
    "sa",
    "states",
    "threat_matrix",
)
