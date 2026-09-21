"""SIH IPsec Correlation Layer — canonical data contract (Phase 2).

This package implements the versioned, strongly-structured data models that a
future Expected-vs-Observed Correlation Engine (Phase 3+) will consume.

Phase 2 scope ONLY:
  - experiment identity
  - expected testbed state
  - observed IPsec state
  - live feature-window information
  - ML result placeholder/interface (contract only, no ML)
  - evidence references
  - unified ``CorrelationInput`` object
  - unified ``CorrelationResult`` skeleton

NOT implemented here (later phases):
  - correlation/mismatch scoring, thresholds, distance calculations
  - anomaly detection
  - risk scoring
  - XAI
  - dashboard / response / policy
  - ML training and inference

The existing SIHPsec feature/dataset pipeline (``feature_schema_version=v2``,
``dataset_schema_version=v1``) remains the authority for its own schema. This
package introduces an independent contract:

    correlation_schema_version = "v1"
"""

from .version import CORRELATION_SCHEMA_VERSION  # noqa: F401

__all__ = ["CORRELATION_SCHEMA_VERSION"]