"""Correlation-layer contract version.

This version is independent from the existing pipeline versions:
    - ``feature_schema_version = "v2"``  (owned by SIHPsec feature pipeline)
    - ``dataset_schema_version = "v1"``  (owned by SIHPsec dataset pipeline)

The correlation contract version must only change when the identity /
expected / observed / ML / evidence / correlation data contract itself changes.
"""

CORRELATION_SCHEMA_VERSION = "v1"