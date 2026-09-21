"""Expected-state adapter: SIHPsec artifacts -> Phase 2 ``ExpectedState``.

Phase 3 read-only materialization layer.

This module converts the REAL expected testbed state that currently lives
implicitly inside the SIH project into the Phase 2 canonical ``ExpectedState``
data contract. It is EXTRACTION / MATERIALIZATION ONLY:

* it never compares expected against observed,
* it never detects mismatches, never scores risk, never runs any ML,
* it never writes into ``D:\\sihipsec`` and never executes testbed commands.

Authoritative sources (in precedence order, see
``EXPECTED_STATE_SOURCE_ORDER``):

1. per-sample plan record      -- ``results/datasets/<run_id>/staging/plan.json``
2. explicit campaign record    -- ``campaign-*.json`` ``experiments`` entries
3. run metadata record         -- dataset ``metadata.jsonl`` / campaign ``metadata.json``
4. explicit configuration      -- ``controller/config.py`` / run CLI / run options
5. documented defaults         -- ONLY when the source semantics say so:

   The dataset executor's ``run_attempt`` applies ``setdefault`` semantics for
   ``traffic.duration`` / ``traffic.port`` / ``capture_filter`` whenever a plan
   sample does not carry its own ``traffic`` overrides. The adapter therefore
   treats those three values as legitimately defaulted (status
   ``MAPPED_WITH_NORMALIZATION``) when no higher source pins them. The IPsec
   security configuration (mode, address_family, ike.*, esp.*) is NEVER
   defaulted silently: a missing security variable fails fast with
   ``ExpectedStateMaterializationError``.

Design rules honoured here:

* the 14 canonical variable names are preserved exactly (never renamed),
* ``esp.integrity`` NULL stays ``null`` (GCM); it is never coerced to
  ``"none"`` unless the source literally contains that string,
* ``security_posture`` is consumed WHEN the source provides it and reported
  ``UNAVAILABLE`` otherwise; it is NEVER re-computed (``posture_of_config``
  stays in the SIH repo),
* ``configuration_id`` is consumed when the source provides it; otherwise it
  is derived ONLY through the Phase 2 ``ExpectedState.derive_configuration_id``
  helper (the documented grammar),
* ``capture_filter`` is preserved verbatim (``"esp"`` stays ``"esp"``,
  the canonical IKE+ESP filter stays as-is),
* window identity (``window_start_ns`` / ``window_end_ns`` / ``window_index``)
  is intentionally left unset here: Phase 2 ``CorrelationIdentity`` already
  carries those optional fields, so a later phase can derive them without
  redesign.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..models import (
    CANONICAL_VARIABLES,
    CorrelationIdentity,
    EspExpected,
    ExpectedState,
    IkeExpected,
    TrafficExpected,
)
from ..version import CORRELATION_SCHEMA_VERSION

# Documented experiment-id protocol (Phase 1 / controller.experiment_runner.EXPERIMENT_ID_RE):
#   <run_id>-exp-<seq:04d>-attempt-<attempt:02d>
EXPERIMENT_ID_RE = re.compile(r"\A(.+)-exp-(\d+)-attempt-(\d+)\Z")

# Documented campaign-run experiment id (controller.campaign.run_trial):
#   <run_id>-exp-<seq:04d>      (no attempt suffix)
CAMPAIGN_EXPERIMENT_ID_RE = re.compile(r"\A(.+)-exp-(\d+)\Z")

STATUS_MAPPED = "MAPPED"
STATUS_MAPPED_WITH_NORMALIZATION = "MAPPED_WITH_NORMALIZATION"
STATUS_MISSING = "MISSING"
STATUS_UNAVAILABLE = "UNAVAILABLE"

# Precedence policy (section 18 of the Phase 3 brief).
EXPECTED_STATE_SOURCE_ORDER = (
    "per-sample plan record",
    "explicit experiment/campaign record",
    "run metadata record",
    "explicit configuration",
    "documented defaults (only when the source semantics say the value was defaulted)",
)

# Documented testbed-wide values (Phase 1 discovery). Used ONLY for the three
# traffic/capture fields whose source semantics are setdefault-able
# (dataset_executor.run_attempt, campaign.execute_trial_pipeline) and in
# explicit-config materialization. Security configuration is NEVER taken from
# this map automatically.
SOURCE_DEFAULTS: Dict[str, Any] = {
    "mode": "tunnel",
    "address_family": "ipv4",
    "ike.version": 2,
    "ike.encryption": "aes256",
    "ike.integrity": "sha256",
    "ike.dh_group": "modp2048",
    "esp.encryption": "aes256cbc",
    "esp.integrity": "sha256",
    "esp.dh_group": "modp2048",
    "esp.pfs": True,
    "traffic.duration": 30,   # controller.traffic.DEFAULT_DURATION
    "traffic.port": 20000,    # controller.traffic.DEFAULT_PORT
    "capture_filter": "udp port 500 or udp port 4500 or esp or ah",  # controller.capture.DEFAULT_CAPTURE_FILTER
}

# Canonical variables the executor legitimately defaults via setdefault
# semantics when a plan sample carries no per-sample ``traffic`` overrides.
SETDEFAULT_ABLE = frozenset(
    {"traffic.duration", "traffic.port", "capture_filter"}
)

# Security variables that must ALWAYS come from an authoritative source.
NEVER_DEFAULTED = frozenset(
    {"mode", "address_family", "ike.version", "ike.encryption",
     "ike.integrity", "ike.dh_group", "esp.encryption", "esp.integrity",
     "esp.dh_group", "esp.pfs", "traffic.profile"}
)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExpectedStateMaterializationError(Exception):
    """Fatal failure while materializing an expected state from a source.

    Raised (never silently recovered from) when a required expected variable
    cannot be obtained, when a higher-priority source is malformed, or when a
    source-specified value is invalid. The error identifies run / sequence /
    experiment / source file / variable so a security assessment can trace
    exactly what failed and why no guessed default was used.
    """

    def __init__(
        self,
        message: str,
        *,
        run_id: Optional[str] = None,
        sequence: Optional[int] = None,
        experiment_id: Optional[str] = None,
        source_file: Optional[str] = None,
        missing_variable: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.run_id = run_id
        self.sequence = sequence
        self.experiment_id = experiment_id
        self.source_file = source_file
        self.missing_variable = missing_variable

    def describe(self) -> str:
        return (
            "ExpectedStateMaterializationError: "
            + self.message
            + f" (run={self.run_id}, sequence={self.sequence}, "
            + f"experiment={self.experiment_id}, "
            + f"source_file={self.source_file or 'n/a'}, "
            + f"missing_variable={self.missing_variable or 'n/a'})"
        )


class MissingExpectedVariableError(ExpectedStateMaterializationError):
    """A required expected variable is absent from an authoritative source."""


class SourceProvenance:
    """Adapter-level provenance for one materialized expected state.

    Adapter-level structure (the Phase 2 models are NOT modified). Records
    where every expected value came from so later correlation results can
    answer: "Where did this expected value come from?"
    """

    __slots__ = (
        "source_type",
        "source_path",
        "source_record",
        "materialized_at",
        "variable_sources",
    )

    def __init__(
        self,
        source_type: str,
        source_path: str,
        source_record: str,
        materialized_at: Optional[str] = None,
        variable_sources: Optional[Dict[str, Tuple[str, str]]] = None,
    ) -> None:
        self.source_type = source_type
        self.source_path = source_path
        self.source_record = source_record
        self.materialized_at = materialized_at or utcnow_iso()
        # canonical variable -> (status, source key)
        self.variable_sources: Dict[str, Tuple[str, str]] = dict(
            variable_sources or {}
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "source_path": self.source_path,
            "source_record": self.source_record,
            "materialized_at": self.materialized_at,
            "variable_sources": {
                variable: {"status": status, "source_key": key}
                for variable, (status, key) in sorted(self.variable_sources.items())
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SourceProvenance":
        vs = {
            variable: (entry["status"], entry["source_key"])
            for variable, entry in (data.get("variable_sources") or {}).items()
        }
        return cls(
            source_type=data["source_type"],
            source_path=data["source_path"],
            source_record=data["source_record"],
            materialized_at=data.get("materialized_at"),
            variable_sources=vs,
        )


class MaterializedExpectedState:
    """One materialized expected state: identity + expected + provenance.

    The adapter's output container (``correlation_schema_version``,
    ``identity``, ``expected``, ``provenance``). It is NOT a Phase 2 model; it
    exists so a later phase can replay both the value and its provenance.
    """

    __slots__ = (
        "correlation_schema_version",
        "identity",
        "expected",
        "provenance",
    )

    def __init__(
        self,
        identity: CorrelationIdentity,
        expected: ExpectedState,
        provenance: SourceProvenance,
        correlation_schema_version: str = CORRELATION_SCHEMA_VERSION,
    ) -> None:
        if correlation_schema_version != CORRELATION_SCHEMA_VERSION:
            raise ValueError(
                f"correlation_schema_version must be "
                f"{CORRELATION_SCHEMA_VERSION!r}, got {correlation_schema_version!r}"
            )
        self.correlation_schema_version = correlation_schema_version
        self.identity = identity
        self.expected = expected
        self.provenance = provenance

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_schema_version": self.correlation_schema_version,
            "identity": self.identity.to_dict(),
            "expected": self.expected.to_dict(),
            "provenance": self.provenance.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MaterializedExpectedState":
        return cls(
            correlation_schema_version=data["correlation_schema_version"],
            identity=CorrelationIdentity.from_dict(data["identity"]),
            expected=ExpectedState.from_dict(data["expected"]),
            provenance=SourceProvenance.from_dict(data["provenance"]),
        )

    @classmethod
    def from_json(cls, raw: str) -> "MaterializedExpectedState":
        return cls.from_dict(json.loads(raw))


def infer_run_id_from_plan_path(plan_path) -> Optional[str]:
    """Best-effort run id for ``results/datasets/<run_id>/staging/plan.json``.

    Returns ``None`` (caller must supply ``--run-id``) when the path does not
    match the canonical dataset layout.
    """
    path = Path(plan_path).resolve()
    if path.name == "plan.json" and path.parent.name == "staging":
        return path.parent.parent.name
    return None


class ExpectedStateAdapter:
    """Read-only extraction of expected state from SIHPsec artifacts.

    Usage::

        adapter = ExpectedStateAdapter()
        out = adapter.from_plan(plan_path, sequence=2)

    ``run_options`` may carry explicit run-level ``traffic.duration`` /
    ``traffic.port`` / ``capture_filter`` (precedence above defaults).
    ``materialized_at`` is injectable for deterministic provenance.
    """

    def __init__(
        self,
        *,
        run_options: Optional[Dict[str, Any]] = None,
        materialized_at: Optional[str] = None,
    ) -> None:
        self.run_options = dict(run_options or {})
        self.materialized_at = materialized_at

    # ------------------------------------------------------------------
    # public source methods
    # ------------------------------------------------------------------

    def from_plan(
        self,
        plan_path,
        sequence: int,
        *,
        experiment_id: Optional[str] = None,
        attempt_number: Optional[int] = None,
        run_id: Optional[str] = None,
    ) -> MaterializedExpectedState:
        """Materialize one sample from ``results/datasets/<run_id>/staging/plan.json``.

        Precedence inside the plan sample: an optional per-sample ``traffic``
        sub-object wins over ``run_options``, which wins over the documented
        run defaults that the executor's ``setdefault`` semantics apply.
        """
        plan_path = Path(plan_path)
        if not plan_path.is_file():
            raise ExpectedStateMaterializationError(
                f"plan file not found: {plan_path}",
                source_file=str(plan_path),
            )
        try:
            plan = json.loads(plan_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ExpectedStateMaterializationError(
                f"plan.json is malformed: {exc}",
                source_file=str(plan_path),
            )

        if run_id is None:
            run_id = infer_run_id_from_plan_path(plan_path)
        if run_id is None:
            raise ExpectedStateMaterializationError(
                "could not infer dataset_run_id from the plan path; pass "
                "--run-id (plan is not under results/datasets/<run_id>/staging/)",
                sequence=sequence,
                source_file=str(plan_path),
            )

        return self.from_plan_record(
            plan,
            run_id=run_id,
            sequence=sequence,
            experiment_id=experiment_id,
            attempt_number=attempt_number,
            source_path=str(plan_path),
            source_type="plan",
        )

    def from_plan_record(
        self,
        plan: Dict[str, Any],
        *,
        run_id: str,
        sequence: int,
        experiment_id: Optional[str] = None,
        attempt_number: Optional[int] = None,
        source_path: str = "plan.json",
        source_type: str = "plan",
    ) -> MaterializedExpectedState:
        """Materialize ``sequence`` from an in-memory plan dict."""
        samples = plan.get("samples")
        if not isinstance(samples, list) or not samples:
            raise ExpectedStateMaterializationError(
                "plan contains no 'samples' list",
                run_id=run_id,
                sequence=sequence,
                source_file=source_path,
                missing_variable="samples",
            )
        by_sequence = {s.get("sequence"): s for s in samples}
        sample = by_sequence.get(sequence)
        if sample is None:
            raise ExpectedStateMaterializationError(
                f"plan has no sample for sequence {sequence}",
                run_id=run_id,
                sequence=sequence,
                source_file=source_path,
                missing_variable="samples[]",
            )
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
            raise ExpectedStateMaterializationError(
                f"sequence must be a positive integer, got {sequence!r}",
                run_id=run_id,
                source_file=source_path,
            )

        _, exp_id, attempt = self._resolve_identity(
            run_id=run_id,
            sequence=sequence,
            experiment_id=experiment_id,
            attempt_number=attempt_number,
            campaign_style=False,
            source_path=source_path,
        )

        ipsec = sample.get("ipsec_configuration")
        if not isinstance(ipsec, dict):
            raise MissingExpectedVariableError(
                f"Missing required expected variable 'ipsec_configuration' for "
                f"experiment {exp_id}",
                run_id=run_id, sequence=sequence, experiment_id=exp_id,
                source_file=source_path, missing_variable="ipsec_configuration",
            )
        traffic_record = sample.get("traffic") or {}
        source_prefix = f"plan.samples[{sequence}]"
        ipsec_prefix = f"plan.samples[{sequence}].ipsec_configuration"
        expected, variable_sources = self._from_config_like(
            ipsec=ipsec,
            ipsec_prefix=ipsec_prefix,
            traffic_profile=sample.get("traffic_profile"),
            traffic=traffic_record,
            traffic_prefix=f"plan.samples[{sequence}].traffic",
            profile_source_key=f"plan.samples[{sequence}].traffic_profile",
            identity_prefix=f"plan.samples[{sequence}]",
            config_id=sample.get("configuration_id"),
            security_posture=sample.get("security_posture"),
            source_path=source_path,
            run_id=run_id,
            sequence=sequence,
            experiment_id=exp_id,
        )

        provenance = SourceProvenance(
            source_type=source_type,
            source_path=str(Path(source_path)),
            source_record=f"sequence={sequence}",
            materialized_at=self.materialized_at,
            variable_sources=variable_sources,
        )
        identity = CorrelationIdentity(
            dataset_run_id=run_id,
            sequence=sequence,
            experiment_id=exp_id,
            attempt_number=attempt,
        )
        return MaterializedExpectedState(
            correlation_schema_version=CORRELATION_SCHEMA_VERSION,
            identity=identity,
            expected=expected,
            provenance=provenance,
        )

    def from_campaign(
        self,
        campaign_path,
        sequence: int,
        *,
        experiment_id: Optional[str] = None,
        attempt_number: Optional[int] = None,
    ) -> MaterializedExpectedState:
        """Materialize experiment ``sequence`` (1-based) from a campaign JSON."""
        campaign_path = Path(campaign_path)
        if not campaign_path.is_file():
            raise ExpectedStateMaterializationError(
                f"campaign file not found: {campaign_path}",
                source_file=str(campaign_path),
            )
        try:
            campaign = json.loads(campaign_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ExpectedStateMaterializationError(
                f"campaign JSON is malformed: {exc}",
                source_file=str(campaign_path),
            )
        return self.from_campaign_record(
            campaign,
            sequence=sequence,
            experiment_id=experiment_id,
            attempt_number=attempt_number,
            source_path=str(campaign_path),
        )

    def from_campaign_record(
        self,
        campaign: Dict[str, Any],
        *,
        sequence: int,
        experiment_id: Optional[str] = None,
        attempt_number: Optional[int] = None,
        source_path: str = "campaign.json",
    ) -> MaterializedExpectedState:
        experiments = campaign.get("experiments")
        if not isinstance(experiments, list) or not experiments:
            raise ExpectedStateMaterializationError(
                "campaign contains no 'experiments' list",
                sequence=sequence,
                source_file=source_path,
                missing_variable="experiments",
            )
        if not (1 <= sequence <= len(experiments)):
            raise ExpectedStateMaterializationError(
                f"campaign experiment index {sequence} out of range "
                f"(1..{len(experiments)})",
                sequence=sequence,
                source_file=source_path,
            )
        run_id = campaign.get("run_id")
        if run_id is None:
            raise ExpectedStateMaterializationError(
                "campaign has no 'run_id'; pass --run-id",
                sequence=sequence,
                source_file=source_path,
            )

        experiment = experiments[sequence - 1]
        _, exp_id, attempt = self._resolve_identity(
            run_id=run_id,
            sequence=sequence,
            experiment_id=experiment_id,
            attempt_number=attempt_number,
            campaign_style=True,
            source_path=source_path,
        )

        traffic = experiment.get("traffic") or {}
        expected, variable_sources = self._from_config_like(
            ipsec=experiment,
            ipsec_prefix=f"campaign.experiments[{sequence - 1}]",
            traffic_profile=traffic.get("profile"),
            traffic=traffic,
            traffic_prefix=f"campaign.experiments[{sequence - 1}].traffic",
            profile_source_key=f"campaign.experiments[{sequence - 1}].traffic.profile",
            identity_prefix=f"campaign.experiments[{sequence - 1}]",
            config_id=None,
            security_posture=None,
            source_path=source_path,
            run_id=run_id,
            sequence=sequence,
            experiment_id=exp_id,
        )

        provenance = SourceProvenance(
            source_type="campaign",
            source_path=str(Path(source_path)),
            source_record=f"sequence={sequence}",
            materialized_at=self.materialized_at,
            variable_sources=variable_sources,
        )
        identity = CorrelationIdentity(
            dataset_run_id=run_id,
            sequence=sequence,
            experiment_id=exp_id,
            attempt_number=attempt,
        )
        return MaterializedExpectedState(
            correlation_schema_version=CORRELATION_SCHEMA_VERSION,
            identity=identity,
            expected=expected,
            provenance=provenance,
        )

    def from_metadata_record(
        self,
        record: Dict[str, Any],
        *,
        source_path: str = "metadata.jsonl",
        source_record: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> MaterializedExpectedState:
        """Materialize from one run-metadata record (dataset or campaign form).

        Supports both the finalized dataset keys (``ike_dh_group`` /
        ``esp_dh_group`` / ``traffic_profile``) and the legacy campaign keys
        (``ike_dh`` / ``esp_dh`` / ``traffic_type``).
        """
        run_id = run_id or record.get("dataset_run_id") or record.get("run_id")
        sequence = record.get("sequence")
        exp_id = record.get("experiment_id")
        attempt = record.get("attempt_number", 1)
        if run_id is None or sequence is None or exp_id is None:
            raise ExpectedStateMaterializationError(
                "metadata record lacks run/sequence/experiment identity",
                source_file=source_path,
                missing_variable="dataset_run_id|sequence|experiment_id",
            )

        def pick(*keys):
            for key in keys:
                if key in record:
                    return record[key]
            return None

        ipsec = {
            "mode": pick("mode"),
            "address_family": pick("address_family"),
            "ike": {
                "version": pick("ike_version"),
                "encryption": pick("ike_encryption"),
                "integrity": pick("ike_integrity"),
                "dh_group": pick("ike_dh_group", "ike_dh"),
            },
            "esp": {
                "encryption": pick("esp_encryption"),
                "integrity": pick("esp_integrity"),
                "dh_group": pick("esp_dh_group", "esp_dh"),
                "pfs": pick("pfs"),
            },
        }
        traffic = {
            "profile": pick("traffic_profile", "traffic_type"),
            "duration": pick("traffic_duration"),
            "port": pick("traffic_port"),
            "capture_filter": pick("capture_filter"),
        }
        traffic_model = record.get("traffic_model") if isinstance(record.get("traffic_model"), dict) else {}
        if traffic["duration"] is None:
            traffic["duration"] = traffic_model.get("duration")
        if traffic["port"] is None:
            traffic["port"] = traffic_model.get("port")

        expected, variable_sources = self._from_config_like(
            ipsec=ipsec,
            ipsec_prefix="metadata",
            traffic_profile=traffic.get("profile"),
            traffic=traffic,
            traffic_prefix="metadata.traffic",
            profile_source_key="metadata.traffic_profile|metadata.traffic_type",
            identity_prefix="metadata",
            config_id=record.get("configuration_id"),
            security_posture=record.get("security_posture"),
            source_path=source_path,
            run_id=run_id,
            sequence=sequence,
            experiment_id=exp_id,
        )

        provenance = SourceProvenance(
            source_type="metadata",
            source_path=str(Path(source_path)),
            source_record=source_record or f"sequence={sequence}",
            materialized_at=self.materialized_at,
            variable_sources=variable_sources,
        )
        identity = CorrelationIdentity(
            dataset_run_id=run_id,
            sequence=sequence,
            experiment_id=exp_id,
            attempt_number=int(attempt or 1),
        )
        return MaterializedExpectedState(
            correlation_schema_version=CORRELATION_SCHEMA_VERSION,
            identity=identity,
            expected=expected,
            provenance=provenance,
        )

    def from_config(
        self,
        config: Dict[str, Any],
        *,
        run_id: str,
        sequence: int = 1,
        experiment_id: Optional[str] = None,
        attempt_number: int = 1,
        source_path: str = "controller/config.py",
    ) -> MaterializedExpectedState:
        """Materialize from an explicit configuration dict (precedence level 4).

        ``config`` mirrors the validated SIHPsec shape (``mode``,
        ``address_family``, ``ike``, ``esp``) optionally with a ``traffic``
        sub-dict. Used when no plan/campaign/metadata record exists.
        """
        traffic = config.get("traffic") if isinstance(config.get("traffic"), dict) else {}
        expected, variable_sources = self._from_config_like(
            ipsec=config,
            ipsec_prefix="config",
            traffic_profile=config.get("traffic_profile") or traffic.get("profile"),
            traffic=traffic,
            traffic_prefix="config.traffic",
            profile_source_key="config.traffic_profile|config.traffic.profile",
            identity_prefix="config",
            config_id=config.get("configuration_id"),
            security_posture=config.get("security_posture"),
            source_path=source_path,
            run_id=run_id,
            sequence=sequence,
            experiment_id=experiment_id,
        )
        provenance = SourceProvenance(
            source_type="config",
            source_path=str(Path(source_path)),
            source_record=f"sequence={sequence}",
            materialized_at=self.materialized_at,
            variable_sources=variable_sources,
        )
        identity = CorrelationIdentity(
            dataset_run_id=run_id,
            sequence=sequence,
            experiment_id=experiment_id or f"{run_id}-exp-{sequence:04d}",
            attempt_number=attempt_number,
        )
        return MaterializedExpectedState(
            correlation_schema_version=CORRELATION_SCHEMA_VERSION,
            identity=identity,
            expected=expected,
            provenance=provenance,
        )

    # ------------------------------------------------------------------
    # batch materialization
    # ------------------------------------------------------------------

    def materialize_all_plan_samples(
        self,
        plan_path,
        *,
        run_id: Optional[str] = None,
        source_path: Optional[str] = None,
    ) -> List[MaterializedExpectedState]:
        """Materialize every valid sample of a plan (deterministic order)."""
        plan_path = Path(plan_path)
        if not plan_path.is_file():
            raise ExpectedStateMaterializationError(
                f"plan file not found: {plan_path}",
                source_file=str(plan_path),
            )
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        path = source_path or str(plan_path)
        if run_id is None:
            run_id = infer_run_id_from_plan_path(plan_path)
        if run_id is None:
            raise ExpectedStateMaterializationError(
                "could not infer dataset_run_id from the plan path; pass "
                "--run-id",
                source_file=path,
            )
        samples = plan.get("samples")
        if not isinstance(samples, list):
            raise ExpectedStateMaterializationError(
                "plan contains no 'samples' list",
                run_id=run_id,
                source_file=path,
            )
        sequenced = sorted(
            (s for s in samples if isinstance(s.get("sequence"), int)),
            key=lambda s: s["sequence"],
        )
        return [
            self.from_plan_record(
                plan,
                run_id=run_id,
                sequence=sample["sequence"],
                source_path=path,
                source_type="plan",
            )
            for sample in sequenced
        ]

    def write_batch(
        self,
        materialized: Sequence[MaterializedExpectedState],
        output_path,
    ) -> Path:
        """Write one JSON object per line (JSONL). Output may live anywhere.

        Never called with a path under ``D:\\sihipsec``; the caller owns the
        output location.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fh:
            for item in materialized:
                fh.write(json.dumps(item.to_dict()) + "\n")
        return output_path

    # ------------------------------------------------------------------
    # identity / validation helpers
    # ------------------------------------------------------------------

    def _resolve_identity(
        self,
        *,
        run_id: str,
        sequence: int,
        experiment_id: Optional[str],
        attempt_number: Optional[int],
        campaign_style: bool,
        source_path: str,
    ) -> Tuple[str, str, int]:
        """Resolve (run_id, experiment_id, attempt_number) with the documented
        experiment-id protocols. Attempt isolation is preserved exactly:
        sequence 5 attempt 2 can never be confused with sequence 5 attempt 1.
        """
        if experiment_id is not None:
            match = EXPERIMENT_ID_RE.fullmatch(experiment_id)
            if match is not None:
                e_run, e_seq, e_attempt = (
                    match.group(1), int(match.group(2)), int(match.group(3))
                )
                if e_seq != sequence:
                    raise ExpectedStateMaterializationError(
                        f"experiment_id '{experiment_id}' encodes sequence "
                        f"{e_seq} but --sequence {sequence} was requested",
                        run_id=run_id,
                        sequence=sequence,
                        experiment_id=experiment_id,
                        source_file=source_path,
                    )
                attempt_number = attempt_number or e_attempt
            else:
                c_match = CAMPAIGN_EXPERIMENT_ID_RE.fullmatch(experiment_id)
                if c_match is None:
                    raise ExpectedStateMaterializationError(
                        f"experiment_id '{experiment_id}' does not match the "
                        f"documented protocol "
                        f"<run_id>-exp-<seq>[-attempt-<attempt>]",
                        run_id=run_id,
                        sequence=sequence,
                        experiment_id=experiment_id,
                        source_file=source_path,
                    )
                if int(c_match.group(2)) != sequence:
                    raise ExpectedStateMaterializationError(
                        f"experiment_id '{experiment_id}' encodes sequence "
                        f"{c_match.group(2)} but --sequence {sequence} was "
                        f"requested",
                        run_id=run_id,
                        sequence=sequence,
                        experiment_id=experiment_id,
                        source_file=source_path,
                    )
        if attempt_number is None:
            attempt_number = 1
        if (
            isinstance(attempt_number, bool)
            or not isinstance(attempt_number, int)
            or attempt_number < 1
        ):
            raise ExpectedStateMaterializationError(
                f"attempt_number must be a positive integer, got {attempt_number!r}",
                run_id=run_id,
                sequence=sequence,
                experiment_id=experiment_id,
                source_file=source_path,
            )
        if experiment_id is not None:
            exp_id = experiment_id
        elif campaign_style:
            exp_id = f"{run_id}-exp-{sequence:04d}"
        else:
            exp_id = f"{run_id}-exp-{sequence:04d}-attempt-{attempt_number:02d}"
        return run_id, exp_id, attempt_number

    # ------------------------------------------------------------------
    # core mapping
    # ------------------------------------------------------------------

    def _from_config_like(
        self,
        *,
        ipsec,
        ipsec_prefix,
        traffic_profile,
        traffic,
        traffic_prefix,
        profile_source_key,
        identity_prefix,
        config_id,
        security_posture,
        source_path,
        run_id,
        sequence,
        experiment_id,
    ) -> Tuple[ExpectedState, Dict[str, Tuple[str, str]]]:
        """Map an SIHPsec-shaped config + traffic record to an ``ExpectedState``.

        Returns ``(expected, variable_sources)`` where ``variable_sources`` is
        canonical variable -> ``(status, source_key)``.
        """
        variable_sources: Dict[str, Tuple[str, str]] = {}

        def mapped(variable, source_key):
            variable_sources[variable] = (STATUS_MAPPED, source_key)

        # -- security block: never silently defaulted ----------------------
        ike = ipsec.get("ike") if isinstance(ipsec.get("ike"), dict) else {}
        esp = ipsec.get("esp") if isinstance(ipsec.get("esp"), dict) else {}

        def sec_value(variable, container_key, allow_none=False):
            value = {
                "mode": ipsec.get("mode"),
                "address_family": ipsec.get("address_family"),
                "ike.version": ike.get("version"),
                "ike.encryption": ike.get("encryption"),
                "ike.integrity": ike.get("integrity"),
                "ike.dh_group": ike.get("dh_group"),
                "esp.encryption": esp.get("encryption"),
                "esp.integrity": esp.get("integrity"),
                "esp.dh_group": esp.get("dh_group"),
                "esp.pfs": esp.get("pfs"),
            }[variable]
            if value is None and not allow_none:
                raise MissingExpectedVariableError(
                    f"Missing required expected variable '{variable}' for "
                    f"experiment {experiment_id} (source key "
                    f"'{ipsec_prefix}.{container_key}')",
                    run_id=run_id,
                    sequence=sequence,
                    experiment_id=experiment_id,
                    source_file=str(Path(source_path)),
                    missing_variable=variable,
                )
            return value

        for variable, container_key in (
            ("mode", "mode"),
            ("address_family", "address_family"),
            ("ike.version", "ike.version"),
            ("ike.encryption", "ike.encryption"),
            ("ike.integrity", "ike.integrity"),
            ("ike.dh_group", "ike.dh_group"),
            ("esp.encryption", "esp.encryption"),
            ("esp.dh_group", "esp.dh_group"),
            ("esp.pfs", "esp.pfs"),
        ):
            sec_value(variable, container_key)
            mapped(variable, f"{ipsec_prefix}.{container_key}")

        esp_encryption = esp.get("encryption")
        esp_integrity = esp.get("integrity")
        if esp_integrity is None:
            sec_value("esp.integrity", "esp.integrity", allow_none=True)
            mapped("esp.integrity", f"{ipsec_prefix}.esp.integrity")
        else:
            mapped("esp.integrity", f"{ipsec_prefix}.esp.integrity")
            variable_sources["esp.integrity"] = (
                STATUS_MAPPED, f"{ipsec_prefix}.esp.integrity"
            )
        self._validate_ipsec_coupling(
            esp_encryption, esp_integrity, run_id, sequence, experiment_id
        )

        # -- traffic.profile (source-alpha) --------------------------------
        if traffic_profile is None:
            raise MissingExpectedVariableError(
                f"Missing required expected variable 'traffic.profile' for "
                f"experiment {experiment_id}",
                run_id=run_id,
                sequence=sequence,
                experiment_id=experiment_id,
                source_file=str(Path(source_path)),
                missing_variable="traffic.profile",
            )
        mapped("traffic.profile", profile_source_key)

        # -- traffic.duration / port / capture_filter ----------------------
        duration, d_status, d_key = self._resolve_traffic_capture_value(
            "traffic.duration", traffic, "duration", traffic_prefix,
            run_id, sequence, experiment_id,
        )
        port, p_status, p_key = self._resolve_traffic_capture_value(
            "traffic.port", traffic, "port", traffic_prefix,
            run_id, sequence, experiment_id,
        )
        capture_filter, c_status, c_key = self._resolve_traffic_capture_value(
            "capture_filter", traffic, "capture_filter", traffic_prefix,
            run_id, sequence, experiment_id,
        )
        variable_sources["traffic.duration"] = (d_status, d_key)
        variable_sources["traffic.port"] = (p_status, p_key)
        variable_sources["capture_filter"] = (c_status, c_key)

        # -- configuration_id / security_posture (never computed here) ------
        if config_id is not None:
            variable_sources["configuration_id"] = (
                STATUS_MAPPED, f"{identity_prefix}.configuration_id"
            )
        else:
            variable_sources["configuration_id"] = (
                STATUS_UNAVAILABLE,
                "absent from source; derived via ExpectedState.derive_configuration_id()",
            )
        if security_posture is not None:
            variable_sources["security_posture"] = (
                STATUS_MAPPED, f"{identity_prefix}.security_posture"
            )
        else:
            variable_sources["security_posture"] = (
                STATUS_UNAVAILABLE,
                "posture_of_config authority result absent from source (never recomputed)",
            )

        expected = ExpectedState(
            mode=sec_value("mode", "mode"),
            address_family=sec_value("address_family", "address_family"),
            ike=IkeExpected(
                version=sec_value("ike.version", "ike.version"),
                encryption=sec_value("ike.encryption", "ike.encryption"),
                integrity=sec_value("ike.integrity", "ike.integrity"),
                dh_group=sec_value("ike.dh_group", "ike.dh_group"),
            ),
            esp=EspExpected(
                encryption=esp_encryption,
                integrity=esp_integrity,
                dh_group=sec_value("esp.dh_group", "esp.dh_group"),
                pfs=sec_value("esp.pfs", "esp.pfs"),
            ),
            traffic=TrafficExpected(
                profile=traffic_profile,
                duration=int(duration),
                port=int(port),
            ),
            capture_filter=capture_filter,
            configuration_id=None,
            security_posture=None,
        )
        if config_id is not None:
            expected = self._with_configuration_id(expected, config_id)
        else:
            expected = self._with_derived_configuration_id(expected)
        if security_posture is not None:
            expected = self._with_posture(expected, security_posture)
        return expected, variable_sources

    def _resolve_traffic_capture_value(
        self,
        variable,
        traffic,
        key,
        traffic_prefix,
        run_id,
        sequence,
        experiment_id,
    ):
        """Sample/campaign/metadata override > run_options > documented defaults."""
        if key in traffic and traffic[key] is not None:
            value = traffic[key]
            if variable == "traffic.duration":
                value = float(value)
            elif variable == "traffic.port":
                value = int(value)
            return value, STATUS_MAPPED, f"{traffic_prefix}.{key}"
        if key in self.run_options and self.run_options[key] is not None:
            value = self.run_options[key]
            if variable == "traffic.duration":
                value = float(value)
            elif variable == "traffic.port":
                value = int(value)
            return value, STATUS_MAPPED_WITH_NORMALIZATION, f"run_options.{key}"
        if variable == "traffic.duration":
            return (
                SOURCE_DEFAULTS["traffic.duration"],
                STATUS_MAPPED_WITH_NORMALIZATION,
                "source_default.controller.traffic.DEFAULT_DURATION (setdefault semantics)",
            )
        if variable == "traffic.port":
            return (
                SOURCE_DEFAULTS["traffic.port"],
                STATUS_MAPPED_WITH_NORMALIZATION,
                "source_default.controller.traffic.DEFAULT_PORT (setdefault semantics)",
            )
        return (
            SOURCE_DEFAULTS["capture_filter"],
            STATUS_MAPPED_WITH_NORMALIZATION,
            "source_default.controller.capture.DEFAULT_CAPTURE_FILTER (setdefault semantics)",
        )

    def _validate_ipsec_coupling(
        self, esp_encryption, esp_integrity, run_id, sequence, experiment_id
    ):
        gcm = esp_encryption is not None and str(esp_encryption).endswith("gcm16")
        if gcm and esp_integrity is not None:
            raise ExpectedStateMaterializationError(
                f"source GCM configuration specifies a separate integrity "
                f"algorithm ({esp_integrity!r}); repository rule: GCM must not "
                f"specify one (validate_config)",
                run_id=run_id,
                sequence=sequence,
                experiment_id=experiment_id,
                missing_variable="esp.integrity",
            )
        if not gcm and esp_integrity is None:
            raise ExpectedStateMaterializationError(
                f"source configuration has no integrity algorithm for "
                f"{esp_encryption!r}; repository rule: CBC ESP requires an "
                f"integrity algorithm (validate_config)",
                run_id=run_id,
                sequence=sequence,
                experiment_id=experiment_id,
                missing_variable="esp.integrity",
            )

    def _with_configuration_id(self, expected: ExpectedState, config_id: str) -> ExpectedState:
        return ExpectedState(
            mode=expected.mode,
            address_family=expected.address_family,
            ike=expected.ike,
            esp=expected.esp,
            traffic=expected.traffic,
            capture_filter=expected.capture_filter,
            configuration_id=config_id,
            security_posture=expected.security_posture,
        )

    def _with_derived_configuration_id(self, expected: ExpectedState) -> ExpectedState:
        return self._with_configuration_id(
            expected, expected.derive_configuration_id()
        )

    def _with_posture(self, expected: ExpectedState, posture: str) -> ExpectedState:
        return ExpectedState(
            mode=expected.mode,
            address_family=expected.address_family,
            ike=expected.ike,
            esp=expected.esp,
            traffic=expected.traffic,
            capture_filter=expected.capture_filter,
            configuration_id=expected.configuration_id,
            security_posture=posture,
        )

    # ------------------------------------------------------------------
    # reporting helpers
    # ------------------------------------------------------------------

    def check_all_canonical_variables(
        self, expected: ExpectedState
    ) -> Tuple[str, ...]:
        """Return canonical variables whose value is None (for tests/reports).

        ``esp.integrity`` is considered present when it is an allowed value OR
        when the ciphersuite is an AEAD/GCM cipher for which a null integrity
        is the documented, legitimate ``esp.integrity: null`` value (Phase 1:
        ALLOWED_ESP_INTEGRITY includes None for GCM).
        """
        null_integrity_ok = getattr(expected.esp, "encryption", None) in (
            "aes128gcm16",
            "aes256gcm16",
        )
        values = {
            "mode": expected.mode,
            "address_family": expected.address_family,
            "ike.version": expected.ike.version,
            "ike.encryption": expected.ike.encryption,
            "ike.integrity": expected.ike.integrity,
            "ike.dh_group": expected.ike.dh_group,
            "esp.encryption": expected.esp.encryption,
            "esp.integrity": expected.esp.integrity,
            "esp.dh_group": expected.esp.dh_group,
            "esp.pfs": expected.esp.pfs,
            "traffic.profile": expected.traffic.profile,
            "traffic.duration": expected.traffic.duration,
            "traffic.port": expected.traffic.port,
            "capture_filter": expected.capture_filter,
        }

        def _present(variable: str) -> bool:
            value = values[variable]
            if value is not None:
                return True
            if variable == "esp.integrity" and null_integrity_ok:
                return True
            return False

        return tuple(v for v in CANONICAL_VARIABLES if not _present(v))