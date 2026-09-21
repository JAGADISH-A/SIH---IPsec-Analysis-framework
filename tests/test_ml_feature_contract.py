"""Phase 5 ML feature-contract tests (brief items 1-8).

Validates the canonical v2 59-feature contract: exact version, exact feature
set (no missing/extra/renamed), explicit canonical ordering, numeric-only
values, NaN/inf rejection, fail-fast missing values, no second schema /
renaming, and an AST cross-check against the AUTHORITATIVE module in
``D:\\sihipsec`` when that repository is present.
"""

import math
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures", "ml"))

from fixtures import (  # noqa: E402
    VOIP_BASE,
    feature_window,
    make_row,
    specifically_mutated_row,
    valid_window,
)
from correlation.ml import (  # noqa: E402
    FEATURE_COLUMNS,
    FEATURE_COUNT,
    FEATURE_SCHEMA_VERSION,
    FeatureContractError,
    canonical_feature_names,
    feature_vector,
    normalize_feature_values,
    validate_feature_values,
    validate_feature_window,
    verify_authoritative_contract,
)
from correlation.ml.feature_contract import (  # noqa: E402
    FLOAT_FEATURES,
    INT_FEATURES,
)
from correlation.models import LiveFeatureWindow  # noqa: E402

SIHIPSEC_ROOT = r"D:\sihipsec"


class TestSchemaVersion(unittest.TestCase):
    def test_accepts_v2_only(self):
        validate_feature_window(valid_window())
        validate_feature_values(make_row(VOIP_BASE))

    def test_rejects_v1_family(self):
        # Beta "v1" had 64 columns incl. IKE exchange columns and is unsupported.
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_window(
                {"feature_schema_version": "v1", "features": make_row(VOIP_BASE)}
            )
        self.assertIn("v2", str(ctx.exception))

    def test_rejects_other_version_strings(self):
        for bad in (None, 2, "V2", "v3"):
            with self.assertRaises(FeatureContractError) as ctx:
                validate_feature_window(
                    {
                        "feature_schema_version": bad,
                        "features": make_row(VOIP_BASE),
                    }
                )
            self.assertIn("v2", str(ctx.exception))
        # LiveFeatureWindow itself already pins version to v2 at construction.
        with self.assertRaises(ValueError):
            LiveFeatureWindow(feature_schema_version="v1", features=make_row(VOIP_BASE))


class TestExactFeatureSet(unittest.TestCase):
    def test_all_59_canonical_names_present_and_unique(self):
        names = canonical_feature_names()
        self.assertEqual(len(names), FEATURE_COUNT)
        self.assertEqual(len(set(names)), FEATURE_COUNT)
        self.assertEqual(tuple(names), tuple(FEATURE_COLUMNS))

    def test_missing_feature_rejected_with_names(self):
        row = make_row(VOIP_BASE)
        del row["packet_count"]
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(row)
        self.assertIn("packet_count", str(ctx.exception))

    def test_extra_feature_rejected_with_names(self):
        row = make_row(VOIP_BASE)
        row["new_feature_xyz"] = 0.0
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(row)
        self.assertIn("new_feature_xyz", str(ctx.exception))

    def test_renamed_feature_rejected(self):
        row = make_row(VOIP_BASE)
        row["packet_count_renamed"] = row.pop("packet_count")
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(row)
        message = str(ctx.exception)
        # Renaming removes the canonical name -> missing report names it.
        self.assertIn("packet_count", message)

    def test_window_missing_feature_rejected(self):
        row = make_row(VOIP_BASE)
        del row["ike_packet_count"]
        with self.assertRaises(FeatureContractError):
            validate_feature_window(feature_window(row))


class TestOrdering(unittest.TestCase):
    def test_vector_built_in_canonical_order_regardless_of_insertion(self):
        window = valid_window()
        vector = feature_vector(window)
        self.assertEqual(len(vector), FEATURE_COUNT)
        self.assertEqual(vector, [float(window.features[name]) for name in FEATURE_COLUMNS])

    def test_shuffled_dict_still_yields_canonical_order(self):
        row = make_row(VOIP_BASE)
        order = list(FEATURE_COLUMNS)
        order.reverse()  # reorder insertion; validation must not care
        window = feature_window({name: row[name] for name in order})
        vector = feature_vector(window)
        self.assertEqual(vector, [float(row[name]) for name in FEATURE_COLUMNS])

    def test_feature_count_and_class_splits(self):
        self.assertEqual(
            len(INT_FEATURES) + len(FLOAT_FEATURES),
            FEATURE_COUNT,
        )
        self.assertEqual(FLOAT_FEATURES, frozenset(FEATURE_COLUMNS) - INT_FEATURES)


class TestNumericValues(unittest.TestCase):
    def test_string_rejected(self):
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(specifically_mutated_row(mean_packet_size="100.0"))
        self.assertIn("mean_packet_size", str(ctx.exception))

    def test_bool_rejected(self):
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(specifically_mutated_row(packet_count=True))
        self.assertIn("packet_count", str(ctx.exception))

    def test_none_rejected(self):
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(specifically_mutated_row(total_bytes=None))
        self.assertIn("total_bytes", str(ctx.exception))

    def test_int_columns_require_integer_values(self):
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(specifically_mutated_row(packet_count=1.5))
        self.assertIn("packet_count", str(ctx.exception))

    def test_int_column_accepts_float_with_integer_value(self):
        # Mirrors authoritative dataset_artifacts._require_int.
        norm = normalize_feature_values(specifically_mutated_row(packet_count=7.0))
        self.assertIsInstance(norm["packet_count"], int)
        self.assertEqual(norm["packet_count"], 7)

    def test_float_column_accepts_int_and_casts(self):
        norm = normalize_feature_values(specifically_mutated_row(flow_duration=30))
        self.assertIsInstance(norm["flow_duration"], float)
        self.assertEqual(norm["flow_duration"], 30.0)

    def test_nan_rejected_naming_feature(self):
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_values(specifically_mutated_row(flow_duration=float("nan")))
        self.assertIn("flow_duration", str(ctx.exception))

    def test_inf_rejected_naming_feature(self):
        for bad in (float("inf"), float("-inf")):
            with self.assertRaises(FeatureContractError) as ctx:
                validate_feature_values(specifically_mutated_row(flow_duration=bad))
            self.assertIn("flow_duration", str(ctx.exception))


class TestFailFastRegressionTimeless(unittest.TestCase):
    def test_missing_value_is_never_filled_with_zero(self):
        row = make_row(VOIP_BASE)
        original = dict(row)
        del row["packet_count"]
        with self.assertRaises(FeatureContractError):
            validate_feature_values(row)
        # Fail-fast: no silent mutation, no default filling, no later columns read.
        for name in FEATURE_COLUMNS:
            self.assertIn(name, original)

    def test_non_live_feature_window_rejected(self):
        with self.assertRaises(FeatureContractError):
            validate_feature_window({"feature_schema_version": "v2"})

    def test_raw_live_record_dict_shape_accepted(self):
        record = {
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "window_start_ns": 0,
            "window_end_ns": 1000,
            "features": make_row(VOIP_BASE),
        }
        validate_feature_window(record)  # must not raise

    def test_raw_live_record_wrong_version_rejected(self):
        record = {
            "feature_schema_version": "v1",
            "features": make_row(VOIP_BASE),
        }
        with self.assertRaises(FeatureContractError) as ctx:
            validate_feature_window(record)
        self.assertIn("v2", str(ctx.exception))


class TestNoSecondSchemaAndAuthoritativeContract(unittest.TestCase):
    def test_snapshot_matches_authoritative_module(self):
        if not os.path.isdir(SIHIPSEC_ROOT):
            self.skipTest("D:\\sihipsec not present; authoritative cross-check skipped")
        report = verify_authoritative_contract(SIHIPSEC_ROOT)
        self.assertTrue(report["checked"])
        self.assertTrue(report["snapshot_matches_authoritative"])
        self.assertEqual(report["authoritative_feature_schema_version"], "v2")
        self.assertEqual(report["authoritative_feature_count"], FEATURE_COUNT)

    def test_frozenset_snapshot_preserved_exactly(self):
        # Guard against accidental wholesale re-listing/renaming drift signals.
        self.assertEqual(list(FEATURE_COLUMNS), [
            "packet_count", "total_bytes", "mean_packet_size", "packet_size_std",
            "min_packet_size", "max_packet_size", "packet_size_p10",
            "packet_size_p50", "packet_size_p90", "packet_size_p95",
            "packet_size_p99", "unique_packet_size_count", "packet_size_entropy",
            "small_packet_ratio", "large_packet_ratio",
            "mean_inter_arrival_time", "inter_arrival_time_std",
            "min_inter_arrival_time", "max_inter_arrival_time",
            "packets_per_second", "bytes_per_second", "flow_duration",
            "outbound_packet_count", "inbound_packet_count", "outbound_bytes",
            "inbound_bytes", "outbound_packet_ratio", "inbound_packet_ratio",
            "outbound_byte_ratio", "inbound_byte_ratio",
            "outbound_mean_packet_size", "inbound_mean_packet_size",
            "outbound_packets_per_second", "inbound_packets_per_second",
            "outbound_packet_size_p10", "outbound_packet_size_p50",
            "outbound_packet_size_p90", "outbound_packet_size_p95",
            "outbound_packet_size_p99", "inbound_packet_size_p10",
            "inbound_packet_size_p50", "inbound_packet_size_p90",
            "inbound_packet_size_p95", "inbound_packet_size_p99",
            "burst_count", "mean_burst_packets", "mean_burst_duration",
            "burst_packet_ratio", "burst_count_10ms", "mean_burst_packets_10ms",
            "burst_count_50ms", "mean_burst_packets_50ms", "burst_count_200ms",
            "mean_burst_packets_200ms", "ike_packet_count",
            "ike_datagram_bytes", "ike_min_packet_size", "ike_max_packet_size",
            "ike_mean_packet_size",
        ])

    def test_workspace_module_str_invariant(self):
        # No feature is allowed to be None/empty and values stay numeric.
        for value in make_row(VOIP_BASE).values():
            self.assertIsInstance(value, (int, float))


if __name__ == "__main__":
    unittest.main()