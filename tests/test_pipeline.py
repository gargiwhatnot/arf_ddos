"""Fast local tests for the shared feature/controller pipeline."""

from __future__ import annotations

import sys
import tempfile
import pickle
from pathlib import Path
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_ROOT))

from shared.attack_type_features import ATTACK_TYPE_FEATURES, build_attack_type_features
from shared.pipeline import CANONICAL_FEATURES, canonicalize_row
from shared.preprocessing import StandardFeatureScaler
from shared.arf_runtime import ARFDetector
from Controller.preprocessing import Preprocessor


class PipelineTests(unittest.TestCase):
    def test_dataset_row_maps_to_live_schema(self):
        row = canonicalize_row(
            {
                "Total Fwd Packets": 10,
                "Total Backward Packets": 2,
                "Total Length of Fwd Packets": 1000,
                "Total Length of Bwd Packets": 200,
                "Flow Duration": 2_000_000,
                "SYN Flag Count": 1,
                "Label": "BENIGN",
            }
        )
        self.assertEqual(set(row), set(CANONICAL_FEATURES))
        self.assertEqual(row["count"], 12.0)
        self.assertEqual(row["bytes"], 1200.0)
        self.assertEqual(row["duration"], 2.0)
        self.assertEqual(row["syn_count"], 1.0)

    def test_scaler_fits_and_round_trips(self):
        rows = [
            {"count": 10, "bytes": 1000, "duration": 1},
            {"count": 20, "bytes": 3000, "duration": 3},
            {"count": 30, "bytes": 5000, "duration": 5},
        ]
        scaler = StandardFeatureScaler().fit(rows)
        transformed = scaler.transform_many(rows)

        self.assertAlmostEqual(sum(row["count"] for row in transformed), 0.0)
        self.assertAlmostEqual(sum(row["bytes"] for row in transformed), 0.0)
        self.assertTrue(all(set(row) == set(CANONICAL_FEATURES) for row in transformed))

        restored = StandardFeatureScaler.from_dict(scaler.to_dict())
        self.assertEqual(restored.transform(rows[0]), transformed[0])

    def test_constant_features_use_safe_unit_scale(self):
        scaler = StandardFeatureScaler().fit(
            [{"count": 5, "bytes_norm": 2}, {"count": 5, "bytes_norm": 2}]
        )
        row = scaler.transform({"count": 5, "bytes_norm": 2})
        self.assertEqual(row["count"], 0.0)
        self.assertEqual(row["bytes_norm"], 0.0)

    def test_controller_uses_the_saved_scaler(self):
        rows = [
            {"count": 10, "bytes": 1000, "duration": 1},
            {"count": 20, "bytes": 3000, "duration": 3},
            {"count": 30, "bytes": 5000, "duration": 5},
        ]
        scaler = StandardFeatureScaler().fit(rows)
        controller_row = Preprocessor(scaler).normalize(rows[1])
        offline_row = scaler.transform(rows[1])
        self.assertEqual(controller_row, offline_row)

    def test_runtime_rejects_raw_legacy_checkpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "legacy.pkl"
            with checkpoint.open("wb") as handle:
                pickle.dump(object(), handle)
            with self.assertRaisesRegex(ValueError, "Unsupported raw River ARF"):
                ARFDetector(checkpoint)

    def test_attack_type_adapter_builds_complete_schema(self):
        features = build_attack_type_features(
            {"duration": 2.0, "ack_count": 4, "rst_count": 1},
            fwd_lengths=[100, 200],
            bwd_lengths=[50],
            all_iats_seconds=[0.5, 1.0],
            fwd_iats_seconds=[0.5],
            bwd_iats_seconds=[1.0],
        )
        self.assertEqual(set(features), set(ATTACK_TYPE_FEATURES))
        self.assertEqual(len(features), 31)
        self.assertEqual(features["flow_duration"], 2_000_000.0)
        self.assertEqual(features["total_fwd_packets"], 2.0)
        self.assertEqual(features["total_backward_packets"], 1.0)
        self.assertEqual(features["flow_bytes/s"], 175.0)
        self.assertEqual(features["fwd_iat_mean"], 500_000.0)


if __name__ == "__main__":
    unittest.main()
