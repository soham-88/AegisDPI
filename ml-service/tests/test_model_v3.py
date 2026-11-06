"""
Unit tests for AnomalyModelV3 (model_v3.py)
"""

import math
import unittest
from pathlib import Path

from model_v3 import GUARD_FEATURES, AnomalyModelV3


class TestModelV3(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        models_dir = Path(__file__).resolve().parent.parent / "models" / "v3"
        cls.model = AnomalyModelV3(str(models_dir))
        cls.model.load()

    def _get_median_features(self):
        return {
            name: stats["median"]
            for name, stats in self.model.base_model.feature_stats.items()
        }

    def test_guard_fires_on_high_udp_rate(self):
        # Median features + high UDP rate (limit is 10.0 UDP pkts/s)
        features = self._get_median_features()
        udp_limit = self.model.limit_raw["log_udp_rate"]

        # Set UDP rate well above limit (e.g. 50 pps)
        high_udp = udp_limit + 40.0
        features["log_udp_rate"] = math.log1p(high_udp)

        raw_score, conf, verdict, contribs, desc = self.model.score(features)

        self.assertEqual(verdict, "ANOMALOUS")
        self.assertEqual(conf, 1.0)
        self.assertEqual(self.model.last_trigger, "guard")
        self.assertGreater(raw_score, 1.0)

    def test_does_not_fire_at_exactly_the_limit(self):
        # Median features + UDP rate set exactly to limit
        features = self._get_median_features()
        udp_limit = self.model.limit_raw["log_udp_rate"]

        features["log_udp_rate"] = math.log1p(udp_limit)

        raw_score, conf, verdict, contribs, desc = self.model.score(features)

        # At exactly the limit (ratio == 1.0), guard must NOT fire
        self.assertNotEqual(verdict, "ANOMALOUS")
        self.assertNotEqual(self.model.last_trigger, "guard")

    def test_anomaly_index_ge_1_iff_anomalous_when_if_below_threshold(self):
        features = self._get_median_features()
        udp_limit = self.model.limit_raw["log_udp_rate"]

        # 1. Just below limit (0.95 * limit)
        features["log_udp_rate"] = math.log1p(udp_limit * 0.95)
        raw_score_below, _, verdict_below, _, _ = self.model.score(features)
        self.assertLess(raw_score_below, 1.0)
        self.assertNotEqual(verdict_below, "ANOMALOUS")

        # 2. Just above limit (1.05 * limit)
        features["log_udp_rate"] = math.log1p(udp_limit * 1.05)
        raw_score_above, _, verdict_above, _, _ = self.model.score(features)
        self.assertGreater(raw_score_above, 1.0)
        self.assertEqual(verdict_above, "ANOMALOUS")

    def test_description_names_guard_feature(self):
        features = self._get_median_features()
        udp_limit = self.model.limit_raw["log_udp_rate"]
        features["log_udp_rate"] = math.log1p(udp_limit + 50.0)

        _, _, verdict, _, desc = self.model.score(features)
        self.assertEqual(verdict, "ANOMALOUS")

        expected_human_name = GUARD_FEATURES["log_udp_rate"][1]
        self.assertIn(expected_human_name, desc)
        self.assertIn("vs normal max", desc)
        self.assertIn("(limit", desc)


if __name__ == "__main__":
    unittest.main()

