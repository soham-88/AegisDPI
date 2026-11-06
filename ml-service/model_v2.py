"""
AegisDPI — ML Model v2 (AnomalyModelV2)
IsolationForest-based inference using shape features (features_v2),
calibrated empirical validation percentile confidence, and robust-z feature attributions.
"""

import bisect
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
from features_v2 import FEATURE_NAMES_V2

FEATURE_HUMAN_NAMES = {
    "log_pps": "packet rate",
    "log_syn_rate": "SYN packet rate",
    "syn_ratio": "SYN packet ratio",
    "log_rst_rate": "RST packet rate",
    "log_icmp_echo_rate": "ICMP echo rate",
    "log_udp_rate": "UDP packet rate",
    "log_unique_dst_ports": "destination port diversity",
    "log_unique_src_ports": "source port diversity",
    "log_pkts_per_flow": "packets per flow",
    "unique_dst_ips": "destination IP count",
}


class AnomalyModelV2:
    """
    ML Detector v2:
    - IsolationForest trained on 10 traffic shape features.
    - Anomaly score = -decision_function (continuous, higher = more anomalous).
    - Verdict thresholds calibrated on validation dataset.
    - Confidence = empirical percentile of validation scores strictly below the anomaly score.
    - Feature attribution using median and IQR (robust z-score).
    """

    def __init__(self, model_dir: Optional[str] = None):
        if model_dir is None:
            script_dir = Path(__file__).resolve().parent
            model_dir = str(script_dir / "models" / "v2")
        self.model_dir = Path(model_dir)
        self.model = None
        self.meta: Dict[str, Any] = {}
        self.feature_names: List[str] = FEATURE_NAMES_V2
        self.threshold_anomalous: float = 0.0
        self.threshold_suspicious: float = 0.0
        self.sorted_val_scores: List[float] = []
        self.feature_stats: Dict[str, Dict[str, float]] = {}

    def load(self):
        """Loads model.joblib and meta.json from model_dir."""
        model_path = self.model_dir / "model.joblib"
        meta_path = self.model_dir / "meta.json"

        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found at: {model_path}")
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found at: {meta_path}")

        self.model = joblib.load(model_path)
        with open(meta_path, "r", encoding="utf-8") as f:
            self.meta = json.load(f)

        self.feature_names = self.meta.get("feature_names", FEATURE_NAMES_V2)
        self.threshold_anomalous = float(self.meta.get("threshold_anomalous", 0.0))
        self.threshold_suspicious = float(self.meta.get("threshold_suspicious", 0.0))
        self.sorted_val_scores = [float(s) for s in self.meta.get("sorted_val_scores", [])]
        self.feature_stats = self.meta.get("feature_stats", {})

    def is_loaded(self) -> bool:
        return self.model is not None and len(self.sorted_val_scores) > 0

    def score(
        self, features: Dict[str, float]
    ) -> Tuple[float, float, Optional[str], List[Dict[str, Any]], str]:
        """
        Runs IsolationForest inference, computes empirical confidence, assigns verdict,
        and attributes feature contributions.

        Returns:
            (raw_score, confidence, verdict, feature_contributions, description)
        """
        if not self.is_loaded():
            raise RuntimeError("AnomalyModelV2 is not loaded.")

        vector = [
            float(features.get(name, self.feature_stats.get(name, {}).get("median", 0.0)))
            for name in self.feature_names
        ]

        # Anomaly score = -decision_function (higher = more anomalous)
        decision_val = float(self.model.decision_function([vector])[0])
        raw_score = -decision_val

        # Empirical percentile confidence: fraction of validation scores strictly below raw_score
        n_val = len(self.sorted_val_scores)
        if n_val > 0:
            rank = bisect.bisect_left(self.sorted_val_scores, raw_score)
            confidence = float(rank / n_val)
        else:
            confidence = 0.0

        # Verdict based on calibrated thresholds
        if raw_score > self.threshold_anomalous:
            verdict = "ANOMALOUS"
        elif raw_score > self.threshold_suspicious:
            verdict = "SUSPICIOUS"
        else:
            verdict = None

        # Robust z-score feature attribution
        z_scores = []
        for name in self.feature_names:
            val = float(features.get(name, 0.0))
            stats = self.feature_stats.get(name, {"median": 0.0, "iqr": 1e-6})
            median = stats.get("median", 0.0)
            iqr = max(stats.get("iqr", 1e-6), 1e-6)
            z = abs(val - median) / iqr
            z_scores.append((name, val, median, z))

        total_z = sum(item[3] for item in z_scores)
        feature_contributions = []
        for name, val, median, z in z_scores:
            pct = (
                round((z / total_z * 100.0), 1)
                if total_z > 0
                else round(100.0 / len(self.feature_names), 1)
            )
            feature_contributions.append({
                "name": name,
                "value": round(val, 4),
                "baseline": round(median, 4),
                "contribution_pct": pct,
                "robust_z": round(z, 2),
            })

        feature_contributions.sort(key=lambda x: x["contribution_pct"], reverse=True)
        top_feature = feature_contributions[0]

        # Human-readable explanation
        feat_name_human = FEATURE_HUMAN_NAMES.get(
            top_feature["name"], top_feature["name"].replace("_", " ")
        )
        pct_unusual = f"{round(confidence * 100, 1)}%"

        if verdict == "ANOMALOUS":
            description = (
                f"ANOMALOUS traffic: abnormal {feat_name_human} "
                f"({top_feature['value']} vs normal median {top_feature['baseline']}), "
                f"more unusual than {pct_unusual} of normal traffic windows"
            )
        elif verdict == "SUSPICIOUS":
            description = (
                f"SUSPICIOUS traffic: elevated {feat_name_human} "
                f"({top_feature['value']} vs normal median {top_feature['baseline']}), "
                f"more unusual than {pct_unusual} of normal traffic windows"
            )
        else:
            description = (
                f"Normal traffic: {feat_name_human} "
                f"({top_feature['value']} vs normal median {top_feature['baseline']}), "
                f"more unusual than {pct_unusual} of normal traffic windows"
            )

        return raw_score, confidence, verdict, feature_contributions, description

