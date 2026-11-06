"""
AegisDPI — ML Model v3 (AnomalyModelV3)
Combines v2 IsolationForest inference with a learned per-feature envelope guard.
"""

import json
import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from features_v2 import FEATURE_NAMES_V2
from model_v2 import AnomalyModelV2

# Guard features and margins are FIXED CONSTANTS
# chosen before evaluating v3; not tuned on test data
GUARD_FEATURES = {
    "log_syn_rate":         ("rate",  "SYN packets/sec"),
    "log_rst_rate":         ("rate",  "RST packets/sec"),
    "log_icmp_echo_rate":   ("rate",  "ICMP echo requests/sec"),
    "log_udp_rate":         ("rate",  "UDP packets/sec"),
    "log_unique_dst_ports": ("count", "distinct destination ports (5 s)"),
    "log_unique_src_ports": ("count", "distinct source ports (5 s)"),
}
GUARD_MULTIPLIER = 3.0
GUARD_MARGIN = {"rate": 10.0, "count": 10.0}


class AnomalyModelV3:
    """
    ML Detector v3:
    - Base IsolationForest model (v2) on traffic shape features.
    - Learned per-feature envelope guard on log1p features (converted with expm1).
    - Anomaly index = max(if_score / threshold_anomalous_v2, max_guard_ratio).
    - Verdict: ANOMALOUS if if_verdict == 'ANOMALOUS' or max_guard_ratio > 1.0;
               else SUSPICIOUS if if_verdict == 'SUSPICIOUS'; else None.
    - Confidence: 1.0 if guard fired, else base if_conf.
    - Tracks last_trigger in {"guard", "iforest", "both", None}.
    """

    def __init__(self, model_dir: Optional[str] = None):
        if model_dir is None:
            script_dir = Path(__file__).resolve().parent
            model_dir = str(script_dir / "models" / "v3")
        self.model_dir = Path(model_dir)
        self.base_model: Optional[AnomalyModelV2] = None
        self.meta: Dict[str, Any] = {}
        self.normal_max_raw: Dict[str, float] = {}
        self.limit_raw: Dict[str, float] = {}
        self.threshold_anomalous_v2: float = 0.0
        self.threshold_suspicious_v2: float = 0.0
        self.last_trigger: Optional[str] = None

    def load(self):
        """Loads meta.json and the underlying v2 model from base_model_dir."""
        meta_path = self.model_dir / "meta.json"
        if not meta_path.exists():
            raise FileNotFoundError(f"v3 meta.json not found at: {meta_path}")

        with open(meta_path, "r", encoding="utf-8") as f:
            self.meta = json.load(f)

        base_model_dir = self.meta.get("base_model_dir", "models/v2")
        # Resolve base_model_dir
        base_dir_path = Path(base_model_dir)
        if not base_dir_path.is_absolute():
            # Check relative to model_dir parent
            candidates = [
                self.model_dir.parent / base_dir_path.name,
                self.model_dir / base_dir_path,
                self.model_dir.parent.parent / base_model_dir,
                Path(__file__).resolve().parent / base_model_dir,
            ]
            for c in candidates:
                if (c / "model.joblib").exists():
                    base_dir_path = c
                    break

        self.base_model = AnomalyModelV2(str(base_dir_path))
        self.base_model.load()

        self.threshold_anomalous_v2 = self.base_model.threshold_anomalous
        self.threshold_suspicious_v2 = self.base_model.threshold_suspicious

        if self.threshold_anomalous_v2 <= 0:
            print("Warning: threshold_anomalous_v2 <= 0, using only guard component for anomaly index")

        self.normal_max_raw = {
            k: float(v) for k, v in self.meta.get("normal_max_raw", {}).items()
        }
        self.limit_raw = {
            k: float(v) for k, v in self.meta.get("limit_raw", {}).items()
        }

    def is_loaded(self) -> bool:
        return (
            self.base_model is not None
            and self.base_model.is_loaded()
            and len(self.limit_raw) > 0
        )

    def score(
        self, features: Dict[str, float]
    ) -> Tuple[float, float, Optional[str], List[Dict[str, Any]], str]:
        """
        Runs v3 inference combining v2 IsolationForest and envelope guard.

        Returns:
            (raw_score, confidence, verdict, feature_contributions, description)
        """
        if not self.is_loaded():
            raise RuntimeError("AnomalyModelV3 is not loaded.")

        # 1. Base v2 IsolationForest scoring
        if_score, if_conf, if_verdict, if_contribs, if_desc = self.base_model.score(features)

        # 2. Envelope guard evaluation
        max_guard_ratio = 0.0
        max_guard_feat = None
        guard_entries = []

        for feat, (kind, human_name) in GUARD_FEATURES.items():
            raw_log_val = float(features.get(feat, 0.0))
            raw_val = math.expm1(raw_log_val)
            limit = float(self.limit_raw.get(feat, 0.0))
            norm_max = float(self.normal_max_raw.get(feat, 0.0))

            # Snap tiny floating-point roundoff (e.g. expm1(log1p(x)) ~= x + 1e-15)
            if limit > 0 and abs(raw_val - limit) < 1e-9:
                raw_val = limit

            ratio = (raw_val / limit) if limit > 0 else 0.0

            if ratio > max_guard_ratio:
                max_guard_ratio = ratio
                max_guard_feat = feat

            if ratio > 0.5:
                guard_entries.append({
                    "feature": feat,
                    "human_name": human_name,
                    "raw_value": round(raw_val, 2),
                    "normal_max": round(norm_max, 2),
                    "limit": round(limit, 2),
                    "ratio": round(ratio, 4),
                })

        # 3. Anomaly index & raw_score
        if self.threshold_anomalous_v2 > 0:
            if_ratio = if_score / self.threshold_anomalous_v2
            anomaly_index = max(if_ratio, max_guard_ratio)
        else:
            anomaly_index = max_guard_ratio
        raw_score = anomaly_index

        # 4. Trigger & verdict determination
        guard_fired = max_guard_ratio > 1.0
        iforest_fired = if_verdict == "ANOMALOUS"

        if guard_fired and iforest_fired:
            self.last_trigger = "both"
        elif guard_fired:
            self.last_trigger = "guard"
        elif iforest_fired:
            self.last_trigger = "iforest"
        else:
            self.last_trigger = None

        if if_verdict == "ANOMALOUS" or guard_fired:
            verdict = "ANOMALOUS"
        elif if_verdict == "SUSPICIOUS":
            verdict = "SUSPICIOUS"
        else:
            verdict = None

        # 5. Confidence
        confidence = 1.0 if guard_fired else if_conf

        # 6. Feature contributions
        feature_contributions = list(if_contribs)
        if guard_entries:
            feature_contributions.append({
                "name": "guard",
                "guard": guard_entries,
                "guard_entries": guard_entries,
            })

        # 7. Description
        if guard_fired and max_guard_feat is not None:
            human_name = GUARD_FEATURES[max_guard_feat][1]
            val_raw = math.expm1(float(features.get(max_guard_feat, 0.0)))
            norm_max = self.normal_max_raw.get(max_guard_feat, 0.0)
            limit = self.limit_raw.get(max_guard_feat, 0.0)
            description = (
                f"{human_name} {round(val_raw, 1)} vs normal max {round(norm_max, 1)} "
                f"(limit {round(limit, 1)})"
            )
        else:
            description = if_desc

        return raw_score, confidence, verdict, feature_contributions, description
