"""
AegisDPI — ML Model & Feature Aggregator
Handles sliding-window feature aggregation, IsolationForest inference,
sigmoid confidence calibration, and feature contribution attribution.
"""

import os
import json
import math
import joblib
import numpy as np
from typing import Optional, Tuple, List, Dict, Any

FEATURE_NAMES = [
    "packets_per_second",
    "unique_dst_ports",
    "unique_dst_ips",
    "dropped_ratio",
    "protocol_diversity",
]

def aggregate_features(events: List[Dict[str, Any]], window_seconds: float = 5.0) -> Dict[str, float]:
    """
    Computes feature vector over a sliding window of events for a single source_ip:
      - packets_per_second: event count in window / window_seconds
      - unique_dst_ports: count of distinct dst_port values in window
      - unique_dst_ips: count of distinct dst_ip values in window
      - dropped_ratio: fraction of events in window with action == 'dropped'
      - protocol_diversity: count of distinct protocol values in window
    """
    total_events = len(events)
    if total_events == 0:
        return {name: 0.0 for name in FEATURE_NAMES}

    # 1. packets_per_second
    pps = total_events / max(window_seconds, 1.0)

    # 2. unique_dst_ports
    ports = set()
    for e in events:
        try:
            ports.add(int(e.get("dst_port", 0)))
        except (ValueError, TypeError):
            ports.add(0)
    unique_dst_ports = len(ports)

    # 3. unique_dst_ips
    ips = {str(e.get("dst_ip", "")) for e in events if e.get("dst_ip")}
    unique_dst_ips = max(len(ips), 1)

    # 4. dropped_ratio
    dropped_count = sum(1 for e in events if str(e.get("action", "")).lower() == "dropped")
    dropped_ratio = dropped_count / total_events

    # 5. protocol_diversity
    protos = {str(e.get("protocol", "0")) for e in events}
    protocol_diversity = len(protos)

    return {
        "packets_per_second": float(round(pps, 2)),
        "unique_dst_ports": float(unique_dst_ports),
        "unique_dst_ips": float(unique_dst_ips),
        "dropped_ratio": float(round(dropped_ratio, 4)),
        "protocol_diversity": float(protocol_diversity),
    }

class AnomalyModel:
    def __init__(self, model_path: str, baselines_path: str, meta_path: Optional[str] = None):
        self.model_path = model_path
        self.baselines_path = baselines_path
        self.meta_path = meta_path or os.path.join(os.path.dirname(model_path), "model_meta.json")
        self.model = None
        self.baselines: Dict[str, float] = {}
        self.meta: Dict[str, Any] = {}

    def load(self):
        """Loads model.joblib, baselines.json, and optional model_meta.json."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found at: {self.model_path}")
        if not os.path.exists(self.baselines_path):
            raise FileNotFoundError(f"Baselines file not found at: {self.baselines_path}")

        self.model = joblib.load(self.model_path)
        with open(self.baselines_path, "r") as f:
            self.baselines = json.load(f)

        if os.path.exists(self.meta_path):
            try:
                with open(self.meta_path, "r") as f:
                    self.meta = json.load(f)
            except Exception:
                self.meta = {}
        else:
            self.meta = {}

    def is_loaded(self) -> bool:
        return self.model is not None and len(self.baselines) > 0

    def score(
        self,
        features: Dict[str, float]
    ) -> Tuple[float, float, Optional[str], List[Dict[str, Any]], str]:
        """
        Runs IsolationForest decision_function, converts to 0.0-1.0 confidence via sigmoid,
        classifies verdict, and calculates normalized feature contributions.

        Returns:
            (raw_score, confidence, verdict, feature_contributions, description)
        """
        if not self.is_loaded():
            raise RuntimeError("Model is not loaded.")

        vector = [float(features.get(name, self.baselines.get(name, 0.0))) for name in FEATURE_NAMES]
        raw_score = float(self.model.decision_function([vector])[0])

        # Sigmoid calibration:
        # IsolationForest decision_function returns positive values for normal instances (~+0.10 to +0.25)
        # and negative values for statistical outliers (~ -0.05 to -0.30).
        # When a severe single-dimension attack occurs (e.g. 500 pps flood on a single port),
        # the other normal dimensions can partially dilute the tree splits.
        # We compute relative deviations to account for extreme single-feature spikes.
        deviations = []
        for name in FEATURE_NAMES:
            val = float(features.get(name, 0.0))
            base = float(self.baselines.get(name, 1.0))
            dev = abs(val - base) / max(base, 0.001)
            deviations.append((name, val, base, dev))

        max_rel_dev = max(d[3] for d in deviations) if deviations else 0.0
        effective_score = raw_score
        if max_rel_dev > 4.0:
            # Adjust effective score for extreme anomalies (>4x baseline)
            effective_score -= min((max_rel_dev - 4.0) * 0.015, 0.25)

        k = 12.0
        confidence = 1.0 / (1.0 + math.exp(effective_score * k))

        # Verdict classification
        if confidence >= 0.85:
            verdict = "ANOMALOUS"
        elif confidence >= 0.60:
            verdict = "SUSPICIOUS"
        else:
            verdict = None

        total_dev = sum(d[3] for d in deviations)
        feature_contributions: List[Dict[str, Any]] = []

        for name, val, base, dev in deviations:
            if total_dev > 0:
                pct = round((dev / total_dev) * 100.0, 1)
            else:
                pct = 20.0
            is_ratio = "ratio" in name.lower()
            feature_contributions.append({
                "name": name,
                "value": round(val, 4) if is_ratio else round(val, 2),
                "baseline": round(base, 4) if is_ratio else round(base, 2),
                "contribution_pct": pct,
            })

        # Sort descending by contribution percentage
        feature_contributions.sort(key=lambda x: x["contribution_pct"], reverse=True)
        top_feature = feature_contributions[0]

        # Generate descriptive sentence referencing top contributing feature
        feat_name_human = top_feature["name"].replace("_", " ")
        if verdict == "ANOMALOUS":
            description = (
                f"Volumetric flood pattern detected: abnormal {feat_name_human} "
                f"({top_feature['value']} vs baseline {top_feature['baseline']}) with {round(confidence * 100, 1)}% confidence"
            )
        elif verdict == "SUSPICIOUS":
            description = (
                f"Suspicious traffic pattern: elevated {feat_name_human} "
                f"({top_feature['value']} vs baseline {top_feature['baseline']}) with {round(confidence * 100, 1)}% confidence"
            )
        else:
            description = (
                f"Normal traffic profile: {feat_name_human} ({top_feature['value']} vs baseline {top_feature['baseline']})"
            )

        return raw_score, confidence, verdict, feature_contributions, description
