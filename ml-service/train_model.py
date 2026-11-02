"""
AegisDPI — ML Model Training Script
Fits an IsolationForest on synthetic normal traffic feature vectors and saves:
  1. model.joblib — Scikit-Learn IsolationForest model artifact
  2. baselines.json — Feature mean baseline values for deviation calculation
"""

import os
import json
from datetime import datetime, timezone
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

FEATURE_NAMES = [
    "packets_per_second",
    "unique_dst_ports",
    "unique_dst_ips",
    "dropped_ratio",
    "protocol_diversity",
]

def generate_synthetic_normal_data(n_samples: int = 1000, random_state: int = 42) -> np.ndarray:
    """
    Generate synthetic feature vectors representative of normal network traffic:
    Cluster 1 (~60%): Lab-style single-destination traffic (1-2 dst IPs).
    Cluster 2 (~40%): Realistic web browsing traffic with multi-destination connections (2-6 dst IPs).
      - packets_per_second: moderate rates (5-35 pps)
      - unique_dst_ports: 1-3 ports (DNS/HTTP/HTTPS)
      - unique_dst_ips: 1-2 IPs (lab) vs 2-6 IPs (browsing)
      - dropped_ratio: near zero (0.00 - 0.05)
      - protocol_diversity: 1-2 protocols (primarily TCP/TLS, occasional UDP/DNS)
    """
    rng = np.random.default_rng(random_state)
    
    n_lab = int(n_samples * 0.60)
    n_browsing = n_samples - n_lab
    
    # ── Cluster 1: Lab-Style (Single/Dual Destination) ──
    # 1. packets_per_second: normal dist around 12.0 pps, clipped to 1.0 - 35.0
    pps_lab = np.clip(rng.normal(loc=12.0, scale=4.0, size=n_lab), 1.0, 35.0)
    # 2. unique_dst_ports: 1 port (75%), 2 ports (20%), 3 ports (5%)
    dst_ports_lab = rng.choice([1, 2, 3], size=n_lab, p=[0.75, 0.20, 0.05])
    # 3. unique_dst_ips: 1 IP (90%), 2 IPs (10%)
    dst_ips_lab = rng.choice([1, 2], size=n_lab, p=[0.90, 0.10])
    # 4. dropped_ratio: low exponential, clipped to max 0.05
    dropped_ratio_lab = np.clip(rng.exponential(scale=0.005, size=n_lab), 0.0, 0.05)
    # 5. protocol_diversity: 1 proto (92%), 2 protos (8%)
    protocol_diversity_lab = rng.choice([1, 2], size=n_lab, p=[0.92, 0.08])

    X_lab = np.column_stack([pps_lab, dst_ports_lab, dst_ips_lab, dropped_ratio_lab, protocol_diversity_lab])

    # ── Cluster 2: Realistic Web Browsing (Multi-Destination) ──
    # 1. packets_per_second: similar range (5-35 pps)
    pps_browsing = np.clip(rng.normal(loc=16.0, scale=5.0, size=n_browsing), 5.0, 35.0)
    # 2. unique_dst_ports: 1-3 ports (DNS/HTTP/HTTPS)
    dst_ports_browsing = rng.choice([1, 2, 3], size=n_browsing, p=[0.60, 0.30, 0.10])
    # 3. unique_dst_ips: 2-6 IPs (wider range reflecting real multi-destination connections)
    dst_ips_browsing = rng.choice([2, 3, 4, 5, 6], size=n_browsing, p=[0.35, 0.30, 0.20, 0.10, 0.05])
    # 4. dropped_ratio: near zero
    dropped_ratio_browsing = np.clip(rng.exponential(scale=0.005, size=n_browsing), 0.0, 0.05)
    # 5. protocol_diversity: 1-2 protocols (unchanged)
    protocol_diversity_browsing = rng.choice([1, 2], size=n_browsing, p=[0.90, 0.10])

    X_browsing = np.column_stack([pps_browsing, dst_ports_browsing, dst_ips_browsing, dropped_ratio_browsing, protocol_diversity_browsing])

    # Concatenate both clusters into final combined training array
    X = np.vstack([X_lab, X_browsing])
    return X

def train_and_save():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(base_dir, "model.joblib")
    baselines_path = os.path.join(base_dir, "baselines.json")
    
    print("[TRAIN] Generating 1,000 synthetic normal traffic feature vectors (60% lab, 40% browsing)...")
    X_train = generate_synthetic_normal_data(1000, random_state=42)
    
    print("[TRAIN] Fitting IsolationForest(contamination=0.05, random_state=42)...")
    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X_train)
    
    # Calculate baseline means from FULL combined training set
    means = np.mean(X_train, axis=0)
    baselines = {
        name: float(round(means[i], 4))
        for i, name in enumerate(FEATURE_NAMES)
    }
    
    print(f"[TRAIN] Calculated feature baselines: {json.dumps(baselines, indent=2)}")
    
    # Save model
    joblib.dump(clf, model_path)
    print(f"[TRAIN] Saved model to: {model_path}")
    
    # Save baselines
    with open(baselines_path, "w") as f:
        json.dump(baselines, f, indent=2)
    print(f"[TRAIN] Saved baselines to: {baselines_path}")

    # Save model metadata
    meta_path = os.path.join(base_dir, "model_meta.json")
    meta = {
        "n_training_samples": int(len(X_train)),
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"[TRAIN] Saved model metadata to: {meta_path}")
    
    print("[TRAIN] Training complete.")

if __name__ == "__main__":
    train_and_save()
