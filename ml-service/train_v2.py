#!/usr/bin/env python3
"""
AegisDPI — ML Detector v2 Training Script
Trains an IsolationForest model on benign traffic features (features_v2)
and calibrates thresholds using empirical validation score percentiles.
"""

import argparse
import collections
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import joblib
import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from features_v2 import FEATURE_NAMES_V2, extract_features_v2
from offline_sim import simulate_windows


def get_git_commit_short(repo_dir: Path) -> str:
    """Returns short git commit hash of the repo, or 'unknown'."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(repo_dir),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "unknown"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train AegisDPI ML Detector v2 on benign traffic datasets."
    )
    parser.add_argument(
        "--train",
        required=True,
        type=str,
        help="Path to benign training dataset directory (e.g. ../datasets/benign-train)",
    )
    parser.add_argument(
        "--val",
        required=True,
        type=str,
        help="Path to benign validation dataset directory (e.g. ../datasets/benign-val)",
    )
    parser.add_argument(
        "--local-ips",
        type=str,
        default="10.10.0.1,10.255.255.254",
        help="Comma-separated list of local IPs",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="",
        help="Directory to save model.joblib and meta.json (default: models/v2)",
    )
    return parser.parse_args()


def load_dataset_vectors(
    dataset_dir: Path, local_ips: Set[str]
) -> Tuple[np.ndarray, Dict[str, int], str]:
    schedule_path = dataset_dir / "schedule.json"
    events_path = dataset_dir / "events.jsonl"

    if not events_path.exists():
        raise FileNotFoundError(f"events.jsonl not found in {dataset_dir}")

    dataset_name = dataset_dir.name
    if schedule_path.exists():
        try:
            with open(schedule_path, "r", encoding="utf-8") as f:
                sched = json.load(f)
                dataset_name = sched.get("name", dataset_name)
                # Augment local_ips if present in schedule
                for ip in sched.get("local_ips", []):
                    local_ips.add(ip)
        except Exception:
            pass

    events_list: List[Tuple[float, Dict[str, Any]]] = []
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                e = json.loads(line_str)
                events_list.append((float(e["ts"]), e))

    events_list.sort(key=lambda x: x[0])

    src_counts = collections.Counter()
    vectors: List[List[float]] = []

    for tick, src_ip, window_events in simulate_windows(
        events_list, local_ips, tick_interval=1.0, window_s=5.0, min_events=3
    ):
        feats = extract_features_v2(window_events, window_s=5.0)
        vec = [feats[name] for name in FEATURE_NAMES_V2]
        vectors.append(vec)
        src_counts[src_ip] += 1

    return np.array(vectors, dtype=float), dict(src_counts), dataset_name


def train_v2():
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent

    local_ips_set = {ip.strip() for ip in args.local_ips.split(",") if ip.strip()}

    train_path = Path(args.train).resolve()
    val_path = Path(args.val).resolve()

    # Safety guard: Never read mixed-test
    if "mixed" in str(train_path).lower() or "mixed" in str(val_path).lower():
        raise ValueError("Error: train_v2 must NEVER read mixed-test or mixed datasets.")

    print(f"Loading training dataset from:   {train_path}")
    X_train, train_counts, train_name = load_dataset_vectors(train_path, local_ips_set)
    print(f"  Training vectors: {len(X_train)} across sources: {train_counts}")

    print(f"Loading validation dataset from: {val_path}")
    X_val, val_counts, val_name = load_dataset_vectors(val_path, local_ips_set)
    print(f"  Validation vectors: {len(X_val)} across sources: {val_counts}")

    if len(X_train) == 0 or len(X_val) == 0:
        raise RuntimeError("Empty training or validation vectors.")

    # 2. Fit IsolationForest
    print("\nFitting IsolationForest(n_estimators=200, contamination='auto', random_state=42)...")
    clf = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train)

    # 3. Anomaly score = -decision_function (higher = more anomalous)
    val_scores = -clf.decision_function(X_val)
    threshold_anomalous = float(np.max(val_scores))
    threshold_suspicious = float(np.percentile(val_scores, 99))
    sorted_val_scores = [float(s) for s in sorted(val_scores.tolist())]

    # 4. Feature median and IQR (75th - 25th percentile, floored at 1e-6) on TRAINING vectors
    medians = np.median(X_train, axis=0)
    q75, q25 = np.percentile(X_train, [75, 25], axis=0)
    iqr = np.maximum(q75 - q25, 1e-6)

    feature_stats: Dict[str, Dict[str, float]] = {}
    for i, name in enumerate(FEATURE_NAMES_V2):
        feature_stats[name] = {
            "median": float(medians[i]),
            "iqr": float(iqr[i]),
        }

    # 5. Save model and metadata
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = script_dir / "models" / "v2"

    output_dir.mkdir(parents=True, exist_ok=True)
    model_file = output_dir / "model.joblib"
    meta_file = output_dir / "meta.json"

    joblib.dump(clf, model_file)

    meta_data = {
        "model_version": "v2",
        "feature_names": FEATURE_NAMES_V2,
        "threshold_anomalous": threshold_anomalous,
        "threshold_suspicious": threshold_suspicious,
        "sorted_val_scores": sorted_val_scores,
        "feature_stats": feature_stats,
        "train_vectors_count": len(X_train),
        "val_vectors_count": len(X_val),
        "train_sources": train_counts,
        "val_sources": val_counts,
        "train_dataset": train_name,
        "val_dataset": val_name,
        "sklearn_version": sklearn.__version__,
        "git_commit": get_git_commit_short(repo_root),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)

    # Print training summary
    print("\n" + "=" * 65)
    print("AEGIS-DPI ML DETECTOR V2 TRAINING SUMMARY")
    print("=" * 65)
    print(f"Training vectors:      {len(X_train):,} ({train_name})")
    print(f"Validation vectors:    {len(X_val):,} ({val_name})")
    print(f"Feature count:         {len(FEATURE_NAMES_V2)}")
    print(f"Threshold SUSPICIOUS:  {threshold_suspicious:.6f} (99th pct of val)")
    print(f"Threshold ANOMALOUS:   {threshold_anomalous:.6f} (max of val)")
    print(f"Validation Score Span: [{min(sorted_val_scores):.4f}, {max(sorted_val_scores):.4f}]")
    print(f"Saved Model Joblib:    {model_file}")
    print(f"Saved Metadata JSON:   {meta_file}")
    print("-" * 65)
    print("Feature Baseline Stats (Training Median / IQR):")
    for name in FEATURE_NAMES_V2:
        stats = feature_stats[name]
        print(f"  * {name.ljust(22)}: median={stats['median']:.4f}, IQR={stats['iqr']:.4f}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    train_v2()

