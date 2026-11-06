#!/usr/bin/env python3
"""
AegisDPI — ML Detector v3 Training Script
Calculates per-feature envelope guard limits from benign training data
and validates against benign validation data.
"""

import argparse
import datetime
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import numpy as np

from features_v2 import FEATURE_NAMES_V2
from model_v3 import GUARD_FEATURES, GUARD_MARGIN, GUARD_MULTIPLIER
from train_v2 import get_git_commit_short, load_dataset_vectors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train AegisDPI ML Detector v3 envelope guard."
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
        help="Directory to save meta.json (default: models/v3)",
    )
    return parser.parse_args()


def train_v3():
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent

    local_ips_set = {ip.strip() for ip in args.local_ips.split(",") if ip.strip()}
    train_path = Path(args.train).resolve()
    val_path = Path(args.val).resolve()

    # Safety guard: Never read mixed-test
    if "mixed" in str(train_path).lower() or "mixed" in str(val_path).lower():
        raise ValueError("Error: train_v3 must NEVER read mixed-test or mixed datasets.")

    print(f"Loading training dataset from:   {train_path}")
    X_train, train_counts, train_name = load_dataset_vectors(train_path, local_ips_set)
    print(f"  Training vectors: {len(X_train)} across sources: {train_counts}")

    print(f"Loading validation dataset from: {val_path}")
    X_val, val_counts, val_name = load_dataset_vectors(val_path, local_ips_set)
    print(f"  Validation vectors: {len(X_val)} across sources: {val_counts}")

    if len(X_train) == 0 or len(X_val) == 0:
        raise RuntimeError("Empty training or validation vectors.")

    feat_indices = {name: i for i, name in enumerate(FEATURE_NAMES_V2)}

    # Calculate per-guard-feature normal max and limit
    normal_max_raw: Dict[str, float] = {}
    limit_raw: Dict[str, float] = {}

    for feat, (kind, human_name) in GUARD_FEATURES.items():
        idx = feat_indices[feat]
        train_vals_raw = np.expm1(X_train[:, idx])
        n_max = float(np.max(train_vals_raw))
        margin = GUARD_MARGIN[kind]
        lim = float(max(GUARD_MULTIPLIER * n_max, n_max + margin))
        normal_max_raw[feat] = n_max
        limit_raw[feat] = lim

    # Evaluate validation vectors against limits (report only)
    validation_guard_hits: Dict[str, int] = {}
    for feat, (kind, human_name) in GUARD_FEATURES.items():
        idx = feat_indices[feat]
        val_vals_raw = np.expm1(X_val[:, idx])
        hits = int(np.sum(val_vals_raw > limit_raw[feat]))
        validation_guard_hits[feat] = hits

    # Save models/v3/meta.json
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    else:
        output_dir = script_dir / "models" / "v3"

    output_dir.mkdir(parents=True, exist_ok=True)
    meta_file = output_dir / "meta.json"

    meta_data = {
        "model_version": "v3",
        "base_model_dir": "models/v2",
        "guard_features": {
            feat: {"kind": kind, "human_name": human_name}
            for feat, (kind, human_name) in GUARD_FEATURES.items()
        },
        "multiplier": GUARD_MULTIPLIER,
        "margins": GUARD_MARGIN,
        "normal_max_raw": normal_max_raw,
        "limit_raw": limit_raw,
        "validation_guard_hits": validation_guard_hits,
        "train_vectors_count": len(X_train),
        "val_vectors_count": len(X_val),
        "train_sources": train_counts,
        "val_sources": val_counts,
        "train_dataset": train_name,
        "val_dataset": val_name,
        "git_commit": get_git_commit_short(repo_root),
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    with open(meta_file, "w", encoding="utf-8") as f:
        json.dump(meta_data, f, indent=2)

    # Print training summary
    print("\n" + "=" * 80)
    print("AEGIS-DPI ML DETECTOR V3 ENVELOPE GUARD TRAINING SUMMARY")
    print("=" * 80)
    print(f"Training vectors:      {len(X_train):,} ({train_name})")
    print(f"Validation vectors:    {len(X_val):,} ({val_name})")
    print(f"Guard multiplier:      {GUARD_MULTIPLIER}x")
    print(f"Guard margins:         {GUARD_MARGIN}")
    print(f"Saved Metadata JSON:   {meta_file}")
    print("-" * 80)
    print("Envelope Guard Limits & Validation Checks:")
    headers = ["Feature", "Kind", "Normal Max (Raw)", "Limit (Raw)", "Validation Hits"]
    col_w = [22, 8, 18, 14, 16]
    header_str = " | ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
    sep_str = "-+-".join("-" * col_w[i] for i in range(len(headers)))
    print(header_str)
    print(sep_str)
    for feat, (kind, human_name) in GUARD_FEATURES.items():
        n_max = f"{normal_max_raw[feat]:.2f}"
        lim = f"{limit_raw[feat]:.2f}"
        hits = str(validation_guard_hits[feat])
        row = [feat, kind, n_max, lim, hits]
        print(" | ".join(row[i].ljust(col_w[i]) for i in range(len(row))))
    print("=" * 80 + "\n")


if __name__ == "__main__":
    train_v3()

