#!/usr/bin/env python3
"""
AegisDPI — Offline Evaluation Tool
Evaluates the ML anomaly detection model against recorded labelled datasets.

Simulates the real-time sliding window admission, tick evaluation, and scoring
without modifying model weights, baselines, or production code.
"""

import argparse
import collections
import datetime
import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import local ML modules
from window_logic import WindowAdmitter
from model import AnomalyModel, aggregate_features, FEATURE_NAMES

try:
    import numpy as np
    from sklearn.metrics import roc_auc_score, average_precision_score
except ImportError:
    np = None
    roc_auc_score = None
    average_precision_score = None


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
        description="Offline evaluation tool for AegisDPI ML anomaly detector."
    )
    parser.add_argument(
        "--dataset",
        required=True,
        type=str,
        help="Path to the dataset directory (e.g. ../datasets/mixed-test)",
    )
    parser.add_argument(
        "--label",
        required=True,
        type=str,
        help="Identifier label for this evaluation run",
    )
    parser.add_argument(
        "--local-ips",
        type=str,
        default="",
        help="Optional comma-separated list of extra local IPs",
    )
    parser.add_argument(
        "--grace",
        type=float,
        default=5.0,
        help="Grace period in seconds after attack end_ts (default: 5.0)",
    )
    parser.add_argument(
        "--tick-interval",
        type=float,
        default=1.0,
        help="Simulation tick interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--results-dir",
        type=str,
        default="",
        help="Custom results directory (default: <repo_root>/eval/results)",
    )
    return parser.parse_args()


def load_schedule_and_events(dataset_path: Path) -> Tuple[Dict[str, Any], Path]:
    schedule_path = dataset_path / "schedule.json"
    events_path = dataset_path / "events.jsonl"

    if not schedule_path.exists():
        raise FileNotFoundError(f"schedule.json not found in {dataset_path}")
    if not events_path.exists():
        raise FileNotFoundError(f"events.jsonl not found in {dataset_path}")

    with open(schedule_path, "r", encoding="utf-8") as f:
        schedule = json.load(f)

    return schedule, events_path


def format_table(headers: List[str], rows: List[List[Any]]) -> str:
    """Formats headers and rows into a clean aligned ASCII table."""
    str_rows = [[str(cell) for cell in row] for row in rows]
    col_widths = [len(h) for h in headers]
    for row in str_rows:
        for i, cell in enumerate(row):
            if len(cell) > col_widths[i]:
                col_widths[i] = len(cell)

    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    data_lines = [
        " | ".join(row[i].ljust(col_widths[i]) for i in range(len(row)))
        for row in str_rows
    ]
    return f"{header_line}\n{sep_line}\n" + "\n".join(data_lines)


def run_evaluation():
    args = parse_args()
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent

    dataset_path = Path(args.dataset).resolve()
    schedule, events_path = load_schedule_and_events(dataset_path)

    # Resolve local IPs
    local_ips_set: Set[str] = set(schedule.get("local_ips", []))
    if args.local_ips.strip():
        for ip in args.local_ips.split(","):
            ip_clean = ip.strip()
            if ip_clean:
                local_ips_set.add(ip_clean)

    admitter = WindowAdmitter(local_ips_set)

    # Load ML model
    model_path = os.getenv("MODEL_PATH", str(script_dir / "model.joblib"))
    baselines_path = os.getenv("BASELINES_PATH", str(script_dir / "baselines.json"))
    meta_path = os.getenv("MODEL_META_PATH", str(script_dir / "model_meta.json"))

    model = AnomalyModel(model_path, baselines_path, meta_path)
    model.load()

    # Pre-read events to verify timestamps and find boundary ts
    # Memory footprint for ~700k events is ~180MB, totally reasonable and enables fast sorted iteration
    events_list: List[Tuple[float, Dict[str, Any]]] = []
    with open(events_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            e = json.loads(line_str)
            events_list.append((float(e["ts"]), e))

    if not events_list:
        print("No events found in dataset.", file=sys.stderr)
        sys.exit(1)

    # Ensure events are ordered by ts
    events_list.sort(key=lambda x: x[0])

    first_ts = events_list[0][0]
    last_ts = events_list[-1][0]
    total_events = len(events_list)

    # Tick simulation setup
    tick_interval = args.tick_interval
    window_size = 5.0
    grace = args.grace

    ip_windows: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
    event_idx = 0
    scored_records: List[Dict[str, Any]] = []

    current_tick = first_ts
    while current_tick <= last_ts:
        # Ingest events up to current_tick
        while event_idx < total_events and events_list[event_idx][0] <= current_tick:
            ts, event = events_list[event_idx]
            src_ip = admitter.admit(event, ts)
            if src_ip:
                ip_windows[src_ip].append((ts, event))
            event_idx += 1

        # Periodic flow table expiration
        admitter.expire_flows(current_tick)

        # Sliding window pruning
        cutoff = current_tick - window_size
        active_ips = sorted(list(ip_windows.keys()))
        for src_ip in active_ips:
            window = ip_windows[src_ip]
            while window and window[0][0] < cutoff:
                window.popleft()

            if not window:
                del ip_windows[src_ip]
                continue

            # Minimum 3 events in 5-second window required for scoring
            if len(window) < 3:
                continue

            # Note: Blocking is NOT simulated (no IP is removed after an ANOMALOUS verdict)
            events = [item[1] for item in window]
            features = aggregate_features(events, window_seconds=window_size)
            raw_score, conf, verdict, feat_contribs, desc = model.score(features)

            # Determine ground truth label
            # POSITIVE: attack entry matches src_ip and start_ts <= tick <= end_ts + grace
            # BENIGN: benign entry matches src_ip and start_ts <= tick <= end_ts
            # UNLABELLED: anything else
            assigned_label = "unlabelled"
            matched_entry_label = None

            for entry in schedule.get("entries", []):
                if entry.get("src_ip") == src_ip:
                    start_ts = float(entry["start_ts"])
                    end_ts = float(entry["end_ts"])
                    kind = entry.get("kind")
                    if kind == "attack" and (start_ts <= current_tick <= end_ts + grace):
                        assigned_label = "positive"
                        matched_entry_label = entry.get("label")
                        break
                    elif kind == "benign" and (start_ts <= current_tick <= end_ts):
                        assigned_label = "benign"
                        matched_entry_label = entry.get("label")
                        break

            scored_records.append({
                "tick": current_tick,
                "src_ip": src_ip,
                "confidence": conf,
                "verdict": verdict,
                "label": assigned_label,
                "entry_label": matched_entry_label,
                "features": features,
            })

        current_tick += tick_interval

    # Ingest any trailing events if loop terminated right before last_ts
    while event_idx < total_events:
        event_idx += 1

    # Analysis & Metrics Calculation
    total_scored_ticks = len(scored_records)
    unlabelled_ticks = sum(1 for r in scored_records if r["label"] == "unlabelled")

    # Group schedule entries by kind
    attack_entries = [e for e in schedule.get("entries", []) if e.get("kind") == "attack"]
    benign_entries = [e for e in schedule.get("entries", []) if e.get("kind") == "benign"]

    # --- Per Attack Entry Metrics ---
    attack_results = []
    for entry in attack_entries:
        lbl = entry.get("label", "")
        src_ip = entry.get("src_ip", "")
        start_ts = float(entry["start_ts"])
        end_ts = float(entry["end_ts"])
        duration_s = end_ts - start_ts

        ticks = [r for r in scored_records if r["entry_label"] == lbl and r["label"] == "positive"]
        num_ticks = len(ticks)

        anom_ticks = [r for r in ticks if r["confidence"] >= 0.85]
        susp_ticks = [r for r in ticks if r["confidence"] >= 0.60]

        detected_anom = len(anom_ticks) > 0
        time_to_first_anom = (
            anom_ticks[0]["tick"] - start_ts if detected_anom else None
        )

        detected_susp = len(susp_ticks) > 0
        time_to_first_susp = (
            susp_ticks[0]["tick"] - start_ts if detected_susp else None
        )

        share_anom = (len(anom_ticks) / num_ticks) if num_ticks > 0 else 0.0
        max_conf = max((r["confidence"] for r in ticks), default=0.0)

        attack_results.append({
            "label": lbl,
            "src_ip": src_ip,
            "duration_s": duration_s,
            "scored_ticks": num_ticks,
            "detected_anomalous": detected_anom,
            "time_to_first_anomalous_s": time_to_first_anom,
            "detected_suspicious": detected_susp,
            "time_to_first_suspicious_s": time_to_first_susp,
            "anomalous_tick_share": share_anom,
            "max_confidence": max_conf,
        })

    # --- Per Benign Entry Metrics ---
    benign_results = []
    for entry in benign_entries:
        lbl = entry.get("label", "")
        src_ip = entry.get("src_ip", "")
        start_ts = float(entry["start_ts"])
        end_ts = float(entry["end_ts"])
        duration_s = end_ts - start_ts

        ticks = [r for r in scored_records if r["entry_label"] == lbl and r["label"] == "benign"]
        num_ticks = len(ticks)

        anom_ticks = [r for r in ticks if r["confidence"] >= 0.85]
        susp_ticks = [r for r in ticks if 0.60 <= r["confidence"] < 0.85]

        # Alert episodes at ANOMALOUS: consecutive flagged ticks merged into one episode
        alert_episodes = 0
        in_episode = False
        prev_tick: Optional[float] = None

        for r in ticks:
            is_anom = (r["confidence"] >= 0.85)
            t = r["tick"]
            if is_anom:
                if not in_episode or prev_tick is None or (t - prev_tick > tick_interval + 1e-4):
                    alert_episodes += 1
                in_episode = True
            else:
                in_episode = False
            prev_tick = t

        duration_hours = duration_s / 3600.0
        episodes_per_hour = alert_episodes / duration_hours if duration_hours > 0 else 0.0

        max_conf = max((r["confidence"] for r in ticks), default=0.0)
        highest_conf_tick = max(ticks, key=lambda r: r["confidence"]) if ticks else None
        highest_conf_features = (
            highest_conf_tick["features"] if highest_conf_tick else {}
        )

        benign_results.append({
            "label": lbl,
            "src_ip": src_ip,
            "duration_s": duration_s,
            "scored_ticks": num_ticks,
            "anomalous_ticks": len(anom_ticks),
            "suspicious_ticks": len(susp_ticks),
            "alert_episodes_anomalous": alert_episodes,
            "episodes_per_hour": episodes_per_hour,
            "max_confidence": max_conf,
            "highest_confidence_features": highest_conf_features,
        })

    # --- Overall Tick-Level Metrics ---
    # Filter to labelled ticks (positive or benign)
    labelled_records = [r for r in scored_records if r["label"] in ("positive", "benign")]
    has_positives = any(r["label"] == "positive" for r in labelled_records)
    has_benigns = any(r["label"] == "benign" for r in labelled_records)

    overall_metrics: Dict[str, Any] = {}

    for name, thresh in [("anomalous_threshold_0.85", 0.85), ("suspicious_threshold_0.60", 0.60)]:
        tp = sum(1 for r in labelled_records if r["label"] == "positive" and r["confidence"] >= thresh)
        fp = sum(1 for r in labelled_records if r["label"] == "benign" and r["confidence"] >= thresh)
        fn = sum(1 for r in labelled_records if r["label"] == "positive" and r["confidence"] < thresh)
        tn = sum(1 for r in labelled_records if r["label"] == "benign" and r["confidence"] < thresh)

        precision = tp / (tp + fp) if (tp + fp) > 0 else (0.0 if has_positives else None)
        recall = tp / (tp + fn) if (tp + fn) > 0 else (0.0 if has_positives else None)
        f1 = (
            (2 * precision * recall / (precision + recall))
            if (precision is not None and recall is not None and (precision + recall) > 0)
            else (0.0 if has_positives else None)
        )
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        overall_metrics[name] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "fpr": fpr,
        }

    # AUC metrics via sklearn
    roc_auc = None
    pr_auc = None
    if has_positives and has_benigns and np is not None and roc_auc_score is not None:
        y_true = np.array([1 if r["label"] == "positive" else 0 for r in labelled_records])
        y_score = np.array([r["confidence"] for r in labelled_records])
        try:
            roc_auc = float(roc_auc_score(y_true, y_score))
            pr_auc = float(average_precision_score(y_true, y_score))
        except Exception:
            roc_auc = None
            pr_auc = None

    overall_metrics["roc_auc"] = roc_auc
    overall_metrics["pr_auc"] = pr_auc

    # Compile final JSON result structure
    dataset_name = schedule.get("name") or dataset_path.name
    today_str = datetime.date.today().isoformat()
    git_hash = get_git_commit_short(repo_root)

    report_data = {
        "header": {
            "label": args.label,
            "dataset": dataset_name,
            "git_commit": git_hash,
            "events_count": total_events,
            "scored_ticks_count": total_scored_ticks,
            "unlabelled_ticks_count": unlabelled_ticks,
            "tick_interval_s": tick_interval,
            "local_ips": sorted(list(local_ips_set)),
            "grace_s": grace,
        },
        "blocking_simulation": "Blocking is NOT simulated (no IP is removed after an ANOMALOUS verdict).",
        "attacks": attack_results,
        "benign": benign_results,
        "overall_metrics": overall_metrics,
    }

    # Write JSON report
    if args.results_dir:
        results_dir = Path(args.results_dir).resolve()
    else:
        results_dir = repo_root / "eval" / "results"

    results_dir.mkdir(parents=True, exist_ok=True)
    report_filename = f"{today_str}_{args.label}_{dataset_name}.json"
    report_file_path = results_dir / report_filename

    with open(report_file_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    # --- Print Terminal Tables ---
    print("\n" + "=" * 80)
    print(f"AEGIS-DPI OFFLINE EVALUATION REPORT")
    print("=" * 80)
    print(f"Label:                 {args.label}")
    print(f"Dataset:               {dataset_name} ({dataset_path})")
    print(f"Git Short Commit:      {git_hash}")
    print(f"Total Events Read:     {total_events:,}")
    print(f"Total Scored Ticks:    {total_scored_ticks:,} (Unlabelled: {unlabelled_ticks:,})")
    print(f"Tick Interval:         {tick_interval:.1f} s (Sliding Window: 5.0 s)")
    print(f"Local IPs:             {', '.join(sorted(local_ips_set))}")
    print(f"Attack Grace Period:   {grace:.1f} s")
    print(f"Blocking Simulation:   Blocking is NOT simulated (no IP is removed after an ANOMALOUS verdict).")
    print(f"Output JSON:           {report_file_path}")
    print("=" * 80 + "\n")

    # 1. Attacks Table (if present)
    if attack_results:
        print("--- ATTACK EVALUATION ---")
        attack_headers = [
            "Attack Label",
            "Src IP",
            "Duration",
            "Ticks",
            "Det. (Anom)",
            "1st Anom (s)",
            "Det. (>=Susp)",
            "1st Susp (s)",
            "Anom Share",
            "Max Conf",
        ]
        attack_rows = []
        for a in attack_results:
            attack_rows.append([
                a["label"],
                a["src_ip"],
                f"{a['duration_s']:.1f}s",
                str(a["scored_ticks"]),
                "YES" if a["detected_anomalous"] else "NO",
                f"{a['time_to_first_anomalous_s']:.1f}s" if a["time_to_first_anomalous_s"] is not None else "n/a",
                "YES" if a["detected_suspicious"] else "NO",
                f"{a['time_to_first_suspicious_s']:.1f}s" if a["time_to_first_suspicious_s"] is not None else "n/a",
                f"{a['anomalous_tick_share'] * 100:.1f}%",
                f"{a['max_confidence']:.4f}",
            ])
        print(format_table(attack_headers, attack_rows))
        print()

    # 2. Benign Table
    print("--- BENIGN EVALUATION ---")
    benign_headers = [
        "Benign Label",
        "Src IP",
        "Ticks",
        "Anom",
        "Susp",
        "Episodes",
        "Ep/Hour",
        "Max Conf",
    ]
    benign_rows = []
    for b in benign_results:
        benign_rows.append([
            b["label"],
            b["src_ip"],
            str(b["scored_ticks"]),
            str(b["anomalous_ticks"]),
            str(b["suspicious_ticks"]),
            str(b["alert_episodes_anomalous"]),
            f"{b['episodes_per_hour']:.2f}",
            f"{b['max_confidence']:.4f}",
        ])
    print(format_table(benign_headers, benign_rows))
    print()

    print("--- BENIGN HIGHEST-CONFIDENCE TICK FEATURES ---")
    for b in benign_results:
        feats_str = ", ".join(f"{k}={v}" for k, v in b["highest_confidence_features"].items())
        print(f"  * {b['label']} ({b['src_ip']}): max_conf={b['max_confidence']:.4f} | {feats_str}")
    print()

    # 3. Overall Metrics Table
    print("--- OVERALL METRICS ---")
    if has_positives:
        metrics_headers = ["Operating Point", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1-Score", "FPR"]
        metrics_rows = []
        for name, label_str in [
            ("anomalous_threshold_0.85", "ANOMALOUS (conf >= 0.85)"),
            ("suspicious_threshold_0.60", "SUSPICIOUS (conf >= 0.60)"),
        ]:
            m = overall_metrics[name]
            prec_str = f"{m['precision']:.4f}" if m["precision"] is not None else "n/a"
            rec_str = f"{m['recall']:.4f}" if m["recall"] is not None else "n/a"
            f1_str = f"{m['f1']:.4f}" if m["f1"] is not None else "n/a"
            fpr_str = f"{m['fpr']:.4f}"
            metrics_rows.append([
                label_str,
                str(m["tp"]),
                str(m["fp"]),
                str(m["fn"]),
                str(m["tn"]),
                prec_str,
                rec_str,
                f1_str,
                fpr_str,
            ])
        print(format_table(metrics_headers, metrics_rows))
        print(f"ROC-AUC:  {f'{roc_auc:.4f}' if roc_auc is not None else 'n/a'}")
        print(f"PR-AUC:   {f'{pr_auc:.4f}' if pr_auc is not None else 'n/a'}")
    else:
        # Benign-only dataset
        metrics_headers = ["Operating Point", "FP", "TN", "FPR"]
        metrics_rows = []
        for name, label_str in [
            ("anomalous_threshold_0.85", "ANOMALOUS (conf >= 0.85)"),
            ("suspicious_threshold_0.60", "SUSPICIOUS (conf >= 0.60)"),
        ]:
            m = overall_metrics[name]
            metrics_rows.append([
                label_str,
                str(m["fp"]),
                str(m["tn"]),
                f"{m['fpr']:.4f}",
            ])
        print(format_table(metrics_headers, metrics_rows))
        print("Note: Dataset has no positive (attack) entries; TP, FN, Precision, Recall, F1, and AUC are n/a.")

    print("\n" + "=" * 80 + "\n")


if __name__ == "__main__":
    run_evaluation()

