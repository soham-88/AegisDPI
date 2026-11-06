#!/usr/bin/env python3
"""
AegisDPI — Offline Evaluation Comparison Tool
Compares two evaluation JSON reports side-by-side with delta columns.

Usage:
    python3 eval/compare.py <before.json> <after.json>
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


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


def fmt_float(val: Optional[float], decimals: int = 4) -> str:
    if val is None:
        return "n/a"
    return f"{val:.{decimals}f}"


def fmt_delta(val_before: Optional[float], val_after: Optional[float], decimals: int = 4, suffix: str = "") -> str:
    if val_before is None or val_after is None:
        return "n/a"
    d = val_after - val_before
    sign = "+" if d > 0 else ""
    return f"{sign}{d:.{decimals}f}{suffix}"


def compare_reports(before_path: str, after_path: str):
    p_before = Path(before_path).resolve()
    p_after = Path(after_path).resolve()

    if not p_before.exists():
        print(f"Error: file not found: {p_before}", file=sys.stderr)
        sys.exit(1)
    if not p_after.exists():
        print(f"Error: file not found: {p_after}", file=sys.stderr)
        sys.exit(1)

    with open(p_before, "r", encoding="utf-8") as f:
        d_before = json.load(f)
    with open(p_after, "r", encoding="utf-8") as f:
        d_after = json.load(f)

    h_before = d_before.get("header", {})
    h_after = d_after.get("header", {})

    print("\n" + "=" * 90)
    print("AEGIS-DPI EVALUATION COMPARISON")
    print("=" * 90)
    print(f"Before: {h_before.get('label', 'before')} (Model: {h_before.get('model_version', 'v1').upper()}) | {p_before.name}")
    print(f"After:  {h_after.get('label', 'after')} (Model: {h_after.get('model_version', 'v2').upper()}) | {p_after.name}")
    print(f"Dataset: {h_before.get('dataset', '')} vs {h_after.get('dataset', '')}")
    print("=" * 90 + "\n")

    # 1. Attacks Comparison
    attacks_before = {a["label"]: a for a in d_before.get("attacks", [])}
    attacks_after = {a["label"]: a for a in d_after.get("attacks", [])}
    all_attack_labels = sorted(list(set(attacks_before.keys()) | set(attacks_after.keys())))

    if all_attack_labels:
        print("--- PER-ATTACK DETECTION & LATENCY ---")
        att_headers = [
            "Attack Label",
            "Det (B)",
            "Det (A)",
            "1st Anom (B)",
            "1st Anom (A)",
            "Delta Lat",
            "1st Pkt (B)",
            "1st Pkt (A)",
            "Delta Pkt Lat",
        ]
        att_rows = []
        for lbl in all_attack_labels:
            ab = attacks_before.get(lbl, {})
            aa = attacks_after.get(lbl, {})

            det_b = "YES" if ab.get("detected_anomalous") else "NO"
            det_a = "YES" if aa.get("detected_anomalous") else "NO"

            t_b = ab.get("time_to_first_anomalous_s")
            t_a = aa.get("time_to_first_anomalous_s")
            t_b_str = f"{t_b:.1f}s" if t_b is not None else "n/a"
            t_a_str = f"{t_a:.1f}s" if t_a is not None else "n/a"
            d_t_str = fmt_delta(t_b, t_a, decimals=1, suffix="s")

            # Packet latency (if available in either report)
            pkt_b = ab.get("time_to_first_anomalous_from_packet_s")
            pkt_a = aa.get("time_to_first_anomalous_from_packet_s")
            pkt_b_str = f"{pkt_b:.1f}s" if pkt_b is not None else "n/a"
            pkt_a_str = f"{pkt_a:.1f}s" if pkt_a is not None else "n/a"
            d_pkt_str = fmt_delta(pkt_b, pkt_a, decimals=1, suffix="s")

            att_rows.append([
                lbl,
                det_b,
                det_a,
                t_b_str,
                t_a_str,
                d_t_str,
                pkt_b_str,
                pkt_a_str,
                d_pkt_str,
            ])

        print(format_table(att_headers, att_rows))
        print()

    # 2. Benign Comparison
    benign_before = {b["label"]: b for b in d_before.get("benign", [])}
    benign_after = {b["label"]: b for b in d_after.get("benign", [])}
    all_benign_labels = sorted(list(set(benign_before.keys()) | set(benign_after.keys())))

    if all_benign_labels:
        print("--- PER-BENIGN ANOMALOUS EPISODES & RATES ---")
        ben_headers = [
            "Benign Label",
            "Episodes (B)",
            "Episodes (A)",
            "Delta Ep",
            "Ep/Hour (B)",
            "Ep/Hour (A)",
            "Delta Ep/Hr",
        ]
        ben_rows = []
        for lbl in all_benign_labels:
            bb = benign_before.get(lbl, {})
            ba = benign_after.get(lbl, {})

            ep_b = bb.get("alert_episodes_anomalous", 0)
            ep_a = ba.get("alert_episodes_anomalous", 0)
            d_ep = ep_a - ep_b
            d_ep_str = f"{'+' if d_ep > 0 else ''}{d_ep}"

            rate_b = bb.get("episodes_per_hour", 0.0)
            rate_a = ba.get("episodes_per_hour", 0.0)
            d_rate_str = fmt_delta(rate_b, rate_a, decimals=2)

            ben_rows.append([
                lbl,
                str(ep_b),
                str(ep_a),
                d_ep_str,
                f"{rate_b:.2f}",
                f"{rate_a:.2f}",
                d_rate_str,
            ])

        print(format_table(ben_headers, ben_rows))
        print()

    # 3. Overall Metrics Comparison
    m_b = d_before.get("overall_metrics", {})
    m_a = d_after.get("overall_metrics", {})

    print("--- OVERALL METRICS COMPARISON ---")
    op_points = [
        ("anomalous_threshold", "ANOMALOUS"),
        ("suspicious_threshold", "SUSPICIOUS-or-higher"),
    ]

    metrics_headers = [
        "Operating Point",
        "Metric",
        "Before",
        "After",
        "Delta",
    ]
    metrics_rows = []

    for key, name in op_points:
        mb_sub = m_b.get(key) or m_b.get(f"{key}_0.85") or m_b.get(f"{key}_0.60") or {}
        ma_sub = m_a.get(key) or m_a.get(f"{key}_0.85") or m_a.get(f"{key}_0.60") or {}

        for metric in ["tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr"]:
            vb = mb_sub.get(metric)
            va = ma_sub.get(metric)

            is_count = metric in ("tp", "fp", "fn", "tn")
            decimals = 0 if is_count else 4

            vb_str = str(vb) if is_count and vb is not None else fmt_float(vb, decimals)
            va_str = str(va) if is_count and va is not None else fmt_float(va, decimals)

            d_str = (
                f"{'+' if (va - vb) > 0 else ''}{va - vb}"
                if is_count and vb is not None and va is not None
                else fmt_delta(vb, va, decimals)
            )

            metrics_rows.append([
                name,
                metric.upper(),
                vb_str,
                va_str,
                d_str,
            ])

    print(format_table(metrics_headers, metrics_rows))
    print()

    # 4. AUC Metrics
    roc_b = m_b.get("roc_auc")
    roc_a = m_a.get("roc_auc")
    pr_b = m_b.get("pr_auc")
    pr_a = m_a.get("pr_auc")

    auc_headers = ["Metric", "Before", "After", "Delta"]
    auc_rows = [
        ["ROC-AUC", fmt_float(roc_b, 4), fmt_float(roc_a, 4), fmt_delta(roc_b, roc_a, 4)],
        ["PR-AUC", fmt_float(pr_b, 4), fmt_float(pr_a, 4), fmt_delta(pr_b, pr_a, 4)],
    ]
    print("--- AUC METRICS ---")
    print(format_table(auc_headers, auc_rows))
    print("\n" + "=" * 90 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compare two offline evaluation reports.")
    parser.add_argument("before", help="Path to before JSON report")
    parser.add_argument("after", help="Path to after JSON report")
    args = parser.parse_args()

    compare_reports(args.before, args.after)
