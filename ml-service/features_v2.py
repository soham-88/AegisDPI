"""
AegisDPI — Feature Extractor v2
Extracts traffic shape, protocol composition, and behavioral diversity features
over sliding event windows.
"""

import math
from typing import Any, Dict, List

FEATURE_NAMES_V2 = [
    "log_pps",
    "log_syn_rate",
    "syn_ratio",
    "log_rst_rate",
    "log_icmp_echo_rate",
    "log_udp_rate",
    "log_unique_dst_ports",
    "log_unique_src_ports",
    "log_pkts_per_flow",
    "unique_dst_ips",
]


def _parse_port(port_val: Any) -> int:
    """Safely parses a port value to an integer, returning 0 if missing or invalid."""
    if port_val is None or str(port_val).strip() == "":
        return 0
    try:
        return int(port_val)
    except (ValueError, TypeError):
        return 0


def extract_features_v2(events: List[Dict[str, Any]], window_s: float = 5.0) -> Dict[str, float]:
    """
    Computes v2 feature vector over a sliding window of events for a single source IP:
      - log_pps: log1p(count / window_s)
      - log_syn_rate: log1p(TCP packets with SYN set and ACK not set / window_s)
      - syn_ratio: SYN-only TCP packets / TCP packets (0 if no TCP)
      - log_rst_rate: log1p(TCP packets with RST set / window_s)
      - log_icmp_echo_rate: log1p(ICMP type 8 packets / window_s)
      - log_udp_rate: log1p(UDP packets / window_s)
      - log_unique_dst_ports: log1p(distinct dst_port)
      - log_unique_src_ports: log1p(distinct src_port)
      - log_pkts_per_flow: log1p(count / distinct (src_port, dst_port, protocol) tuples)
      - unique_dst_ips: distinct dst_ip (raw count)
    """
    count = len(events)
    safe_window_s = max(float(window_s), 1e-6)

    if count == 0:
        return {name: 0.0 for name in FEATURE_NAMES_V2}

    tcp_count = 0
    syn_only_count = 0
    rst_count = 0
    icmp_echo_count = 0
    udp_count = 0

    dst_ports = set()
    src_ports = set()
    flows = set()
    dst_ips = set()

    for e in events:
        proto_raw = str(e.get("protocol") or "").strip().lower()
        is_tcp = "tcp" in proto_raw or proto_raw == "6"
        is_icmp = "icmp" in proto_raw or proto_raw == "1"
        is_udp = "udp" in proto_raw or proto_raw == "17"

        # Safe port parsing
        sp = _parse_port(e.get("src_port"))
        dp = _parse_port(e.get("dst_port"))
        dst_ports.add(dp)
        src_ports.add(sp)
        flows.add((sp, dp, proto_raw))

        dst_ip_str = str(e.get("dst_ip") or "").strip()
        if dst_ip_str:
            dst_ips.add(dst_ip_str)

        if is_tcp:
            tcp_count += 1
            raw_flags = e.get("tcp_flags")
            flags_val = None
            if raw_flags is not None and str(raw_flags).strip() != "":
                try:
                    flags_val = int(raw_flags)
                except (ValueError, TypeError):
                    flags_val = None

            if flags_val is not None:
                is_syn = (flags_val & 0x02) != 0
                is_ack = (flags_val & 0x10) != 0
                is_rst = (flags_val & 0x04) != 0

                if is_syn and not is_ack:
                    syn_only_count += 1
                if is_rst:
                    rst_count += 1

        elif is_icmp:
            raw_type = e.get("icmp_type")
            type_val = None
            if raw_type is not None and str(raw_type).strip() != "":
                try:
                    type_val = int(raw_type)
                except (ValueError, TypeError):
                    type_val = None

            if type_val == 8:
                icmp_echo_count += 1

        elif is_udp:
            udp_count += 1

    distinct_flows = max(len(flows), 1)

    log_pps = math.log1p(count / safe_window_s)
    log_syn_rate = math.log1p(syn_only_count / safe_window_s)
    syn_ratio = (syn_only_count / tcp_count) if tcp_count > 0 else 0.0
    log_rst_rate = math.log1p(rst_count / safe_window_s)
    log_icmp_echo_rate = math.log1p(icmp_echo_count / safe_window_s)
    log_udp_rate = math.log1p(udp_count / safe_window_s)
    log_unique_dst_ports = math.log1p(len(dst_ports))
    log_unique_src_ports = math.log1p(len(src_ports))
    log_pkts_per_flow = math.log1p(count / distinct_flows)
    unique_dst_ips = float(len(dst_ips))

    return {
        "log_pps": float(log_pps),
        "log_syn_rate": float(log_syn_rate),
        "syn_ratio": float(syn_ratio),
        "log_rst_rate": float(log_rst_rate),
        "log_icmp_echo_rate": float(log_icmp_echo_rate),
        "log_udp_rate": float(log_udp_rate),
        "log_unique_dst_ports": float(log_unique_dst_ports),
        "log_unique_src_ports": float(log_unique_src_ports),
        "log_pkts_per_flow": float(log_pkts_per_flow),
        "unique_dst_ips": float(unique_dst_ips),
    }

