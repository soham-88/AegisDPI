"""
Unit tests for Feature Extractor v2 (features_v2.py)
"""

import math
import unittest
from features_v2 import extract_features_v2, FEATURE_NAMES_V2


class TestFeaturesV2(unittest.TestCase):

    def test_syn_only_vs_syn_ack_vs_ack(self):
        # 3 TCP packets:
        # 1: SYN only (flags=2)
        # 2: SYN+ACK (flags=18 = 0x02 | 0x10)
        # 3: ACK only (flags=16 = 0x10)
        events = [
            {"protocol": "6", "tcp_flags": "2", "src_port": 1000, "dst_port": 80},
            {"protocol": "tcp", "tcp_flags": "18", "src_port": 1001, "dst_port": 80},
            {"protocol": "TCP", "tcp_flags": "16", "src_port": 1002, "dst_port": 80},
        ]
        feats = extract_features_v2(events, window_s=5.0)

        # SYN-only count = 1, total TCP = 3
        expected_syn_rate = math.log1p(1.0 / 5.0)
        self.assertAlmostEqual(feats["log_syn_rate"], expected_syn_rate)
        self.assertAlmostEqual(feats["syn_ratio"], 1.0 / 3.0)

    def test_rst_counting(self):
        # TCP packets with and without RST
        # RST alone (4), RST+ACK (20 = 4 | 16), ACK alone (16)
        events = [
            {"protocol": "tcp", "tcp_flags": "4"},
            {"protocol": "tcp", "tcp_flags": "20"},
            {"protocol": "tcp", "tcp_flags": "16"},
        ]
        feats = extract_features_v2(events, window_s=5.0)

        expected_rst_rate = math.log1p(2.0 / 5.0)
        self.assertAlmostEqual(feats["log_rst_rate"], expected_rst_rate)

    def test_icmp_type_8_vs_type_0(self):
        # ICMP echo request (type 8), echo reply (type 0), error (type 3)
        events = [
            {"protocol": "1", "icmp_type": "8"},
            {"protocol": "icmp", "icmp_type": "8"},
            {"protocol": "ICMP", "icmp_type": "0"},
            {"protocol": "1", "icmp_type": "3"},
        ]
        feats = extract_features_v2(events, window_s=5.0)

        expected_icmp_echo_rate = math.log1p(2.0 / 5.0)
        self.assertAlmostEqual(feats["log_icmp_echo_rate"], expected_icmp_echo_rate)

    def test_udp_rate(self):
        # UDP packets with "17", "udp", "UDP" and non-UDP
        events = [
            {"protocol": "17", "src_port": 5000, "dst_port": 53},
            {"protocol": "udp", "src_port": 5001, "dst_port": 53},
            {"protocol": "UDP", "src_port": 5002, "dst_port": 53},
            {"protocol": "tcp", "src_port": 5003, "dst_port": 80},
        ]
        feats = extract_features_v2(events, window_s=5.0)

        expected_udp_rate = math.log1p(3.0 / 5.0)
        self.assertAlmostEqual(feats["log_udp_rate"], expected_udp_rate)

    def test_packets_per_flow_and_ports(self):
        # 5 packets total:
        # 3 packets on flow (1000, 80, tcp)
        # 1 packet on flow (1000, 443, tcp)
        # 1 packet on flow (2000, 53, udp)
        events = [
            {"src_port": 1000, "dst_port": 80, "protocol": "6"},
            {"src_port": 1000, "dst_port": 80, "protocol": "6"},
            {"src_port": 1000, "dst_port": 80, "protocol": "6"},
            {"src_port": 1000, "dst_port": 443, "protocol": "6"},
            {"src_port": 2000, "dst_port": 53, "protocol": "17"},
        ]
        feats = extract_features_v2(events, window_s=5.0)

        # 3 distinct flows, 5 packets -> 5 / 3
        expected_pkts_per_flow = math.log1p(5.0 / 3.0)
        self.assertAlmostEqual(feats["log_pkts_per_flow"], expected_pkts_per_flow)

        # Distinct src_ports: {1000, 2000} -> 2
        self.assertAlmostEqual(feats["log_unique_src_ports"], math.log1p(2))
        # Distinct dst_ports: {80, 443, 53} -> 3
        self.assertAlmostEqual(feats["log_unique_dst_ports"], math.log1p(3))

    def test_missing_fields_robustness(self):
        # Malformed or missing fields should never raise exceptions
        events = [
            {},
            {"protocol": None, "tcp_flags": None, "icmp_type": None},
            {"protocol": "", "tcp_flags": "not_a_number", "icmp_type": ""},
            {"src_port": "invalid", "dst_port": None, "dst_ip": None},
            {"dst_ip": "10.10.0.1"},
            {"dst_ip": "10.10.0.2"},
        ]
        feats = extract_features_v2(events, window_s=5.0)

        self.assertEqual(len(feats), len(FEATURE_NAMES_V2))
        for name in FEATURE_NAMES_V2:
            self.assertIn(name, feats)
            self.assertFalse(math.isnan(feats[name]))
            self.assertFalse(math.isinf(feats[name]))

        self.assertEqual(feats["unique_dst_ips"], 2.0)
        self.assertEqual(feats["syn_ratio"], 0.0)


if __name__ == "__main__":
    unittest.main()

