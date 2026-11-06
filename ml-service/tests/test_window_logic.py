import unittest
from window_logic import WindowAdmitter, is_non_unicast


class TestWindowLogic(unittest.TestCase):
    def setUp(self):
        self.local_ips = {"10.10.0.1", "10.255.255.254", "127.0.0.1"}
        self.admitter = WindowAdmitter(
            local_ips=self.local_ips,
            flow_table_ttl_s=120.0,
            max_flow_entries=50000,
        )
        self.now = 1000.0

    def test_local_to_local_ignored(self):
        # Local-to-local traffic must never feed any window
        data = {
            "src_ip": "10.10.0.1",
            "dst_ip": "10.255.255.254",
            "src_port": "50000",
            "dst_port": "8080",
            "protocol": "6",
            "tcp_flags": "2",
        }
        res = self.admitter.admit(data, self.now)
        self.assertIsNone(res)

    def test_local_sourced_packet_ignored(self):
        # Packets sent from a local IP to a remote IP must never feed any window
        data = {
            "src_ip": "10.10.0.1",
            "dst_ip": "1.2.3.4",
            "src_port": "45678",
            "dst_port": "443",
            "protocol": "6",
            "tcp_flags": "2",
        }
        res = self.admitter.admit(data, self.now)
        self.assertIsNone(res)

    def test_inbound_remote_initiated_tcp_admitted(self):
        # 1. Remote client initiates connection with SYN
        syn_data = {
            "src_ip": "1.2.3.4",
            "dst_ip": "10.10.0.1",
            "src_port": "12345",
            "dst_port": "80",
            "protocol": "6",
            "tcp_flags": "2",  # SYN
        }
        res_syn = self.admitter.admit(syn_data, self.now)
        self.assertEqual(res_syn, "1.2.3.4")

        # 2. Local responds with SYN+ACK (outbound, ignored from window)
        syn_ack_data = {
            "src_ip": "10.10.0.1",
            "dst_ip": "1.2.3.4",
            "src_port": "80",
            "dst_port": "12345",
            "protocol": "6",
            "tcp_flags": "18",  # SYN+ACK
        }
        res_syn_ack = self.admitter.admit(syn_ack_data, self.now + 0.01)
        self.assertIsNone(res_syn_ack)

        # 3. Remote responds with ACK (inbound, should be admitted to 1.2.3.4)
        ack_data = {
            "src_ip": "1.2.3.4",
            "dst_ip": "10.10.0.1",
            "src_port": "12345",
            "dst_port": "80",
            "protocol": "6",
            "tcp_flags": "16",  # ACK
        }
        res_ack = self.admitter.admit(ack_data, self.now + 0.02)
        self.assertEqual(res_ack, "1.2.3.4")

    def test_inbound_local_initiated_flow_not_admitted(self):
        # 1. Local host initiates connection to remote server with SYN
        local_syn = {
            "src_ip": "10.10.0.1",
            "dst_ip": "1.2.3.4",
            "src_port": "54321",
            "dst_port": "443",
            "protocol": "6",
            "tcp_flags": "2",  # SYN
        }
        res_local_syn = self.admitter.admit(local_syn, self.now)
        self.assertIsNone(res_local_syn)

        # 2. Remote server replies with SYN+ACK
        remote_syn_ack = {
            "src_ip": "1.2.3.4",
            "dst_ip": "10.10.0.1",
            "src_port": "443",
            "dst_port": "54321",
            "protocol": "6",
            "tcp_flags": "18",  # SYN+ACK (candidate initiator = receiver = local)
        }
        res_remote_syn_ack = self.admitter.admit(remote_syn_ack, self.now + 0.01)
        self.assertIsNone(res_remote_syn_ack)

        # 3. Subsequent inbound data packet from remote server must NOT be admitted
        remote_data = {
            "src_ip": "1.2.3.4",
            "dst_ip": "10.10.0.1",
            "src_port": "443",
            "dst_port": "54321",
            "protocol": "6",
            "tcp_flags": "16",  # ACK / data
        }
        res_remote_data = self.admitter.admit(remote_data, self.now + 0.02)
        self.assertIsNone(res_remote_data)

    def test_non_unicast_handled(self):
        # Multicast destination
        mcast_dst = {
            "src_ip": "1.2.3.4",
            "dst_ip": "224.0.0.1",
            "src_port": "1234",
            "dst_port": "5678",
            "protocol": "17",
        }
        self.assertIsNone(self.admitter.admit(mcast_dst, self.now))

        # Broadcast destination
        bcast_dst = {
            "src_ip": "1.2.3.4",
            "dst_ip": "255.255.255.255",
            "src_port": "67",
            "dst_port": "68",
            "protocol": "17",
        }
        self.assertIsNone(self.admitter.admit(bcast_dst, self.now))

        # Multicast source
        mcast_src = {
            "src_ip": "224.0.0.251",
            "dst_ip": "10.10.0.1",
            "src_port": "5353",
            "dst_port": "5353",
            "protocol": "17",
        }
        self.assertIsNone(self.admitter.admit(mcast_src, self.now))

        # is_non_unicast helper checks
        self.assertTrue(is_non_unicast("224.0.0.1"))
        self.assertTrue(is_non_unicast("255.255.255.255"))
        self.assertTrue(is_non_unicast("169.254.1.1"))
        self.assertTrue(is_non_unicast("0.0.0.0"))
        self.assertFalse(is_non_unicast("10.10.0.1"))
        self.assertFalse(is_non_unicast("1.2.3.4"))

    def test_flow_table_respects_max_flow_entries(self):
        small_admitter = WindowAdmitter(
            local_ips={"10.10.0.1"},
            flow_table_ttl_s=120.0,
            max_flow_entries=3,
        )

        for port in [1001, 1002, 1003, 1004, 1005]:
            data = {
                "src_ip": "1.2.3.4",
                "dst_ip": "10.10.0.1",
                "src_port": str(port),
                "dst_port": "80",
                "protocol": "6",
                "tcp_flags": "2",
            }
            res = small_admitter.admit(data, self.now)
            self.assertEqual(res, "1.2.3.4")

        # Table size must not exceed max_flow_entries (3)
        self.assertEqual(len(small_admitter.flow_table), 3)

        # Oldest flow keys (ports 1001, 1002) should have been evicted
        self.assertNotIn(("1.2.3.4", 1001, 80, "6"), small_admitter.flow_table)
        self.assertNotIn(("1.2.3.4", 1002, 80, "6"), small_admitter.flow_table)
        # Most recent keys (ports 1003, 1004, 1005) must remain
        self.assertIn(("1.2.3.4", 1003, 80, "6"), small_admitter.flow_table)
        self.assertIn(("1.2.3.4", 1004, 80, "6"), small_admitter.flow_table)
        self.assertIn(("1.2.3.4", 1005, 80, "6"), small_admitter.flow_table)


if __name__ == "__main__":
    unittest.main()

