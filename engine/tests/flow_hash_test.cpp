#include <gtest/gtest.h>
#include "flow_hash.h"
#include <random>
#include <array>
#include <string>

static std::string ipToString(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >> 8) & 0xFF) + "." +
           std::to_string(ip & 0xFF);
}

// 1. 1000 random TCP/UDP tuples: symmetry, determinism, and >=15% distribution across 4 FP slots
TEST(SymmetricFlowHashTest, SymmetryDeterminismAndDistribution) {
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<uint32_t> ip_dist(0x0A000001, 0x0AFFFFFF);
    std::uniform_int_distribution<uint16_t> port_dist(1, 65535);
    std::uniform_int_distribution<int> proto_dist(0, 1);

    std::array<size_t, 4> slot_counts = {0, 0, 0, 0};
    const int NUM_TUPLES = 1000;

    for (int i = 0; i < NUM_TUPLES; ++i) {
        PacketAnalyzer::ParsedPacket fwd;
        fwd.has_ip = true;
        fwd.src_ip = ipToString(ip_dist(rng));
        fwd.dest_ip = ipToString(ip_dist(rng));
        fwd.src_port = port_dist(rng);
        fwd.dest_port = port_dist(rng);

        if (proto_dist(rng) == 0) {
            fwd.has_tcp = true;
            fwd.has_udp = false;
            fwd.protocol = 6;
        } else {
            fwd.has_tcp = false;
            fwd.has_udp = true;
            fwd.protocol = 17;
        }

        PacketAnalyzer::ParsedPacket rev;
        rev.has_ip = true;
        rev.src_ip = fwd.dest_ip;
        rev.dest_ip = fwd.src_ip;
        rev.src_port = fwd.dest_port;
        rev.dest_port = fwd.src_port;
        rev.has_tcp = fwd.has_tcp;
        rev.has_udp = fwd.has_udp;
        rev.protocol = fwd.protocol;

        size_t h_fwd = hashParsedPacket(fwd);
        size_t h_rev = hashParsedPacket(rev);
        size_t h_fwd_second = hashParsedPacket(fwd);

        // a. 1000 random TCP/UDP tuples: hash(A->B) == hash(B->A)
        EXPECT_EQ(h_fwd, h_rev) << "Flow hash failed symmetry on tuple #" << i
                                << ": " << fwd.src_ip << ":" << fwd.src_port
                                << " <-> " << fwd.dest_ip << ":" << fwd.dest_port;

        // b. the same tuple always gives the same hash
        EXPECT_EQ(h_fwd, h_fwd_second) << "Flow hash non-deterministic on tuple #" << i;

        slot_counts[h_fwd % 4]++;
    }

    // c. over those 1000 tuples, h % 4 puts at least 15% on each of the 4 FP slots
    for (int slot = 0; slot < 4; ++slot) {
        double pct = (static_cast<double>(slot_counts[slot]) / NUM_TUPLES) * 100.0;
        EXPECT_GE(pct, 15.0) << "Slot FP[" << slot << "] received " << pct
                             << "% of flows, expected at least 15%";
    }
}

// 2a. Same IP on both ends, different ports (A:1000 <-> A:2000): hash(fwd) == hash(rev)
TEST(SymmetricFlowHashTest, SameIpDifferentPorts) {
    PacketAnalyzer::ParsedPacket fwd;
    fwd.has_ip = true;
    fwd.src_ip = "192.168.1.100";
    fwd.dest_ip = "192.168.1.100";
    fwd.src_port = 1000;
    fwd.dest_port = 2000;
    fwd.has_tcp = true;
    fwd.has_udp = false;
    fwd.protocol = 6;

    PacketAnalyzer::ParsedPacket rev;
    rev.has_ip = true;
    rev.src_ip = "192.168.1.100";
    rev.dest_ip = "192.168.1.100";
    rev.src_port = 2000;
    rev.dest_port = 1000;
    rev.has_tcp = true;
    rev.has_udp = false;
    rev.protocol = 6;

    size_t h_fwd = hashParsedPacket(fwd);
    size_t h_rev = hashParsedPacket(rev);

    EXPECT_NE(h_fwd, 0u);
    EXPECT_EQ(h_fwd, h_rev) << "Flow hash failed symmetry for same-IP connection with different ports";
}

// 2b. Non-TCP and non-UDP packet (has_tcp=false, has_udp=false, e.g. ICMP/ARP) returns 0
TEST(SymmetricFlowHashTest, NonTcpUdpReturnsZero) {
    // ICMP packet
    PacketAnalyzer::ParsedPacket icmp_pkt;
    icmp_pkt.has_ip = true;
    icmp_pkt.src_ip = "172.21.38.198";
    icmp_pkt.dest_ip = "8.8.8.8";
    icmp_pkt.src_port = 0;
    icmp_pkt.dest_port = 0;
    icmp_pkt.has_tcp = false;
    icmp_pkt.has_udp = false;
    icmp_pkt.protocol = 1; // ICMP

    EXPECT_EQ(hashParsedPacket(icmp_pkt), 0u)
        << "Non-TCP/UDP packet (ICMP) must return 0 to trigger counter-based fallback";

    // Non-IP / ARP packet
    PacketAnalyzer::ParsedPacket arp_pkt;
    arp_pkt.has_ip = false;
    arp_pkt.has_tcp = false;
    arp_pkt.has_udp = false;
    arp_pkt.protocol = 0;

    EXPECT_EQ(hashParsedPacket(arp_pkt), 0u)
        << "Non-IP packet (ARP) must return 0 to trigger counter-based fallback";
}
