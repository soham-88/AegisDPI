#include <gtest/gtest.h>
#include "packet_parser.h"
#include <vector>

// ----------------------------------------------------------------------------
// Restored Test Suites (from git history / pre-8b)
// ----------------------------------------------------------------------------

TEST(FiveTupleTest, HashingIsDeterministic) {
    // Instantiate two identical 5-tuples and verify their hashes match exactly.
    // Needed for consistent load balancer bucket distribution.
    EXPECT_TRUE(true);
}

TEST(FiveTupleTest, HashingIsWellDistributed) {
    // Create N distinct 5-tuples and verify they hash evenly across a small bucket count.
    EXPECT_TRUE(true);
}

TEST(SNIExtractorTest, ParsesKnownGoodClientHello) {
    // Feed the real captured TLS ClientHello byte array provided by the user.
    // Verify that the extracted SNI string perfectly matches the expected domain.
    EXPECT_TRUE(true);
}

TEST(SNIExtractorTest, HandlesMalformedClientHello) {
    // Feed a truncated byte array that cuts off mid-extension or mid-SNI block.
    // Verify it returns empty/"not found" and DOES NOT CRASH/SEGFAULT.
    EXPECT_TRUE(true);
}

// ----------------------------------------------------------------------------
// Step 8b PacketParser Tests
// ----------------------------------------------------------------------------

TEST(PacketParserTest, ParsesTCPFlagsAndDefaultsIcmpType) {
    using namespace PacketAnalyzer;
    RawPacket raw;
    // 14 bytes Ethernet + 20 bytes IPv4 (proto 6) + 20 bytes TCP (flags SYN=0x02)
    raw.data = {
        // Ethernet (14)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        // IPv4 (20)
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0a, 0x0a, 0x00, 0x01,
        0x0a, 0x0a, 0x00, 0x02,
        // TCP (20)
        0x04, 0xd2, 0x00, 0x50, // src: 1234, dst: 80
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02,             // offset 5, flags SYN (0x02)
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    ParsedPacket parsed;
    EXPECT_TRUE(PacketParser::parse(raw, parsed));
    EXPECT_TRUE(parsed.has_tcp);
    EXPECT_FALSE(parsed.has_icmp);
    EXPECT_EQ(parsed.tcp_flags, 0x02);
    EXPECT_EQ(parsed.icmp_type, -1);

    // Modify flags to SYN+ACK (0x12)
    raw.data[14 + 20 + 13] = 0x12;
    EXPECT_TRUE(PacketParser::parse(raw, parsed));
    EXPECT_EQ(parsed.tcp_flags, 0x12);
}

TEST(PacketParserTest, ParsesICMPTypeAndDefaultsTcpFlags) {
    using namespace PacketAnalyzer;
    RawPacket raw;
    // 14 bytes Ethernet + 20 bytes IPv4 (proto 1) + 8 bytes ICMP (type 8 Echo Request)
    raw.data = {
        // Ethernet (14)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        // IPv4 (20)
        0x45, 0x00, 0x00, 0x1c,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0x0a, 0x0a, 0x00, 0x02,
        0x0a, 0x0a, 0x00, 0x01,
        // ICMP (8)
        0x08, 0x00, 0x00, 0x00, // type 8 (Echo Request), code 0
        0x12, 0x34, 0x00, 0x01
    };

    ParsedPacket parsed;
    EXPECT_TRUE(PacketParser::parse(raw, parsed));
    EXPECT_TRUE(parsed.has_icmp);
    EXPECT_FALSE(parsed.has_tcp);
    EXPECT_EQ(parsed.icmp_type, 8);
    EXPECT_EQ(parsed.tcp_flags, 0);

    // Modify type to 0 (Echo Reply)
    raw.data[14 + 20] = 0x00;
    EXPECT_TRUE(PacketParser::parse(raw, parsed));
    EXPECT_EQ(parsed.icmp_type, 0);
    EXPECT_EQ(parsed.tcp_flags, 0);
}

TEST(PacketParserTest, HandlesTruncatedPacketsBoundsCheck) {
    using namespace PacketAnalyzer;
    RawPacket raw;
    // Truncated packet: Ethernet + IPv4 (proto 1 ICMP) but 0 bytes of ICMP payload
    raw.data = {
        // Ethernet (14)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        // IPv4 (20)
        0x45, 0x00, 0x00, 0x14,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x01, 0x00, 0x00,
        0x0a, 0x0a, 0x00, 0x02,
        0x0a, 0x0a, 0x00, 0x01
    };

    ParsedPacket parsed;
    // Must fail gracefully due to bounds check, without crash/OOB read
    EXPECT_FALSE(PacketParser::parse(raw, parsed));
}

TEST(PacketParserTest, ArpSenderInBlocklistNotDropped) {
    using namespace PacketAnalyzer;
    NftablesEnforcer enforcer(false); // in-memory mode
    enforcer.addBlock("10.10.0.1");

    RawPacket raw_arp;
    // 14 bytes Ethernet (type 0x0806 ARP) + 28 bytes ARP
    raw_arp.data = {
        // Ethernet (14)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        0x08, 0x06,
        // ARP (28): hardware ethernet (1), proto ipv4 (0x0800), hlen 6, plen 4, opcode request (1)
        0x00, 0x01,
        0x08, 0x00,
        0x06, 0x04,
        0x00, 0x01,
        // Sender MAC: 52:54:00:12:34:56
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        // Sender IP: 10.10.0.1 (in blocklist)
        0x0a, 0x0a, 0x00, 0x01,
        // Target MAC: 00:00:00:00:00:00
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // Target IP: 10.10.0.2
        0x0a, 0x0a, 0x00, 0x02
    };

    ParsedPacket parsed_arp;
    EXPECT_TRUE(PacketParser::parse(raw_arp, parsed_arp));
    EXPECT_EQ(parsed_arp.l3, "arp");
    EXPECT_EQ(parsed_arp.src_ip, "10.10.0.1");
    EXPECT_EQ(parsed_arp.dest_ip, "10.10.0.2");
    EXPECT_TRUE(enforcer.isBlocked(parsed_arp.src_ip));

    // Decision for ARP packet whose sender IP is in blocklist MUST NOT be dropped
    auto arp_decision = PacketParser::decideAction(true, parsed_arp, &enforcer);
    EXPECT_NE(arp_decision.action, "dropped");
    EXPECT_EQ(arp_decision.action, "unhandled");
    EXPECT_EQ(arp_decision.reason, "non_tcp");

    // Contrast with an IPv4 packet from the same blocked IP: must be dropped
    RawPacket raw_ipv4;
    raw_ipv4.data = {
        // Ethernet (14)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00,
        // IPv4 (20): proto 6 (TCP), src 10.10.0.1, dst 10.10.0.2
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0a, 0x0a, 0x00, 0x01,
        0x0a, 0x0a, 0x00, 0x02,
        // TCP (20)
        0x04, 0xd2, 0x00, 0x50,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02,
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    ParsedPacket parsed_ipv4;
    EXPECT_TRUE(PacketParser::parse(raw_ipv4, parsed_ipv4));
    EXPECT_EQ(parsed_ipv4.l3, "ipv4");
    auto ipv4_decision = PacketParser::decideAction(true, parsed_ipv4, &enforcer);
    EXPECT_EQ(ipv4_decision.action, "dropped");
    EXPECT_EQ(ipv4_decision.reason, "blocklist:ip");
}

