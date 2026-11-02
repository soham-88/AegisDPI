#ifndef FLOW_HASH_H
#define FLOW_HASH_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <functional>
#include "packet_parser.h"

inline size_t hashParsedPacket(const PacketAnalyzer::ParsedPacket& parsed) {
    size_t h = 0;
    if (parsed.has_tcp || parsed.has_udp) {
        // Compare (src_ip, src_port) and (dest_ip, dest_port) by const reference
        // (compare IP string first, then port) to guarantee canonical endpoint ordering
        bool src_is_lower = (parsed.src_ip < parsed.dest_ip) ||
                            (parsed.src_ip == parsed.dest_ip && parsed.src_port < parsed.dest_port);

        const std::string& low_ip = src_is_lower ? parsed.src_ip : parsed.dest_ip;
        const std::string& high_ip = src_is_lower ? parsed.dest_ip : parsed.src_ip;
        uint16_t low_port = src_is_lower ? parsed.src_port : parsed.dest_port;
        uint16_t high_port = src_is_lower ? parsed.dest_port : parsed.src_port;

        // Existing combiner applied in canonical order: low.ip, high.ip, low.port, high.port, proto
        h ^= std::hash<std::string>{}(low_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(high_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(low_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(high_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(parsed.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
}

#endif // FLOW_HASH_H
