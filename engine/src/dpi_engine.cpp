#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <pcap.h>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "enforcer.h"
#include "flow_hash.h"
#include "packet_parser.h"
#include "pcap_reader.h"
#include "reporter.h"
#include "rule_subscriber.h"
#include "sni_extractor.h"
#include "thread_safe_queue.h"
#include "types.h"

using namespace DPI;
using namespace PacketAnalyzer;

std::shared_ptr<Reporter> global_reporter;

std::atomic<bool> keep_running{true};
std::atomic<bool> lb_keep_running{true};
std::atomic<bool> fp_keep_running{true};

pcap_t *global_pcap_handle = nullptr;

void signal_handler(int signum) {
  if (signum == SIGINT) {
    std::cout << "\n[SIGINT] Shutting down gracefully...\n";
    keep_running = false;
    if (global_pcap_handle) {
      pcap_breakloop(global_pcap_handle);
    }
  }
}

struct LBStats {
  std::atomic<uint64_t> dispatched{0};
};

struct FPStats {
  std::atomic<uint64_t> processed{0};
  std::atomic<uint64_t> forwarded{0};
  std::atomic<uint64_t> dropped{0};
  std::atomic<uint64_t> unhandled{0};

  std::atomic<uint64_t> tcp_packets{0};
  std::atomic<uint64_t> sni_found{0};
};

constexpr size_t WORKER_BATCH_SIZE = 256;
constexpr size_t READER_BATCH_SIZE = 128;

int num_lbs = 1;
int num_fps = 1;

std::vector<std::unique_ptr<ThreadSafeQueue<std::shared_ptr<RawPacket>>>>
    lb_queues;
std::vector<std::unique_ptr<ThreadSafeQueue<std::shared_ptr<RawPacket>>>>
    fp_queues;

std::vector<std::unique_ptr<LBStats>> lb_stats;
std::vector<std::unique_ptr<FPStats>> fp_stats;

std::atomic<uint64_t> total_read{0};
std::atomic<uint64_t> total_bytes{0};
std::atomic<uint64_t> total_dropped{0};
std::atomic<uint64_t> total_forwarded{0};
std::atomic<uint64_t> total_unhandled{0};

std::shared_ptr<Enforcer> global_enforcer = nullptr;

static void process_lb_packet(
    int id, const std::shared_ptr<RawPacket>& pkt_ptr,
    std::vector<std::vector<std::shared_ptr<RawPacket>>>& fp_batches) {
  ParsedPacket parsed;
  // Always parse to extract hash, but route it regardless of success/IP
  // presence If it's malformed or non-IP (ARP, etc), hash will be 0 and it
  // goes to FP[0]
  PacketParser::parse(*pkt_ptr, parsed);
  size_t h = hashParsedPacket(parsed);
  if (h == 0)
    h = lb_stats[id]->dispatched;

  int fp_idx = h % num_fps;
  fp_batches[fp_idx].push_back(pkt_ptr);
  lb_stats[id]->dispatched++;
  if (global_reporter) {
    global_reporter->incrementLBStat(id);
  }
}

void lb_thread_func(int id) {
  std::vector<std::shared_ptr<RawPacket>> batch;
  batch.reserve(WORKER_BATCH_SIZE);
  std::vector<std::vector<std::shared_ptr<RawPacket>>> fp_batches(num_fps);
  for (int i = 0; i < num_fps; ++i) {
    fp_batches[i].reserve(WORKER_BATCH_SIZE);
  }

  while (lb_keep_running || !lb_queues[id]->empty()) {
    batch.clear();
    size_t n = lb_queues[id]->popBatch(batch, WORKER_BATCH_SIZE,
                                        std::chrono::milliseconds(100));
    for (size_t i = 0; i < n; ++i) {
      process_lb_packet(id, batch[i], fp_batches);
    }
    for (int i = 0; i < num_fps; ++i) {
      if (!fp_batches[i].empty()) {
        fp_queues[i]->pushBatch(fp_batches[i]);
      }
    }
  }

  for (int i = 0; i < num_fps; ++i) {
    if (!fp_batches[i].empty()) {
      fp_queues[i]->pushBatch(fp_batches[i]);
    }
  }
}

static void process_fp_packet(int id, const std::shared_ptr<RawPacket>& pkt_ptr) {
  fp_stats[id]->processed++;

  ParsedPacket parsed;
  if (!PacketParser::parse(*pkt_ptr, parsed)) {
    // Entirely malformed packet (e.g. truncated ethernet frame)
    fp_stats[id]->dropped++;
    total_dropped++;
    if (global_reporter) {
      LogEvent ev;
      ev.l3 = "other";
      ev.action = "dropped";
      ev.reason = "malformed_ethernet";
      ev.thread_id = id;
      global_reporter->incrementStat("dropped");
      global_reporter->incrementFPStat(id, "dropped");
      global_reporter->tryPushLog(std::move(ev));
    }
  } else if (parsed.l3 == "ipv4" && global_enforcer &&
             !parsed.src_ip.empty() &&
             global_enforcer->isBlocked(parsed.src_ip)) {
    // Blocked source IP (dropped by blocklist rule - IPv4 only)
    fp_stats[id]->dropped++;
    total_dropped++;
    if (global_reporter) {
      LogEvent ev;
      ev.l3 = parsed.l3;
      ev.src_ip = parsed.src_ip;
      ev.dst_ip = parsed.dest_ip;
      ev.src_port = parsed.src_port;
      ev.dst_port = parsed.dest_port;
      ev.protocol = parsed.protocol;
      ev.action = "dropped";
      ev.reason = "blocklist:ip";
      ev.thread_id = id;
      ev.tcp_flags = parsed.tcp_flags;
      ev.icmp_type = parsed.icmp_type;
      global_reporter->incrementStat("dropped");
      global_reporter->incrementFPStat(id, "dropped");
      global_reporter->tryPushLog(std::move(ev));
    }
  } else if (parsed.has_tcp) {
    fp_stats[id]->forwarded++;
    total_forwarded++;
    fp_stats[id]->tcp_packets++;

    // Payload-based protocol classification for forwarded TCP packets
    if (parsed.payload_length == 0) {
      if (global_reporter)
        global_reporter->incrementProto(ProtoClass::TCP_CTRL);
    } else if (parsed.payload_length >= 5 &&
               (parsed.payload_data[0] == 0x14 ||
                parsed.payload_data[0] == 0x15 ||
                parsed.payload_data[0] == 0x16 ||
                parsed.payload_data[0] == 0x17) &&
               parsed.payload_data[1] == 0x03 &&
               parsed.payload_data[2] <= 0x04) {
      if (global_reporter)
        global_reporter->incrementProto(ProtoClass::TLS);
    } else if (([&]() {
                 std::string_view p(
                     reinterpret_cast<const char *>(parsed.payload_data),
                     parsed.payload_length);
                 return p.rfind("GET ", 0) == 0 ||
                        p.rfind("POST ", 0) == 0 ||
                        p.rfind("PUT ", 0) == 0 ||
                        p.rfind("HEAD ", 0) == 0 ||
                        p.rfind("DELETE ", 0) == 0 ||
                        p.rfind("OPTIONS ", 0) == 0 ||
                        p.rfind("PATCH ", 0) == 0 ||
                        p.rfind("HTTP/1.", 0) == 0;
               })()) {
      if (global_reporter)
        global_reporter->incrementProto(ProtoClass::HTTP);
    } else {
      if (global_reporter)
        global_reporter->incrementProto(ProtoClass::TCP_OTHER);
    }

    bool has_sni = false;
    std::string sni_val;
    if (parsed.payload_length > 0) {
      auto sni =
          SNIExtractor::extract(parsed.payload_data, parsed.payload_length);
      if (sni) {
        fp_stats[id]->sni_found++;
        has_sni = true;
        sni_val = *sni;
        if (global_reporter)
          global_reporter->incrementSniSeen();
      }
    }
    if (global_reporter) {
      LogEvent ev;
      ev.l3 = parsed.l3;
      ev.src_ip = parsed.src_ip;
      ev.dst_ip = parsed.dest_ip;
      ev.src_port = parsed.src_port;
      ev.dst_port = parsed.dest_port;
      ev.protocol = parsed.protocol;
      ev.sni = sni_val;
      ev.action = "forwarded";
      ev.reason = "clean";
      ev.thread_id = id;
      ev.tcp_flags = parsed.tcp_flags;
      ev.icmp_type = parsed.icmp_type;
      global_reporter->incrementStat("forwarded");
      global_reporter->incrementFPStat(id, "forwarded");
      global_reporter->tryPushLog(std::move(ev));
    }
  } else {
    // Non-TCP protocols and non-IPv4 frames (ARP, IPv6, UDP, ICMP)
    fp_stats[id]->unhandled++;
    total_unhandled++;
    if (global_reporter) {
      global_reporter->incrementStat("unhandled");
      global_reporter->incrementFPStat(id, "unhandled");
      LogEvent ev;
      ev.l3 = parsed.l3;
      ev.src_ip = parsed.src_ip;
      ev.dst_ip = parsed.dest_ip;
      ev.src_port = parsed.has_udp ? parsed.src_port : 0;
      ev.dst_port = parsed.has_udp ? parsed.dest_port : 0;
      ev.protocol = parsed.protocol;
      ev.action = "unhandled";
      ev.reason = "non_tcp";
      ev.thread_id = id;
      ev.tcp_flags = parsed.tcp_flags;
      ev.icmp_type = parsed.icmp_type;
      global_reporter->tryPushLog(std::move(ev));
    }
  }
}

void fp_thread_func(int id) {
  std::vector<std::shared_ptr<RawPacket>> batch;
  batch.reserve(WORKER_BATCH_SIZE);
  while (fp_keep_running || !fp_queues[id]->empty()) {
    batch.clear();
    size_t n = fp_queues[id]->popBatch(batch, WORKER_BATCH_SIZE,
                                        std::chrono::milliseconds(100));
    for (size_t i = 0; i < n; ++i) {
      process_fp_packet(id, batch[i]);
    }
  }
}
// Resolve the Redis password without hardcoding it:
// 1) REDIS_PASSWORD env var (used by Docker), 2) --redis-password-file (used
// under sudo).
static std::string resolveRedisPassword(const std::string &password_file) {
  if (const char *env = std::getenv("REDIS_PASSWORD"); env && *env) {
    return env;
  }
  if (!password_file.empty()) {
    std::ifstream in(password_file);
    std::string pw;
    if (in && std::getline(in, pw)) {
      while (!pw.empty() &&
             (pw.back() == '\r' || pw.back() == '\n' || pw.back() == ' '))
        pw.pop_back();
      return pw;
    }
    std::cerr << "[WARNING] Could not read Redis password file: "
              << password_file << "\n";
  }
  return "";
}
int main(int argc, char *argv[]) {
  std::cout << std::unitbuf;

  std::string input_pcap;
  std::string output_pcap;
  std::string live_iface;
  std::string block_ip;
  std::string redis_host = "127.0.0.1";
  std::string redis_password_file;
  size_t log_queue_size = DEFAULT_LOG_QUEUE_CAPACITY;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--lbs" && i + 1 < argc) {
      num_lbs = std::stoi(argv[++i]);
    } else if (arg == "--fps" && i + 1 < argc) {
      num_fps = std::stoi(argv[++i]);
    } else if (arg == "--live" && i + 1 < argc) {
      live_iface = argv[++i];
    } else if (arg == "--replay" && i + 1 < argc) {
      input_pcap = argv[++i];
    } else if (arg == "--block-ip" && i + 1 < argc) {
      block_ip = argv[++i];
    } else if (arg == "--redis-password-file" && i + 1 < argc) {
      redis_password_file = argv[++i];
    } else if (arg == "--redis-host" && i + 1 < argc) {
      redis_host = argv[++i];
    } else if (arg == "--log-queue-size") {
      if (i + 1 >= argc) {
        std::cerr << "Error: --log-queue-size requires a positive integer argument\n";
        return 1;
      }
      std::string val = argv[++i];
      try {
        size_t pos = 0;
        long long parsed = std::stoll(val, &pos);
        if (pos != val.size() || parsed <= 0) {
          std::cerr << "Error: --log-queue-size must be a positive integer\n";
          return 1;
        }
        log_queue_size = static_cast<size_t>(parsed);
      } catch (...) {
        std::cerr << "Error: --log-queue-size must be a positive integer\n";
        return 1;
      }
    } else if (input_pcap.empty() && live_iface.empty()) {
      input_pcap = arg;
    } else if (output_pcap.empty()) {
      output_pcap = arg;
    }
  }

  if (input_pcap.empty() && live_iface.empty()) {
    std::cerr << "Usage: " << argv[0]
              << " [--replay <file> | --live <iface>] [--lbs N] [--fps N] "
                 "[--block-ip <ip>] [--redis-host <ip>] [--redis-password-file "
                 "<path>] [--log-queue-size <n>]\n";
    return 1;
  }

  std::signal(SIGINT, signal_handler);

  std::cout << "dpi_engine: Multi-threaded DPI Engine starting...\n";
  if (!live_iface.empty()) {
    std::cout << "Mode: LIVE (Interface: " << live_iface << ")\n";
  } else {
    std::cout << "Mode: REPLAY (File: " << input_pcap << ")\n";
  }
  std::cout << "Configured with " << num_lbs << " Load Balancer(s) and "
            << num_fps << " Fast Path(s).\n";
  std::cout << "Reporter queue capacity: " << log_queue_size << "\n";

  std::shared_ptr<Enforcer> enforcer;
  if (!live_iface.empty()) {
    enforcer = std::make_shared<NftablesEnforcer>(true);
    if (!enforcer->initialize()) {
      std::cerr << "[ERROR] Failed to initialize NftablesEnforcer. Are you "
                   "running as root?\n";
      return 1;
    }
  } else {
    enforcer = std::make_shared<NftablesEnforcer>(false);
    enforcer->initialize();
  }
  global_enforcer = enforcer;

  if (!block_ip.empty()) {
    if (enforcer) {
      if (enforcer->addBlock(block_ip)) {
        std::cout << "[ENFORCER] Added block rule for IP: " << block_ip << "\n";
      } else {
        std::cerr << "[ERROR] Failed to add block rule for IP: " << block_ip
                  << " (Invalid format?)\n";
      }
    } else {
      std::cout << "[ENFORCER] Skipped block rule for IP: " << block_ip
                << " (Replay mode)\n";
    }
  }
  const std::string redis_password = resolveRedisPassword(redis_password_file);
  std::shared_ptr<sw::redis::Redis> redis_client;
  try {
    sw::redis::ConnectionOptions opts;
    opts.host = redis_host;
    opts.port = 6379;
    opts.password = redis_password;
    opts.socket_timeout = std::chrono::milliseconds(200);

    redis_client = std::make_shared<sw::redis::Redis>(opts);
    redis_client->ping();
    std::cout << "[REDIS] Connected successfully to " << redis_host
              << ":6379\n";

    std::vector<std::string> ips;
    redis_client->smembers("blocklist:ips", std::back_inserter(ips));
    for (const auto &ip : ips) {
      if (enforcer && enforcer->addBlock(ip)) {
        std::cout << "[ENFORCER] Loaded IP from Redis: " << ip << "\n";
      }
    }
  } catch (const sw::redis::Error &e) {
    std::cerr << "[WARNING] Redis is unreachable at startup: " << e.what()
              << "\n";
    std::cerr
        << "[WARNING] Failing open: Continuing without Redis connection.\n";
    redis_client.reset();
  }

  std::atomic<uint64_t> bytes_total{0};
  std::atomic<uint64_t> pcap_recv{0};
  std::atomic<uint64_t> pcap_drop{0};
  std::atomic<uint64_t> pcap_ifdrop{0};

  global_reporter = std::make_shared<Reporter>(redis_client, log_queue_size);
  global_reporter->setCaptureStatsSources(&bytes_total, &pcap_recv, &pcap_drop,
                                          &pcap_ifdrop);
  global_reporter->start();
  std::string iface_label = !live_iface.empty() ? live_iface : "offline";
  global_reporter->initRedisStats(num_lbs, num_fps, iface_label);

  std::shared_ptr<RuleSubscriber> rule_subscriber;
  if (redis_client && enforcer) {
    rule_subscriber =
        std::make_shared<RuleSubscriber>(redis_host, redis_password, enforcer);
    rule_subscriber->start();
  }

  for (int i = 0; i < num_lbs; ++i) {
    lb_queues.push_back(
        std::make_unique<ThreadSafeQueue<std::shared_ptr<RawPacket>>>());
    lb_stats.push_back(std::make_unique<LBStats>());
  }
  for (int i = 0; i < num_fps; ++i) {
    fp_queues.push_back(
        std::make_unique<ThreadSafeQueue<std::shared_ptr<RawPacket>>>());
    fp_stats.push_back(std::make_unique<FPStats>());
  }

  std::vector<std::thread> lb_threads;
  std::vector<std::thread> fp_threads;
  for (int i = 0; i < num_lbs; ++i)
    lb_threads.emplace_back(lb_thread_func, i);
  for (int i = 0; i < num_fps; ++i)
    fp_threads.emplace_back(fp_thread_func, i);

  std::chrono::steady_clock::time_point start_time;
  bool timing_started = false;

  if (!live_iface.empty()) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle =
        pcap_open_live(live_iface.c_str(), 65535, 1, 100, errbuf);
    if (!pcap_handle) {
      std::cerr << "Error opening live interface " << live_iface << ": "
                << errbuf << "\n";
      keep_running = false;
    } else {
      global_pcap_handle = pcap_handle;
      struct pcap_pkthdr *header;
      const u_char *data;
      auto last_pcap_stats_time = std::chrono::steady_clock::now();
      while (keep_running) {
        int ret = pcap_next_ex(pcap_handle, &header, &data);

        auto now = std::chrono::steady_clock::now();
        if (now - last_pcap_stats_time >= std::chrono::seconds(1)) {
          struct pcap_stat ps;
          if (pcap_stats(pcap_handle, &ps) == 0) {
            pcap_recv.store(ps.ps_recv, std::memory_order_relaxed);
            pcap_drop.store(ps.ps_drop, std::memory_order_relaxed);
            pcap_ifdrop.store(ps.ps_ifdrop, std::memory_order_relaxed);
          }
          last_pcap_stats_time = now;
        }

        if (ret == 0)
          continue; // Timeout
        if (ret < 0)
          break; // EOF or Error

        if (!timing_started) {
          start_time = std::chrono::steady_clock::now();
          timing_started = true;
        }

        total_read++;
        bytes_total += header->len;
        RawPacket raw;
        raw.header.ts_sec = header->ts.tv_sec;
        raw.header.ts_usec = header->ts.tv_usec;
        raw.header.incl_len = header->caplen;
        raw.header.orig_len = header->len;
        raw.data.assign(data, data + header->caplen);
        total_bytes += raw.data.size();

        // Directly distribute to LBs. Parsing in Reader is redundant overhead.
        int lb_idx = total_read % num_lbs;
        lb_queues[lb_idx]->push(std::make_shared<RawPacket>(std::move(raw)));
      }
      pcap_close(pcap_handle);
    }
  } else {
    PcapReader reader;
    if (!reader.open(input_pcap)) {
      keep_running = false;
    } else {
      std::vector<std::vector<std::shared_ptr<RawPacket>>> lb_batches(num_lbs);
      for (int i = 0; i < num_lbs; ++i) {
        lb_batches[i].reserve(READER_BATCH_SIZE);
      }

      RawPacket raw;
      while (keep_running && reader.readNextPacket(raw)) {
        if (!timing_started) {
          start_time = std::chrono::steady_clock::now();
          timing_started = true;
        }
        total_read++;
        bytes_total += raw.header.orig_len;
        total_bytes += raw.data.size();
        // Directly distribute to LBs.
        int lb_idx = total_read % num_lbs;
        lb_batches[lb_idx].push_back(
            std::make_shared<RawPacket>(std::move(raw)));
        if (lb_batches[lb_idx].size() >= READER_BATCH_SIZE) {
          lb_queues[lb_idx]->pushBatch(lb_batches[lb_idx]);
        }
      }

      // Flush any remaining packets before stopping LB threads
      for (int i = 0; i < num_lbs; ++i) {
        if (!lb_batches[i].empty()) {
          lb_queues[i]->pushBatch(lb_batches[i]);
        }
      }
    }
  }

  // Graceful Shutdown
  keep_running = false;
  lb_keep_running = false;
  for (auto &t : lb_threads)
    t.join();

  fp_keep_running = false;
  for (auto &t : fp_threads)
    t.join();

  auto end_time = std::chrono::steady_clock::now();

  if (global_reporter) {
    global_reporter->stop();
  }
  if (rule_subscriber) {
    rule_subscriber->stop();
  }

  if (enforcer) {
    enforcer->teardown();
    std::cout << "[ENFORCER] Cleaned up nftables state.\n";
  }

  // Print Summary
  std::cout << "\n=== DPI Engine Summary ===\n";
  std::cout << "Total Packets Read : " << total_read << "\n";
  std::cout << "Packets Forwarded  : " << total_forwarded << "\n";
  std::cout << "Packets Dropped    : " << total_dropped << "\n";
  std::cout << "Packets Unhandled  : " << total_unhandled << "\n";
  if (global_reporter) {
    std::cout << "Reporter Q Drops : " << global_reporter->getDroppedLogEvents()
              << "\n";
    std::cout << "Reporter Redis Failures : "
              << global_reporter->getFailedLogEvents() << "\n";
  }

  double processing_seconds = 0.0;
  uint64_t throughput_pps = 0;
  double throughput_mbps = 0.0;
  if (timing_started && total_read > 0) {
    processing_seconds =
        std::chrono::duration<double>(end_time - start_time).count();
    if (processing_seconds > 0.0) {
      throughput_pps = static_cast<uint64_t>(
          static_cast<double>(total_read) / processing_seconds);
      throughput_mbps =
          (static_cast<double>(total_bytes) * 8.0) / processing_seconds / 1e6;
    }
  }

  std::cout << std::fixed;
  std::cout << "Processing Time (s): " << std::setprecision(3)
            << processing_seconds << "\n";
  std::cout << "Throughput (pps)   : " << throughput_pps << "\n";
  std::cout << "Throughput (Mbps)  : " << std::setprecision(2)
            << throughput_mbps << "\n";
  std::cout << std::defaultfloat;
  std::cout << "\n";

  std::cout << "--- Load Balancer Stats ---\n";
  for (int i = 0; i < num_lbs; ++i) {
    std::cout << "LB[" << i << "] dispatched : " << lb_stats[i]->dispatched
              << "\n";
  }

  std::cout << "\n--- Fast Path Stats ---\n";
  for (int i = 0; i < num_fps; ++i) {
    std::cout << "FP[" << i << "] processed  : " << fp_stats[i]->processed
              << " (Forwarded: " << fp_stats[i]->forwarded
              << ", Unhandled: " << fp_stats[i]->unhandled
              << ", Dropped: " << fp_stats[i]->dropped
              << " | TCP: " << fp_stats[i]->tcp_packets
              << ", SNI found: " << fp_stats[i]->sni_found << ")\n";
  }
  std::cout << "==========================\n";

  return 0;
}
