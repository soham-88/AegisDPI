#ifndef REPORTER_H
#define REPORTER_H

#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <sw/redis++/redis++.h>
#include "thread_safe_queue.h"

namespace DPI {

struct LogEvent {
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    uint8_t protocol{0};
    std::string sni;
    std::string action;
    std::string reason;
    int thread_id{0};
    int tcp_flags{0};
    int icmp_type{-1};
    std::string l3{"other"};
};

enum class ProtoClass {
    TLS,
    HTTP,
    TCP_CTRL,
    TCP_OTHER
};

class Reporter {
public:
    // Pass pointer to Redis (can be null if running offline/disconnected)
    Reporter(std::shared_ptr<sw::redis::Redis> redis);
    ~Reporter();

    void start();
    void stop();

    static constexpr size_t MAX_WORKERS = 16;
    static constexpr long long LOG_STREAM_MAXLEN = 200000;

    // Fast path uses this. Returns false if queue is full.
    bool tryPushLog(LogEvent event);

    // Increment local stats to be flushed periodically
    void incrementStat(const std::string& stat_name);
    void incrementFPStat(int id, const std::string& action);
    void incrementLBStat(int id);
    void incrementProto(ProtoClass c);
    void incrementSniSeen();

    void setCaptureStatsSources(const std::atomic<uint64_t>* bytes_total,
                                const std::atomic<uint64_t>* pcap_recv,
                                const std::atomic<uint64_t>* pcap_drop,
                                const std::atomic<uint64_t>* pcap_ifdrop);

    void initRedisStats(int num_lbs, int num_fps, const std::string& interface_name);

    uint64_t getDroppedLogEvents() const { return dropped_events_.load(); }
    uint64_t getFailedLogEvents() const { return failed_events_.load(); }

private:
    void threadFunc();
    void flushStats();

    std::shared_ptr<sw::redis::Redis> redis_;
    ThreadSafeQueue<LogEvent> log_queue_;
    std::thread thread_;
    std::atomic<bool> keep_running_{false};
    std::atomic<uint64_t> dropped_events_{0};
    std::atomic<uint64_t> failed_events_{0};

    // Pointers to capture thread atomics
    const std::atomic<uint64_t>* bytes_total_ptr_{nullptr};
    const std::atomic<uint64_t>* pcap_recv_ptr_{nullptr};
    const std::atomic<uint64_t>* pcap_drop_ptr_{nullptr};
    const std::atomic<uint64_t>* pcap_ifdrop_ptr_{nullptr};

    // Stats aggregation before sending to Redis to avoid HINCRBY spam
    std::atomic<uint64_t> stat_forwarded_{0};
    std::atomic<uint64_t> stat_dropped_{0};
    std::atomic<uint64_t> stat_unhandled_{0};
    std::atomic<uint64_t> stat_proto_tls_{0};
    std::atomic<uint64_t> stat_proto_http_{0};
    std::atomic<uint64_t> stat_proto_tcp_ctrl_{0};
    std::atomic<uint64_t> stat_proto_tcp_other_{0};
    std::atomic<uint64_t> stat_tls_sni_seen_{0};

    // Per-worker thread counters
    std::atomic<uint64_t> lb_dispatched_[MAX_WORKERS];
    std::atomic<uint64_t> fp_processed_[MAX_WORKERS];
    std::atomic<uint64_t> fp_forwarded_[MAX_WORKERS];
    std::atomic<uint64_t> fp_dropped_[MAX_WORKERS];
    std::atomic<uint64_t> fp_unhandled_[MAX_WORKERS];
};

} // namespace DPI

#endif // REPORTER_H
