#include "reporter.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <unistd.h>

namespace DPI {

Reporter::Reporter(std::shared_ptr<sw::redis::Redis> redis) 
    : redis_(redis), log_queue_(10000) {
    for (size_t i = 0; i < MAX_WORKERS; ++i) {
        lb_dispatched_[i].store(0);
        fp_processed_[i].store(0);
        fp_forwarded_[i].store(0);
        fp_dropped_[i].store(0);
        fp_unhandled_[i].store(0);
    }
}

Reporter::~Reporter() {
    stop();
}

void Reporter::start() {
    keep_running_ = true;
    thread_ = std::thread(&Reporter::threadFunc, this);
}

void Reporter::stop() {
    if (keep_running_) {
        keep_running_ = false;
        log_queue_.shutdown();
        if (thread_.joinable()) {
            thread_.join();
        }
    }
}

bool Reporter::tryPushLog(LogEvent event) {
    if (!log_queue_.tryPush(std::move(event))) {
        dropped_events_++;
        return false;
    }
    return true;
}

void Reporter::incrementStat(const std::string& stat_name) {
    if (stat_name == "forwarded") stat_forwarded_++;
    else if (stat_name == "dropped") stat_dropped_++;
    else if (stat_name == "unhandled") stat_unhandled_++;
}

void Reporter::incrementFPStat(int id, const std::string& action) {
    if (id >= 0 && static_cast<size_t>(id) < MAX_WORKERS) {
        fp_processed_[id]++;
        if (action == "forwarded") fp_forwarded_[id]++;
        else if (action == "dropped") fp_dropped_[id]++;
        else if (action == "unhandled") fp_unhandled_[id]++;
    }
}

void Reporter::incrementLBStat(int id) {
    if (id >= 0 && static_cast<size_t>(id) < MAX_WORKERS) {
        lb_dispatched_[id]++;
    }
}

void Reporter::incrementProto(ProtoClass c) {
    switch (c) {
        case ProtoClass::TLS: stat_proto_tls_++; break;
        case ProtoClass::HTTP: stat_proto_http_++; break;
        case ProtoClass::TCP_CTRL: stat_proto_tcp_ctrl_++; break;
        case ProtoClass::TCP_OTHER: stat_proto_tcp_other_++; break;
    }
}

void Reporter::incrementSniSeen() {
    stat_tls_sni_seen_++;
}

void Reporter::setCaptureStatsSources(const std::atomic<uint64_t>* bytes_total,
                                      const std::atomic<uint64_t>* pcap_recv,
                                      const std::atomic<uint64_t>* pcap_drop,
                                      const std::atomic<uint64_t>* pcap_ifdrop) {
    bytes_total_ptr_ = bytes_total;
    pcap_recv_ptr_ = pcap_recv;
    pcap_drop_ptr_ = pcap_drop;
    pcap_ifdrop_ptr_ = pcap_ifdrop;
}

void Reporter::initRedisStats(int num_lbs, int num_fps, const std::string& interface_name) {
    if (!redis_) return;
    try {
        redis_->del("dpi:stats");

        // Static metadata fields
        redis_->hset("dpi:stats", "interface", interface_name);
        redis_->hset("dpi:stats", "engine_pid", std::to_string(getpid()));
        redis_->hset("dpi:stats", "started_at", std::to_string(static_cast<int64_t>(std::time(nullptr))));

        // Dynamic capture stats initialized to 0
        redis_->hset("dpi:stats", "bytes_total", "0");
        redis_->hset("dpi:stats", "pcap_recv", "0");
        redis_->hset("dpi:stats", "pcap_drop", "0");
        redis_->hset("dpi:stats", "pcap_ifdrop", "0");

        // Protocol breakdown stats initialized to 0
        redis_->hset("dpi:stats", "proto_tls", "0");
        redis_->hset("dpi:stats", "proto_http", "0");
        redis_->hset("dpi:stats", "proto_tcp_ctrl", "0");
        redis_->hset("dpi:stats", "proto_tcp_other", "0");
        redis_->hset("dpi:stats", "tls_sni_seen", "0");

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        redis_->hset("dpi:stats", "updated_at_ms", std::to_string(now_ms));

        redis_->hset("dpi:stats", "forwarded", "0");
        redis_->hset("dpi:stats", "dropped", "0");
        redis_->hset("dpi:stats", "unhandled", "0");
        for (int i = 0; i < num_lbs; ++i) {
            redis_->hset("dpi:stats", "lb_" + std::to_string(i) + "_dispatched", "0");
        }
        for (int i = 0; i < num_fps; ++i) {
            redis_->hset("dpi:stats", "fp_" + std::to_string(i) + "_processed", "0");
            redis_->hset("dpi:stats", "fp_" + std::to_string(i) + "_forwarded", "0");
            redis_->hset("dpi:stats", "fp_" + std::to_string(i) + "_dropped", "0");
            redis_->hset("dpi:stats", "fp_" + std::to_string(i) + "_unhandled", "0");
        }
        redis_->publish("dpi:stats:updated", "1");
    } catch (...) {}
}

void Reporter::flushStats() {
    if (!redis_) return;

    try {
        auto tx = redis_->transaction();

        uint64_t total_fwd = 0;
        uint64_t total_drp = 0;
        uint64_t total_unh = 0;

        for (size_t i = 0; i < MAX_WORKERS; ++i) {
            uint64_t lb_d = lb_dispatched_[i].exchange(0);
            if (lb_d > 0) {
                tx.hincrby("dpi:stats", "lb_" + std::to_string(i) + "_dispatched", lb_d);
            }

            uint64_t fp_p = fp_processed_[i].exchange(0);
            if (fp_p > 0) {
                tx.hincrby("dpi:stats", "fp_" + std::to_string(i) + "_processed", fp_p);
            }

            uint64_t fp_f = fp_forwarded_[i].exchange(0);
            if (fp_f > 0) {
                tx.hincrby("dpi:stats", "fp_" + std::to_string(i) + "_forwarded", fp_f);
                total_fwd += fp_f;
            }

            uint64_t fp_d = fp_dropped_[i].exchange(0);
            if (fp_d > 0) {
                tx.hincrby("dpi:stats", "fp_" + std::to_string(i) + "_dropped", fp_d);
                total_drp += fp_d;
            }

            uint64_t fp_u = fp_unhandled_[i].exchange(0);
            if (fp_u > 0) {
                tx.hincrby("dpi:stats", "fp_" + std::to_string(i) + "_unhandled", fp_u);
                total_unh += fp_u;
            }
        }

        uint64_t standalone_fwd = stat_forwarded_.exchange(0);
        uint64_t standalone_drp = stat_dropped_.exchange(0);
        uint64_t standalone_unh = stat_unhandled_.exchange(0);
        uint64_t inc_proto_tls = stat_proto_tls_.exchange(0);
        uint64_t inc_proto_http = stat_proto_http_.exchange(0);
        uint64_t inc_proto_tcp_ctrl = stat_proto_tcp_ctrl_.exchange(0);
        uint64_t inc_proto_tcp_other = stat_proto_tcp_other_.exchange(0);
        uint64_t inc_tls_sni_seen = stat_tls_sni_seen_.exchange(0);

        uint64_t fwd_inc = total_fwd > 0 ? total_fwd : standalone_fwd;
        uint64_t drp_inc = total_drp > 0 ? total_drp : standalone_drp;
        uint64_t unh_inc = total_unh > 0 ? total_unh : standalone_unh;

        if (fwd_inc > 0) { tx.hincrby("dpi:stats", "forwarded", fwd_inc); }
        if (drp_inc > 0) { tx.hincrby("dpi:stats", "dropped", drp_inc); }
        if (unh_inc > 0) { tx.hincrby("dpi:stats", "unhandled", unh_inc); }
        if (inc_proto_tls > 0) { tx.hincrby("dpi:stats", "proto_tls", inc_proto_tls); }
        if (inc_proto_http > 0) { tx.hincrby("dpi:stats", "proto_http", inc_proto_http); }
        if (inc_proto_tcp_ctrl > 0) { tx.hincrby("dpi:stats", "proto_tcp_ctrl", inc_proto_tcp_ctrl); }
        if (inc_proto_tcp_other > 0) { tx.hincrby("dpi:stats", "proto_tcp_other", inc_proto_tcp_other); }
        if (inc_tls_sni_seen > 0) { tx.hincrby("dpi:stats", "tls_sni_seen", inc_tls_sni_seen); }

        if (bytes_total_ptr_) {
            tx.hset("dpi:stats", "bytes_total", std::to_string(bytes_total_ptr_->load(std::memory_order_relaxed)));
        }
        if (pcap_recv_ptr_) {
            tx.hset("dpi:stats", "pcap_recv", std::to_string(pcap_recv_ptr_->load(std::memory_order_relaxed)));
        }
        if (pcap_drop_ptr_) {
            tx.hset("dpi:stats", "pcap_drop", std::to_string(pcap_drop_ptr_->load(std::memory_order_relaxed)));
        }
        if (pcap_ifdrop_ptr_) {
            tx.hset("dpi:stats", "pcap_ifdrop", std::to_string(pcap_ifdrop_ptr_->load(std::memory_order_relaxed)));
        }

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        tx.hset("dpi:stats", "updated_at_ms", std::to_string(now_ms));

        tx.publish("dpi:stats:updated", "1");

        tx.exec();
    } catch (const std::exception& e) {
        std::cerr << "[REPORTER] flush failed: " << e.what() << "\n";
    }
}

void Reporter::threadFunc() {
    auto last_stat_flush = std::chrono::steady_clock::now();

    while (keep_running_ || !log_queue_.empty()) {
        auto opt_event = log_queue_.popWithTimeout(std::chrono::milliseconds(100));
        
        if (opt_event && redis_) {
            const auto& ev = *opt_event;
            try {
                redis_->xadd("dpi:logs", "*", {
                    std::make_pair("src_ip", ev.src_ip),
                    std::make_pair("dst_ip", ev.dst_ip),
                    std::make_pair("src_port", std::to_string(ev.src_port)),
                    std::make_pair("dst_port", std::to_string(ev.dst_port)),
                    std::make_pair("protocol", std::to_string(ev.protocol)),
                    std::make_pair("sni", ev.sni),
                    std::make_pair("action", ev.action),
                    std::make_pair("reason", ev.reason),
                    std::make_pair("thread_id", std::to_string(ev.thread_id)),
                    std::make_pair("tcp_flags", std::to_string(ev.tcp_flags)),
                    std::make_pair("icmp_type", std::to_string(ev.icmp_type)),
                    std::make_pair("l3", ev.l3)
                });
            } catch (const std::exception& e) {
                // Ignore redis connection issues silently so we don't spam stdout
            }
        }
        
        auto now = std::chrono::steady_clock::now();
        if (now - last_stat_flush > std::chrono::seconds(1)) {
            try {
                flushStats();
            } catch(...) {}
            last_stat_flush = now;
        }
    }
    
    // Final flush
    try {
        flushStats();
    } catch(...) {}
}

} // namespace DPI
