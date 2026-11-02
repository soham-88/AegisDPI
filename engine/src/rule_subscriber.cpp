#include "rule_subscriber.h"
#include <iostream>

namespace DPI {

RuleSubscriber::RuleSubscriber(const std::string &redis_host,
                               const std::string &redis_password,
                               std::shared_ptr<Enforcer> enforcer)
    : redis_host_(redis_host), redis_password_(redis_password),
      enforcer_(enforcer) {}

RuleSubscriber::~RuleSubscriber() { stop(); }

void RuleSubscriber::start() {
  keep_running_ = true;
  thread_ = std::thread(&RuleSubscriber::threadFunc, this);
}

void RuleSubscriber::stop() {
  if (keep_running_) {
    keep_running_ = false;
    try {
      // Wake up blocking subscriber by publishing QUIT
      sw::redis::ConnectionOptions opts;
      opts.host = redis_host_;
      opts.port = 6379;
      opts.password = redis_password_;
      opts.socket_timeout = std::chrono::milliseconds(500);
      sw::redis::Redis publisher(opts);
      publisher.publish("blocklist:updates", "QUIT");
    } catch (...) {
    }
    if (thread_.joinable()) {
      thread_.join();
    }
  }
}

void RuleSubscriber::handleMessage(std::string channel, std::string msg) {
  if (msg == "QUIT")
    return;
  std::cout << "[SUBSCRIBER] Received on " << channel << ": \"" << msg
            << "\"\n";
  // Format expected: "ADD IP 10.10.0.1" or "DEL IP 10.10.0.1"
  if (msg.rfind("ADD IP ", 0) == 0) {
    std::string ip = msg.substr(7);
    while (!ip.empty() &&
           (ip.back() == ' ' || ip.back() == '\r' || ip.back() == '\n'))
      ip.pop_back();
    if (enforcer_) {
      enforcer_->addBlock(ip);
      std::cout << "[SUBSCRIBER] Added rule for IP: " << ip << "\n";
    }
  } else if (msg.rfind("DEL IP ", 0) == 0) {
    std::string ip = msg.substr(7);
    while (!ip.empty() &&
           (ip.back() == ' ' || ip.back() == '\r' || ip.back() == '\n'))
      ip.pop_back();
    if (enforcer_) {
      enforcer_->removeBlock(ip);
      std::cout << "[SUBSCRIBER] Removed rule for IP: " << ip << "\n";
    }
  }
}

void RuleSubscriber::threadFunc() {
  sw::redis::ConnectionOptions opts;
  opts.host = redis_host_;
  opts.port = 6379;
  opts.password = redis_password_;
  // CRITICAL: socket_timeout must be 0 for Pub/Sub so hiredis doesn't time out
  // and kill the context!
  opts.socket_timeout = std::chrono::milliseconds(0);

  while (keep_running_) {
    try {
      auto sub_redis = std::make_shared<sw::redis::Redis>(opts);
      auto sub = sub_redis->subscriber();
      sub.on_message([this](std::string channel, std::string msg) {
        handleMessage(channel, msg);
      });
      sub.subscribe("blocklist:updates");
      std::cout << "[SUBSCRIBER] Subscribed to blocklist:updates on "
                << redis_host_ << ":6379\n";

      while (keep_running_) {
        try {
          sub.consume();
        } catch (const sw::redis::TimeoutError &) {
          continue;
        } catch (const sw::redis::Error &e) {
          if (keep_running_) {
            std::cerr << "[SUBSCRIBER] Connection error: " << e.what()
                      << ", reconnecting in 1s...\n";
            std::this_thread::sleep_for(std::chrono::seconds(1));
          }
          break;
        }
      }
    } catch (const std::exception &e) {
      if (keep_running_) {
        std::cerr << "[SUBSCRIBER] Failed to connect to Redis on "
                  << redis_host_ << ": " << e.what() << ", retrying in 2s...\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
      }
    }
  }
}

} // namespace DPI
