#ifndef RULE_SUBSCRIBER_H
#define RULE_SUBSCRIBER_H

#include "enforcer.h"
#include <atomic>
#include <memory>
#include <sw/redis++/redis++.h>
#include <thread>

namespace DPI {

class RuleSubscriber {
public:
  RuleSubscriber(const std::string &redis_host,
                 const std::string &redis_password,
                 std::shared_ptr<Enforcer> enforcer);
  ~RuleSubscriber();

  void start();
  void stop();

private:
  void threadFunc();
  void handleMessage(std::string channel, std::string msg);

  std::string redis_host_{"127.0.0.1"};
  std::string redis_password_;
  std::shared_ptr<Enforcer> enforcer_;
  std::thread thread_;
  std::atomic<bool> keep_running_{false};
};

} // namespace DPI

#endif // RULE_SUBSCRIBER_H
