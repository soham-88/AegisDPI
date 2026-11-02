#ifndef ENFORCER_H
#define ENFORCER_H

#include <string>
#include <regex>
#include <cstdlib>
#include <iostream>
#include <unordered_set>
#include <mutex>

class Enforcer {
public:
    virtual ~Enforcer() = default;
    virtual bool initialize() = 0;
    virtual bool addBlock(const std::string& ip_or_cidr) = 0;
    virtual bool removeBlock(const std::string& ip_or_cidr) = 0;
    virtual bool isBlocked(const std::string& ip) = 0;
    virtual void teardown() = 0;
};

class NftablesEnforcer : public Enforcer {
private:
    bool is_live_{true};
    std::unordered_set<std::string> blocked_ips_;
    mutable std::mutex mutex_;

    bool isValidIPv4(const std::string& ip) {
        // Strict regex for IPv4 (and optional CIDR /1-32)
        std::regex ip_regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/([1-9]|[1-2][0-9]|3[0-2]))?$");
        return std::regex_match(ip, ip_regex);
    }

public:
    NftablesEnforcer(bool is_live = true) : is_live_(is_live) {}

    bool initialize() override {
        if (!is_live_) return true;
        // Pre-emptively wipe any left-over table from a prior crash to ensure clean state
        if (std::system("nft delete table inet aegis >/dev/null 2>&1") != 0) {
            // Table may not exist yet, safe to ignore
        }
        
        bool ok = true;
        ok &= (std::system("nft add table inet aegis") == 0);
        ok &= (std::system("nft add chain inet aegis prerouting '{ type filter hook prerouting priority -300; }'") == 0);
        ok &= (std::system("nft add set inet aegis blocklist '{ type ipv4_addr; }'") == 0);
        ok &= (std::system("nft add rule inet aegis prerouting ip saddr @blocklist drop") == 0);
        return ok;
    }

    bool addBlock(const std::string& ip) override {
        if (!isValidIPv4(ip)) {
            std::cerr << "[NftablesEnforcer] Rejecting invalid IP/CIDR: " << ip << "\n";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            blocked_ips_.insert(ip);
            if (ip.size() > 3 && ip.substr(ip.size() - 3) == "/32") {
                blocked_ips_.insert(ip.substr(0, ip.size() - 3));
            }
        }
        if (!is_live_) return true;
        std::string cmd = "nft add element inet aegis blocklist '{ " + ip + " }'";
        int ret = std::system(cmd.c_str());
        if (ret != 0) {
            std::cerr << "[NftablesEnforcer] Command failed (" << ret << "): " << cmd << "\n";
            return false;
        }
        return true;
    }

    bool removeBlock(const std::string& ip) override {
        if (!isValidIPv4(ip)) {
            std::cerr << "[NftablesEnforcer] Rejecting invalid IP/CIDR: " << ip << "\n";
            return false;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            blocked_ips_.erase(ip);
            if (ip.size() > 3 && ip.substr(ip.size() - 3) == "/32") {
                blocked_ips_.erase(ip.substr(0, ip.size() - 3));
            }
        }
        if (!is_live_) return true;
        std::string cmd = "nft delete element inet aegis blocklist '{ " + ip + " }'";
        int ret = std::system(cmd.c_str());
        if (ret != 0) {
            std::cerr << "[NftablesEnforcer] Command failed (" << ret << "): " << cmd << "\n";
            return false;
        }
        return true;
    }

    bool isBlocked(const std::string& ip) override {
        if (ip.empty()) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_ips_.count(ip) > 0;
    }

    void teardown() override {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            blocked_ips_.clear();
        }
        if (is_live_) {
            if (std::system("nft delete table inet aegis >/dev/null 2>&1") != 0) {
                // Table may already be deleted or not exist
            }
        }
    }
};

#endif // ENFORCER_H
