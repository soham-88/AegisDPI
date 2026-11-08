#ifndef ENFORCER_H
#define ENFORCER_H

#include <string>
#include <regex>
#include <iostream>
#include <unordered_set>
#include <mutex>
#include <nftables/libnftables.h>

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
    struct nft_ctx* nft_{nullptr};

    bool isValidIPv4(const std::string& ip) {
        // Strict regex for IPv4 (and optional CIDR /1-32)
        std::regex ip_regex("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(/([1-9]|[1-2][0-9]|3[0-2]))?$");
        return std::regex_match(ip, ip_regex);
    }

    bool runCmdLocked(const std::string& cmd, bool ignore_errors = false) {
        if (!nft_) {
            return false;
        }
        int rc = nft_run_cmd_from_buffer(nft_, cmd.c_str());
        if (rc != 0) {
            const char* err = nft_ctx_get_error_buffer(nft_);
            if (!ignore_errors) {
                std::cerr << "[NftablesEnforcer] Command failed (" << rc << "): " << cmd << "\n";
                if (err && *err) {
                    std::cerr << "[NftablesEnforcer] Error buffer: " << err << "\n";
                }
            }
            return false;
        }
        return true;
    }

public:
    NftablesEnforcer(bool is_live = true) : is_live_(is_live) {
        if (is_live_) {
            nft_ = nft_ctx_new(NFT_CTX_DEFAULT);
            if (nft_) {
                nft_ctx_buffer_output(nft_);
                nft_ctx_buffer_error(nft_);
            } else {
                std::cerr << "[NftablesEnforcer] Failed to create nft_ctx\n";
            }
        }
    }

    ~NftablesEnforcer() override {
        teardown();
        std::lock_guard<std::mutex> lock(mutex_);
        if (nft_) {
            nft_ctx_free(nft_);
            nft_ = nullptr;
        }
    }

    bool initialize() override {
        if (!is_live_) return true;
        std::lock_guard<std::mutex> lock(mutex_);
        if (!nft_) {
            std::cerr << "[NftablesEnforcer] Cannot initialize: nft_ctx is null\n";
            return false;
        }

        // Pre-emptively wipe any left-over table from a prior crash to ensure clean state
        runCmdLocked("delete table inet aegis", true);

        bool ok = true;
        ok &= runCmdLocked("add table inet aegis");
        ok &= runCmdLocked("add chain inet aegis prerouting { type filter hook prerouting priority -300; }");
        ok &= runCmdLocked("add set inet aegis blocklist { type ipv4_addr; }");
        ok &= runCmdLocked("add rule inet aegis prerouting ip saddr @blocklist drop");
        return ok;
    }

    bool addBlock(const std::string& ip) override {
        if (!isValidIPv4(ip)) {
            std::cerr << "[NftablesEnforcer] Rejecting invalid IP/CIDR: " << ip << "\n";
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.insert(ip);
        if (ip.size() > 3 && ip.substr(ip.size() - 3) == "/32") {
            blocked_ips_.insert(ip.substr(0, ip.size() - 3));
        }
        if (!is_live_) return true;
        std::string cmd = "add element inet aegis blocklist { " + ip + " }";
        return runCmdLocked(cmd);
    }

    bool removeBlock(const std::string& ip) override {
        if (!isValidIPv4(ip)) {
            std::cerr << "[NftablesEnforcer] Rejecting invalid IP/CIDR: " << ip << "\n";
            return false;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.erase(ip);
        if (ip.size() > 3 && ip.substr(ip.size() - 3) == "/32") {
            blocked_ips_.erase(ip.substr(0, ip.size() - 3));
        }
        if (!is_live_) return true;
        std::string cmd = "delete element inet aegis blocklist { " + ip + " }";
        return runCmdLocked(cmd);
    }

    bool isBlocked(const std::string& ip) override {
        if (ip.empty()) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        return blocked_ips_.count(ip) > 0;
    }

    void teardown() override {
        std::lock_guard<std::mutex> lock(mutex_);
        blocked_ips_.clear();
        if (is_live_ && nft_) {
            runCmdLocked("delete table inet aegis", true);
        }
    }
};

#endif // ENFORCER_H
