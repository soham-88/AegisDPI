#ifndef THREAD_SAFE_QUEUE_H
#define THREAD_SAFE_QUEUE_H

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include <vector>

namespace DPI {

// ============================================================================
// Thread-safe queue with hysteresis and batch consumption/production.
//
// Performance design rationale:
// In a naive bounded queue, every pop wakes a blocked producer (which pushes
// one item and sleeps again), and every push wakes a consumer. When queues are
// near capacity or drained faster than produced, this creates a CPU-intensive
// "ping-pong" effect where threads spend the majority of their CPU time in
// kernel voluntary context switching (~2.2 switches per packet).
//
// To eliminate context-switch ping-pong:
// 1. Consumer batching (popBatch): Consumers fetch up to max_items at once under
//    a single lock acquisition, amortizing mutex and condition variable overhead.
// 2. Producer batching (pushBatch): Producers insert batches of items under a
//    single lock acquisition whenever capacity allows, waking consumers only
//    when necessary and dramatically reducing futex wakeups.
// 3. Producer notification pruning: Producers only notify not_empty_ if
//    waiting_consumers_ > 0, avoiding spurious condition variable signaling when
//    the consumer is actively running and processing a batch.
// 4. Low-watermark hysteresis: Consumers only wake blocked producers when
//    waiting_producers_ > 0 AND the queue has drained to or below low_watermark_
//    (set to max_size_ / 2, at least 1). This allows producers to push in
//    substantial bursts rather than waking for single-item trickles.
// ============================================================================
template<typename T>
class ThreadSafeQueue {
public:
    ThreadSafeQueue(size_t max_size = 10000)
        : max_size_(max_size),
          low_watermark_(std::max<size_t>(1, max_size / 2)) {}
    
    // Push item to queue (blocks if full)
    void push(T item) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_ && !shutdown_) {
            ++waiting_producers_;
            not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
            --waiting_producers_;
        }
        
        if (shutdown_) return;
        
        queue_.push(std::move(item));
        if (waiting_consumers_ > 0) {
            not_empty_.notify_one();
        }
    }
    
    // Try to push without blocking
    bool tryPush(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (queue_.size() >= max_size_ || shutdown_) {
            return false;
        }
        queue_.push(std::move(item));
        if (waiting_consumers_ > 0) {
            not_empty_.notify_one();
        }
        return true;
    }
    
    // Push batch of items (blocks if full, moves all items and clears items)
    void pushBatch(std::vector<T>& items) {
        if (items.empty()) return;

        std::unique_lock<std::mutex> lock(mutex_);
        size_t idx = 0;
        const size_t total = items.size();

        while (idx < total) {
            if (queue_.size() >= max_size_ && !shutdown_) {
                ++waiting_producers_;
                not_full_.wait(lock, [this] { return queue_.size() < max_size_ || shutdown_; });
                --waiting_producers_;
            }

            if (shutdown_) {
                items.clear();
                return;
            }

            bool inserted_any = false;
            while (idx < total && queue_.size() < max_size_) {
                queue_.push(std::move(items[idx++]));
                inserted_any = true;
            }

            if (inserted_any && waiting_consumers_ > 0) {
                not_empty_.notify_one();
            }
        }

        items.clear();
    }
    
    // Pop item from queue (blocks if empty)
    std::optional<T> pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.empty() && !shutdown_) {
            ++waiting_consumers_;
            not_empty_.wait(lock, [this] { return !queue_.empty() || shutdown_; });
            --waiting_consumers_;
        }
        
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        if (waiting_producers_ > 0 && queue_.size() <= low_watermark_) {
            not_full_.notify_all();
        }
        return item;
    }
    
    // Pop with timeout
    std::optional<T> popWithTimeout(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.empty() && !shutdown_) {
            ++waiting_consumers_;
            bool acquired = not_empty_.wait_for(lock, timeout, [this] {
                return !queue_.empty() || shutdown_;
            });
            --waiting_consumers_;
            if (!acquired) {
                return std::nullopt;  // Timeout
            }
        }
        
        if (queue_.empty()) return std::nullopt;
        
        T item = std::move(queue_.front());
        queue_.pop();
        if (waiting_producers_ > 0 && queue_.size() <= low_watermark_) {
            not_full_.notify_all();
        }
        return item;
    }
    
    // Pop batch of items (waits like popWithTimeout, appends up to max_items)
    size_t popBatch(std::vector<T>& out, size_t max_items, std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.empty() && !shutdown_) {
            ++waiting_consumers_;
            bool acquired = not_empty_.wait_for(lock, timeout, [this] {
                return !queue_.empty() || shutdown_;
            });
            --waiting_consumers_;
            if (!acquired) {
                return 0;  // Timeout
            }
        }
        
        if (queue_.empty()) return 0;
        
        size_t count = 0;
        while (!queue_.empty() && count < max_items) {
            out.push_back(std::move(queue_.front()));
            queue_.pop();
            ++count;
        }
        
        if (waiting_producers_ > 0 && queue_.size() <= low_watermark_) {
            not_full_.notify_all();
        }
        return count;
    }
    
    // Check if empty
    bool empty() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }
    
    // Get current size
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
    
    // Signal shutdown (wake up all waiting threads)
    void shutdown() {
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_ = true;
        not_empty_.notify_all();
        not_full_.notify_all();
    }
    
    bool isShutdown() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return shutdown_;
    }

private:
    std::queue<T> queue_;
    mutable std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    size_t max_size_;
    size_t low_watermark_;
    size_t waiting_consumers_ = 0;
    size_t waiting_producers_ = 0;
    bool shutdown_ = false;
};

} // namespace DPI

#endif // THREAD_SAFE_QUEUE_H
