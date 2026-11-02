#include <gtest/gtest.h>
#include "thread_safe_queue.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

// 1. Single-thread FIFO: push 1..1000, pop all, order preserved.
TEST(QueueTest, SingleThreadFifoOrderPreserved) {
    DPI::ThreadSafeQueue<int> q(2000);
    for (int i = 1; i <= 1000; ++i) {
        q.push(i);
    }
    EXPECT_EQ(q.size(), 1000u);

    for (int i = 1; i <= 1000; ++i) {
        auto val = q.pop();
        ASSERT_TRUE(val.has_value());
        EXPECT_EQ(*val, i);
    }

    EXPECT_TRUE(q.empty());
    EXPECT_EQ(q.size(), 0u);
}

// 2. popBatch returns at most max_items, appends (does not clear), returns 0 after timeout on an empty queue (use a 20 ms timeout).
TEST(QueueTest, PopBatchBehavior) {
    DPI::ThreadSafeQueue<int> q(100);
    std::vector<int> out;

    // Timeout on empty queue returns 0
    auto t0 = std::chrono::steady_clock::now();
    size_t count = q.popBatch(out, 10, std::chrono::milliseconds(20));
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    EXPECT_EQ(count, 0u);
    EXPECT_TRUE(out.empty());
    EXPECT_GE(elapsed.count(), 15);

    // Pre-populate vector to verify popBatch appends (does not clear)
    out = {998, 999};
    for (int i = 1; i <= 5; ++i) {
        q.push(i);
    }
    EXPECT_EQ(q.size(), 5u);

    // Returns at most max_items (requesting 3 out of 5)
    count = q.popBatch(out, 3, std::chrono::milliseconds(20));
    EXPECT_EQ(count, 3u);
    EXPECT_EQ(out.size(), 5u);
    std::vector<int> expected_first = {998, 999, 1, 2, 3};
    EXPECT_EQ(out, expected_first);
    EXPECT_EQ(q.size(), 2u);

    // Pop remaining items (requesting up to 10 when only 2 remain)
    count = q.popBatch(out, 10, std::chrono::milliseconds(20));
    EXPECT_EQ(count, 2u);
    EXPECT_EQ(out.size(), 7u);
    std::vector<int> expected_all = {998, 999, 1, 2, 3, 4, 5};
    EXPECT_EQ(out, expected_all);
    EXPECT_TRUE(q.empty());
}

// 3. Stress, multi-producer single-consumer with a tiny queue to force blocking:
//    max_size = 64, 4 producer threads each push 200000 items encoded as (producer_id, seq);
//    one consumer uses popBatch(…, 32, 50ms) until it has received 800000 items.
//    Assert: total count = 800000, and for each producer the seq numbers arrive strictly increasing (per-producer FIFO).
//    The test must finish (no deadlock) — run it with a reasonable overall time budget.
struct WorkItem {
    uint32_t producer_id;
    uint32_t seq;
};

TEST(QueueTest, MultiProducerSingleConsumerStress) {
    constexpr size_t QUEUE_MAX_SIZE = 64;
    constexpr size_t NUM_PRODUCERS = 4;
    constexpr size_t ITEMS_PER_PRODUCER = 200000;
    constexpr size_t TOTAL_ITEMS = NUM_PRODUCERS * ITEMS_PER_PRODUCER;

    DPI::ThreadSafeQueue<WorkItem> q(QUEUE_MAX_SIZE);

    std::vector<std::thread> producers;
    producers.reserve(NUM_PRODUCERS);
    for (uint32_t p = 0; p < NUM_PRODUCERS; ++p) {
        producers.emplace_back([&q, p]() {
            for (uint32_t seq = 0; seq < ITEMS_PER_PRODUCER; ++seq) {
                q.push({p, seq});
            }
        });
    }

    std::vector<int64_t> last_seq(NUM_PRODUCERS, -1);
    std::vector<WorkItem> batch;
    batch.reserve(32);
    size_t total_received = 0;

    auto start_time = std::chrono::steady_clock::now();
    while (total_received < TOTAL_ITEMS) {
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count() > 30) {
            FAIL() << "Stress test timed out after 30 seconds; potential deadlock";
            break;
        }

        batch.clear();
        size_t n = q.popBatch(batch, 32, std::chrono::milliseconds(50));
        for (size_t i = 0; i < n; ++i) {
            const auto& item = batch[i];
            ASSERT_LT(item.producer_id, NUM_PRODUCERS);
            EXPECT_EQ(static_cast<int64_t>(item.seq), last_seq[item.producer_id] + 1);
            last_seq[item.producer_id] = static_cast<int64_t>(item.seq);
            ++total_received;
        }
    }

    for (auto& t : producers) {
        if (t.joinable()) {
            t.join();
        }
    }

    EXPECT_EQ(total_received, TOTAL_ITEMS);
    for (size_t p = 0; p < NUM_PRODUCERS; ++p) {
        EXPECT_EQ(last_seq[p], static_cast<int64_t>(ITEMS_PER_PRODUCER - 1));
    }
}

// 4. Shutdown wakes a producer blocked on a full queue and a consumer blocked on an empty queue (both threads must return/join).
TEST(QueueTest, ShutdownWakesBlockedProducerAndConsumer) {
    // 1. Producer blocked on full queue
    DPI::ThreadSafeQueue<int> full_q(1);
    full_q.push(10); // Queue is full (1/1)

    std::atomic<bool> producer_started{false};
    std::thread producer([&full_q, &producer_started]() {
        producer_started = true;
        full_q.push(20); // Blocks on full queue
    });

    while (!producer_started) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // 2. Consumer blocked on empty queue
    DPI::ThreadSafeQueue<int> empty_q(10);
    std::atomic<bool> consumer_started{false};
    std::atomic<bool> consumer_woke{false};
    std::thread consumer([&empty_q, &consumer_started, &consumer_woke]() {
        consumer_started = true;
        auto item = empty_q.pop(); // Blocks on empty queue
        EXPECT_FALSE(item.has_value());
        consumer_woke = true;
    });

    while (!consumer_started) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Wake both threads via shutdown
    full_q.shutdown();
    empty_q.shutdown();

    producer.join();
    consumer.join();

    EXPECT_TRUE(full_q.isShutdown());
    EXPECT_TRUE(empty_q.isShutdown());
    EXPECT_TRUE(consumer_woke);
}

