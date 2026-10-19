// Component-only race harness for CVE-2026-58313.
// Uses synthetic cache keys and the pinned upstream LruCacheUtil header.
// It does not build or exercise an OpenHarmony product.
#include <atomic>
#include <cstddef>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#ifndef LRU_HEADER
#error "Compile with -DLRU_HEADER=\"path/to/lru_cache_util.h\""
#endif
#include LRU_HEADER

using Cache = OHOS::AppDomainVerify::LruCacheUtil<std::string, std::string>;

int main()
{
    Cache cache(32);
    for (int i = 0; i < 32; ++i) {
        cache.Put("key-" + std::to_string(i), "value-" + std::to_string(i));
    }

    std::atomic<unsigned> ready{0};
    std::atomic<bool> start{false};
    std::vector<std::thread> workers;
    for (int worker = 0; worker < 8; ++worker) {
        workers.emplace_back([&, worker] {
            ready.fetch_add(1, std::memory_order_release);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < 150000; ++i) {
                const auto key = "key-" + std::to_string((i + worker) % 32);
                if (worker % 3 == 0) {
                    std::string value;
                    (void)cache.Get(key, value);
                } else if (worker % 3 == 1) {
                    cache.Put(key, "new-" + std::to_string(i));
                } else if ((i % 4) == 0) {
                    cache.Clear();
                } else {
                    cache.Put(key, "refill-" + std::to_string(i));
                }
            }
        });
    }

    while (ready.load(std::memory_order_acquire) != workers.size()) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    for (auto& worker : workers) {
        worker.join();
    }
    std::cout << "completed synthetic concurrent cache workload\n";
    return 0;
}