#include "singleton.h"

#include <atomic>
#include <cstdio>
#include <thread>

// Minimal isolated multithread harness for the DelayedSingleton<T>
// GetInstance/DestroyInstance shared_ptr race. It is intentionally a narrow
// trigger harness, not a general PoC executor and not a vulnerability verdict.

class Payload {
public:
    Payload() : value_(0x12345678) {}
    ~Payload() { value_ = 0xdeadbeef; }

    int value_;
    char padding_[64];
};

int main() {
    using Singleton = OHOS::DelayedSingleton<Payload>;
    constexpr int rounds = 200000;
    std::atomic<bool> start{false};

    std::thread reader([&]() {
        while (!start.load(std::memory_order_relaxed)) {
        }
        for (int i = 0; i < rounds; ++i) {
            std::shared_ptr<Payload> ptr = Singleton::GetInstance();
            if (ptr) {
                volatile int observed = ptr->value_;
                (void)observed;
            }
        }
    });

    std::thread destroyer([&]() {
        while (!start.load(std::memory_order_relaxed)) {
        }
        for (int i = 0; i < rounds; ++i) {
            Singleton::DestroyInstance();
        }
    });

    start.store(true, std::memory_order_relaxed);
    reader.join();
    destroyer.join();
    return 0;
}
