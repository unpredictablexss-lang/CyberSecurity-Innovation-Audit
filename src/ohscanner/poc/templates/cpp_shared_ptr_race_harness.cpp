#include "singleton.h"

#include <atomic>
#include <cstdlib>
#include <cstdio>
#include <thread>

namespace {
constexpr int kDefaultRounds = 200000;

class Payload {
public:
    Payload() : value_(0x12345678) {}
    ~Payload() { value_ = 0xdeadbeef; }

    int value_;
    char padding_[64];
};
}

int main(int argc, char** argv) {
    using Singleton = OHOS::DelayedSingleton<Payload>;
    int rounds = kDefaultRounds;
    if (argc > 1) {
        char* end = nullptr;
        long parsed = std::strtol(argv[1], &end, 10);
        if (end == argv[1] || *end != '\0' || parsed <= 0 || parsed > 10000000) {
            std::fprintf(stderr, "invalid round count\n");
            return 2;
        }
        rounds = static_cast<int>(parsed);
    }

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
