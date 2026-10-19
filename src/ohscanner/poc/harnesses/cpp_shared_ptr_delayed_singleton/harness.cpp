// Controlled workload for the real commonlibrary_c_utils singleton.h.
// It does not reimplement the affected class: the runner installs a verified
// vulnerable, upstream-fixed or fully-atomic-patched header as "singleton.h".
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <new>
#include <thread>
#include <vector>

#include "singleton.h"

class Widget {
public:
    Widget() : value_(0x5A5A) {}
    void Touch() const { (void)value_; }

private:
    volatile int value_;
};

static int RunSingle()
{
    std::shared_ptr<Widget> first = OHOS::DelayedSingleton<Widget>::GetInstance();
    if (first != nullptr) {
        first->Touch();
    }
    OHOS::DelayedSingleton<Widget>::DestroyInstance();
    std::shared_ptr<Widget> second = OHOS::DelayedSingleton<Widget>::GetInstance();
    if (second != nullptr) {
        second->Touch();
    }
    OHOS::DelayedSingleton<Widget>::DestroyInstance();
    std::printf("RESULT=single_ok\n");
    return 0;
}

static int RunRace(int readers, long iterations)
{
    std::atomic<bool> start{false};
    std::atomic<long> observed{0};
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(readers) + 1);

    for (int index = 0; index < readers; ++index) {
        threads.emplace_back([&start, &observed, iterations]() {
            while (!start.load()) {
            }
            for (long step = 0; step < iterations; ++step) {
                std::shared_ptr<Widget> instance =
                    OHOS::DelayedSingleton<Widget>::GetInstance();
                if (instance != nullptr) {
                    instance->Touch();
                    observed.fetch_add(1);
                }
            }
        });
    }

    threads.emplace_back([&start, iterations]() {
        while (!start.load()) {
        }
        for (long step = 0; step < iterations; ++step) {
            OHOS::DelayedSingleton<Widget>::DestroyInstance();
        }
    });

    start.store(true);
    for (std::thread& thread : threads) {
        thread.join();
    }
    std::printf("RESULT=race_ok observed=%ld\n", observed.load());
    return 0;
}

int main(int argc, char** argv)
{
    const char* mode = argc > 1 ? argv[1] : "single";
    if (std::strcmp(mode, "single") == 0) {
        return RunSingle();
    }
    if (std::strcmp(mode, "race") == 0) {
        const int readers = argc > 2 ? std::atoi(argv[2]) : 4;
        const long iterations = argc > 3 ? std::atol(argv[3]) : 20000;
        return RunRace(readers, iterations);
    }
    std::fprintf(stderr, "usage: %s single|race [readers] [iterations]\n", argv[0]);
    return 2;
}