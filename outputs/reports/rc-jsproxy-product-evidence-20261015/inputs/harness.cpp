// Controlled JSProxy shared_ptr owner race workload.
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include "js_proxy_variant.h"

class Widget {
public:
    Widget() : value_(0x5A5A) {}
    void Touch() const { value_.fetch_add(1, std::memory_order_relaxed); }

private:
    mutable std::atomic<int> value_;
};

class WidgetProxy : public OHOS::JSProxy::JSProxy<Widget> {
public:
    WidgetProxy() = default;
    ~WidgetProxy() = default;
};

static void RunSingle()
{
    WidgetProxy proxy;
    proxy.SetInstance(std::make_shared<Widget>());
    auto instance = proxy.GetInstance();
    if (instance == nullptr) {
        std::abort();
    }
    instance->Touch();
    proxy.SetInstance(nullptr);
    std::printf("RESULT=single_ok\n");
}

static void RunRace(int readers, int writers, long iterations)
{
    WidgetProxy proxy;
    proxy.SetInstance(std::make_shared<Widget>());
    std::atomic<bool> start{false};
    std::atomic<long> observed{0};
    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(readers + writers));

    for (int index = 0; index < readers; ++index) {
        threads.emplace_back([&proxy, &start, &observed, iterations]() {
            while (!start.load(std::memory_order_acquire)) {
            }
            for (long step = 0; step < iterations; ++step) {
                auto instance = proxy.GetInstance();
                if (instance != nullptr) {
                    instance->Touch();
                    observed.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    for (int index = 0; index < writers; ++index) {
        threads.emplace_back([&proxy, &start, iterations]() {
            while (!start.load(std::memory_order_acquire)) {
            }
            for (long step = 0; step < iterations; ++step) {
                if ((step & 1) == 0) {
                    proxy.SetInstance(std::make_shared<Widget>());
                } else {
                    auto previous = proxy.GetInstance();
                    proxy.SetInstance(nullptr);
                    if (previous != nullptr) {
                        previous->Touch();
                    }
                }
            }
        });
    }

    start.store(true, std::memory_order_release);
    for (std::thread& thread : threads) {
        thread.join();
    }
    std::printf("RESULT=race_ok observed=%ld\n", observed.load(std::memory_order_relaxed));
}

static void RunCloseGetEntry(long rounds)
{
    long observed = 0;
    for (long step = 0; step < rounds; ++step) {
        WidgetProxy proxy;
        proxy.SetInstance(std::make_shared<Widget>());
        std::atomic<int> ready{0};
        std::atomic<bool> go{false};

        std::thread closeResultSet([&proxy, &ready, &go]() {
            auto resultSet = proxy.GetInstance();
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            proxy.SetInstance(nullptr);
            if (resultSet != nullptr) {
                resultSet->Touch();
            }
        });

        std::thread getEntry([&proxy, &ready, &go, &observed]() {
            ready.fetch_add(1, std::memory_order_release);
            while (!go.load(std::memory_order_acquire)) {
            }
            auto resultSet = proxy.GetInstance();
            if (resultSet != nullptr) {
                resultSet->Touch();
                observed++;
            }
        });

        while (ready.load(std::memory_order_acquire) != 2) {
        }
        go.store(true, std::memory_order_release);
        closeResultSet.join();
        getEntry.join();
    }
    std::printf("RESULT=close_get_entry_ok rounds=%ld observed=%ld\n", rounds, observed);
}
static void RunUnrelated()
{
    WidgetProxy first;
    WidgetProxy second;
    first.SetInstance(std::make_shared<Widget>());
    second.SetInstance(std::make_shared<Widget>());
    std::atomic<bool> start{false};
    std::thread reader([&first, &start]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (long step = 0; step < 20000; ++step) {
            auto instance = first.GetInstance();
            if (instance != nullptr) {
                instance->Touch();
            }
        }
    });
    std::thread writer([&second, &start]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (long step = 0; step < 20000; ++step) {
            second.SetInstance(std::make_shared<Widget>());
        }
    });
    start.store(true, std::memory_order_release);
    reader.join();
    writer.join();
    std::printf("RESULT=unrelated_ok\n");
}

int main(int argc, char** argv)
{
    const char* mode = argc > 1 ? argv[1] : "single";
    if (std::strcmp(mode, "single") == 0) {
        RunSingle();
        return 0;
    }
    if (std::strcmp(mode, "race") == 0) {
        const int readers = argc > 2 ? std::atoi(argv[2]) : 4;
        const int writers = argc > 3 ? std::atoi(argv[3]) : 2;
        const long iterations = argc > 4 ? std::atol(argv[4]) : 50000;
        RunRace(readers, writers, iterations);
        return 0;
    }
    if (std::strcmp(mode, "close_get_entry") == 0) {
        const long rounds = argc > 2 ? std::atol(argv[2]) : 2000;
        RunCloseGetEntry(rounds);
        return 0;
    }    if (std::strcmp(mode, "unrelated") == 0) {
        RunUnrelated();
        return 0;
    }
    std::fprintf(stderr, "usage: %s single|race [readers] [writers] [iterations]|close_get_entry [rounds]|unrelated\n", argv[0]);
    return 2;
}
