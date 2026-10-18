#include <atomic>
#include <chrono>
#include <memory>
#include <thread>

#include "js_proxy.h"

class IntProxy : public OHOS::JSProxy::JSProxy<int> {
public:
    IntProxy() = default;
};

int main()
{
    IntProxy proxy;
    proxy.SetInstance(std::make_shared<int>(1));

    std::atomic<bool> started{false};
    std::atomic<bool> stop{false};

    std::thread writer([&proxy, &started, &stop]() {
        started.store(true, std::memory_order_release);
        int value = 2;
        while (!stop.load(std::memory_order_acquire)) {
            proxy.SetInstance(std::make_shared<int>(value++));
        }
    });
    std::thread reader([&proxy, &started, &stop]() {
        while (!started.load(std::memory_order_acquire)) {
        }
        while (!stop.load(std::memory_order_acquire)) {
            auto instance = proxy.GetInstance();
            (void)instance;
        }
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    stop.store(true, std::memory_order_release);
    writer.join();
    reader.join();
    return 0;
}
