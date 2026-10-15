#include <atomic>
#include <memory>
#include <thread>
#include <vector>

class Widget {
public:
    void Touch() const {}
};

class Holder {
public:
    static void Exchange()
    {
        std::atomic_exchange(&instance_, std::make_shared<Widget>());
    }

    static bool CompareExchange()
    {
        std::shared_ptr<Widget> expected;
        return std::atomic_compare_exchange_strong(
            &instance_, &expected, std::make_shared<Widget>());
    }

    static std::shared_ptr<Widget> Load()
    {
        return std::atomic_load(&instance_);
    }

private:
    static std::shared_ptr<Widget> instance_;
};

std::shared_ptr<Widget> Holder::instance_;

int main()
{
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    threads.emplace_back([&start]() {
        while (!start.load()) {
        }
        for (int step = 0; step < 20000; ++step) {
            Holder::Exchange();
            (void)Holder::CompareExchange();
        }
    });
    threads.emplace_back([&start]() {
        while (!start.load()) {
        }
        for (int step = 0; step < 20000; ++step) {
            auto instance = Holder::Load();
            if (instance != nullptr) {
                instance->Touch();
            }
        }
    });
    start.store(true);
    for (auto& thread : threads) {
        thread.join();
    }
    return 0;
}