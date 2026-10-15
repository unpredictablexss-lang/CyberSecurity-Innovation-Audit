#include <atomic>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

class Widget {
public:
    void Touch() const {}
};

class DelayedSingletonControl {
public:
    static std::shared_ptr<Widget> GetInstance()
    {
        std::shared_ptr<Widget> instance = instance_;
        if (instance == nullptr) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (instance_ == nullptr) {
                instance_ = std::make_shared<Widget>();
            }
            instance = instance_;
        }
        return instance;
    }

    static void DestroyInstance()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }

private:
    static std::shared_ptr<Widget> instance_;
    static std::mutex mutex_;
};

std::shared_ptr<Widget> DelayedSingletonControl::instance_;
std::mutex DelayedSingletonControl::mutex_;

int main()
{
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;
    for (int index = 0; index < 3; ++index) {
        threads.emplace_back([&start]() {
            while (!start.load()) {
            }
            for (int step = 0; step < 20000; ++step) {
                auto instance = DelayedSingletonControl::GetInstance();
                if (instance != nullptr) {
                    instance->Touch();
                }
            }
        });
    }
    threads.emplace_back([&start]() {
        while (!start.load()) {
        }
        for (int step = 0; step < 20000; ++step) {
            DelayedSingletonControl::DestroyInstance();
        }
    });
    start.store(true);
    for (auto& thread : threads) {
        thread.join();
    }
    DelayedSingletonControl::DestroyInstance();
    return 0;
}