#include <memory>
#include <mutex>
#include <thread>
#include <vector>

class Widget {
public:
    void Touch() const {}
};

class Holder {
public:
    static void Reset()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }

    static std::shared_ptr<Widget> Load()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return instance_;
    }

private:
    static std::shared_ptr<Widget> instance_;
    static std::mutex mutex_;
};

std::shared_ptr<Widget> Holder::instance_;
std::mutex Holder::mutex_;

int main()
{
    std::vector<std::thread> threads;
    for (int index = 0; index < 2; ++index) {
        threads.emplace_back([]() {
            for (int step = 0; step < 20000; ++step) {
                auto instance = Holder::Load();
                if (instance != nullptr) {
                    instance->Touch();
                }
            }
        });
    }
    threads.emplace_back([]() {
        for (int step = 0; step < 20000; ++step) {
            Holder::Reset();
        }
    });
    for (auto& thread : threads) {
        thread.join();
    }
    return 0;
}