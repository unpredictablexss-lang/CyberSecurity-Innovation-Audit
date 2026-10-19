#include <memory>
#include <mutex>
class GuardControl {
    static std::shared_ptr<int> slot_;
    static std::mutex mutex_;
public:
    static void Set(std::shared_ptr<int> value) {
        std::unique_lock<std::mutex> guard(mutex_);
        slot_ = value;
    }
    static std::shared_ptr<int> Get() {
        std::lock_guard<std::mutex> guard(mutex_);
        return slot_;
    }
};
