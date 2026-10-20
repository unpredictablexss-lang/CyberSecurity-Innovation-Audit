#include <memory>
#include <mutex>
class GuardControl {
    static int* slot_;
    static std::mutex mutex_;
public:
    static void Set(int* value) {
        std::unique_lock<std::mutex> guard(mutex_);
        guard.unlock();
        slot_ = value;
    }
    static int* Get() {
        std::lock_guard<std::mutex> guard(mutex_);
        return slot_;
    }
};
