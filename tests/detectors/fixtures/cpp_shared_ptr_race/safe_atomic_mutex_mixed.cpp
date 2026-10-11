#include <atomic>
#include <memory>
#include <mutex>

class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;

    static void ResetAtomic()
    {
        std::atomic_store(&instance_, std::shared_ptr<int>(nullptr));
    }

    static void ResetGuarded()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }
};
