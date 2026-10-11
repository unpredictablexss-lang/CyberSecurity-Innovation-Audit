#include <memory>
#include <mutex>

class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;

    static void Reset()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        instance_.reset();
    }

    static int Load()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return instance_ ? 1 : 0;
    }
};
