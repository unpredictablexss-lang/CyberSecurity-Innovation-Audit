#include <memory>
#include <mutex>

class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_;

    static void Reset()
    {
        std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
        instance_.reset();
    }
};
