#include <memory>
#include <mutex>

class Holder {
public:
    static std::shared_ptr<int> instance_;
    static std::mutex mutex_a_;
    static std::mutex mutex_b_;

    static void ResetA()
    {
        std::lock_guard<std::mutex> lock(mutex_a_);
        instance_.reset();
    }

    static void ResetB()
    {
        std::lock_guard<std::mutex> lock(mutex_b_);
        instance_.reset();
    }
};
