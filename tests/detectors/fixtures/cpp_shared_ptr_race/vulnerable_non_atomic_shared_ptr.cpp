#include <memory>
#include <mutex>

class Widget {
public:
    int value = 1;
};

class Holder {
public:
    static std::shared_ptr<Widget> GetInstance();
    static void DestroyInstance();

private:
    static std::shared_ptr<Widget> instance_;
    static std::mutex mutex_;
};

std::shared_ptr<Widget> Holder::instance_ = nullptr;
std::mutex Holder::mutex_;

std::shared_ptr<Widget> Holder::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            std::shared_ptr<Widget> temp(new Widget());
            instance_ = temp;
        }
    }
    return instance_;
}

void Holder::DestroyInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ != nullptr) {
        instance_.reset();
        instance_ = nullptr;
    }
}
