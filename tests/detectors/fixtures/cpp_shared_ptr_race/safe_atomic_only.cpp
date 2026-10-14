#include <atomic>
#include <memory>

class Widget {
public:
    int value = 1;
};

class Holder {
public:
    static std::shared_ptr<Widget> Load();

private:
    static std::shared_ptr<Widget> instance_;
};

std::shared_ptr<Widget> Holder::instance_ = nullptr;

std::shared_ptr<Widget> Holder::Load()
{
    return std::atomic_load(&instance_);
}
