#include <atomic>
#include <memory>

class Widget {
public:
    int value = 1;
};

class Holder {
public:
    static std::shared_ptr<Widget> instance_;
    static std::shared_ptr<Widget> AtomicLoad();
    static void AtomicStore();
};

std::shared_ptr<Widget> Holder::instance_ = nullptr;

std::shared_ptr<Widget> Holder::AtomicLoad()
{
    return std::atomic_load(&instance_);
}

void Holder::AtomicStore()
{
    std::atomic_store(&instance_, std::shared_ptr<Widget>(nullptr));
}
