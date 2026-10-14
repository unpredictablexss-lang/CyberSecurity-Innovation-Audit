#include <memory>

class Widget {
public:
    int value = 1;
};

class Holder {
public:
    static std::shared_ptr<Widget> instance_;
};

std::shared_ptr<Widget> Holder::instance_ = nullptr;

void local_shared_ptr_use()
{
    std::shared_ptr<Widget> local(new Widget());
    local.reset();
}
