#include <memory>

class Holder {
public:
    static std::shared_ptr<int> instance_;
};

std::shared_ptr<int> Holder::instance_ = nullptr;
void external_touch(std::shared_ptr<int> value);
external_touch(instance_);
