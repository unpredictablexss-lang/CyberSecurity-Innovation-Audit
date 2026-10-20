#include <memory>

class Holder {
public:
    static std::shared_ptr<int> instance_;
};

std::shared_ptr<int> Holder::instance_ = nullptr;

#define RESET_INSTANCE_MACRO() Holder::instance_.reset()
