#include <memory>

std::shared_ptr<int> instance_;

void use_global()
{
    instance_.reset();
}
