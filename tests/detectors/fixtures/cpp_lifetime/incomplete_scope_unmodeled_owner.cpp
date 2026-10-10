#include <memory>

std::unique_ptr<int> owner;

void reset_owner() {
    owner.reset();
}
