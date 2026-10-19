#include <memory>

void failed_parse_fixture() {
    std::unique_ptr<int> owner;
    owner.reset(
