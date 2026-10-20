#include <memory>

struct Widget {
    void Use() const {}
};

void parse_not_run_fixture() {
    std::unique_ptr<Widget> owner;
    Widget* alias = owner.get();
    owner.reset();
    alias->Use();
}
