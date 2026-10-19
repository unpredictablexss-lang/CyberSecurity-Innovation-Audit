#include <memory>

struct Widget {
    explicit Widget(int seed) : value(seed) {}
    int Value() const { return value; }
    int value;
};

void consume(int) {}

void fixed_rebind_after_owner_reset() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>(1);
    Widget* alias = owner.get();
    owner.reset(std::make_unique<Widget>(2));
    alias = owner.get();
    consume(alias->Value());
}
