#include <memory>

struct Widget {
    int Value() const { return 7; }
};

void consume(int) {}

void vulnerable_unserialized() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
    owner.reset();
    consume(alias->Value());
}
