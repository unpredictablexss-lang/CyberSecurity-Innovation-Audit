#include <memory>

struct Widget {
    int Value() const { return 7; }
};

void consume(int) {}

void macro_context_is_incomplete() {
    std::unique_ptr<Widget> owner = std::make_unique<Widget>();
    Widget* alias = owner.get();
#ifdef OH_EXTERNAL_OWNER_RESET
    owner.reset();
#endif
    consume(alias->Value());
}
