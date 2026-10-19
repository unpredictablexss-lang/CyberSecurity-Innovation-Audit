#include <memory>

struct Widget {
    void Use() const {}
};

void unresolved_owner_reset_and_alias_use(Widget* alias) {
    owner.reset();
    alias->Use();
}
