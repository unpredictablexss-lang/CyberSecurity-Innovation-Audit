#include <memory>

struct Item {
    int id;
};

int unknown_exception_destructor_shape(std::unique_ptr<Item> item, bool fail) {
    if (fail) {
        throw 1;
    }
    return item->id;
}
