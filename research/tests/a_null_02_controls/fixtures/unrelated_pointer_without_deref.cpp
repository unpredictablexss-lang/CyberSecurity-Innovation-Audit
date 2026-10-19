struct Item {
    int id;
};

int unrelated_pointer_without_deref(const Item *item) {
    return item == nullptr ? 0 : 1;
}
