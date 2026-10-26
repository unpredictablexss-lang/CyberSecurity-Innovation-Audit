struct Item {
    int id;
};

int safe_positive_guard_nested(const Item *item) {
    if (item != nullptr) {
        return item->id;
    }
    return 0;
}
