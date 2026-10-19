struct Item {
    int id;
};

int unrelated_null_check_without_sink(const Item *item) {
    if (item == nullptr) {
        return 0;
    }
    return 1;
}
