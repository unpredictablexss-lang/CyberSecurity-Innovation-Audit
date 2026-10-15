struct Item {
    int id;
};

int dereference_parameter(const Item *item) {
    return item->id;
}
