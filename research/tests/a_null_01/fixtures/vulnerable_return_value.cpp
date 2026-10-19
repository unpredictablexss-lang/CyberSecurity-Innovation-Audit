struct Item {
    int id;
};

Item *LookupItem();

int dereference_return_value() {
    Item *item = LookupItem();
    return item->id;
}
