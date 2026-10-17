struct Item {
    int id;
};

Item *LookupPositive();

int positive_return_value_unknown() {
    Item *item = LookupPositive();
    return item->id;
}
