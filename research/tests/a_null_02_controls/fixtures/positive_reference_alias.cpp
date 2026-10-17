struct Item {
    int id;
};

int positive_reference_alias(Item *item) {
    Item *&alias = item;
    return alias->id;
}
