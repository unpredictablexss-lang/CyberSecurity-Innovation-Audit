struct Item {
    int id;
};

int positive_parameter_unguarded(const Item *item) {
    return item->id;
}
