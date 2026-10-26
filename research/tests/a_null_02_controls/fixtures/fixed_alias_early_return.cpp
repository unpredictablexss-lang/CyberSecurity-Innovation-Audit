struct Item {
    int id;
};

int fixed_alias_early_return(Item *item) {
    Item *&alias = item;
    if (alias == nullptr) {
        return -1;
    }
    return alias->id;
}
