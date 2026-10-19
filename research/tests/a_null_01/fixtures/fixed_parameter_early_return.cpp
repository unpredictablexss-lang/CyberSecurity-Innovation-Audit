struct Item {
    int id;
};

int fixed_parameter_early_return(const Item *item) {
    if (item == nullptr) {
        return -1;
    }
    return item->id;
}
