struct Item {
    int id;
};

int fixed_short_circuit(const Item *item) {
    return item && item->id;
}
