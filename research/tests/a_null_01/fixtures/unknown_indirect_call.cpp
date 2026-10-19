struct Item {
    int id;
};

int ReadItem(const Item *item);

int unknown_indirect_call_shape(int (*reader)(const Item *), const Item *item) {
    return reader(item);
}
