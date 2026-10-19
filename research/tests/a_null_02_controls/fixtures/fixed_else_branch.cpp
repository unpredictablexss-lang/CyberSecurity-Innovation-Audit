struct Item {
    int id;
};

int fixed_else_branch(const Item *item) {
    if (item == nullptr) {
        return -1;
    } else {
        return item->id;
    }
}
