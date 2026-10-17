struct Item {
    int id;
};

int safe_nonpointer_member(Item item) {
    return item.id;
}
