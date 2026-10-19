struct Item {
    int id;
};

int guard_does_not_dominate(const Item *item) {
    bool observed = false;
    if (item != nullptr) {
        observed = true;
    }
    return item->id + (observed ? 0 : 0);
}
