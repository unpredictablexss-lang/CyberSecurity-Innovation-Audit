struct Item {
    int id;
};

int error_path_falls_through(const Item *item) {
    if (item == nullptr) {
        int error_code = -1;
        (void)error_code;
    }
    return item->id;
}
