struct Item {
    int id;
};

int fixed_error_path_multistatement(const Item *item) {
    if (!item) {
        int error_code = -1;
        return error_code;
    }
    return item->id;
}
