struct Item {
    int id;
};

int dereference_local_null() {
    int *value = nullptr;
    return *value;
}
