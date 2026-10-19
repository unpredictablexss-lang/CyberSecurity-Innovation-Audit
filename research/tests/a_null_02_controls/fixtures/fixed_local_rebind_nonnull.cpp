int fixed_local_rebind_nonnull() {
    int local = 7;
    int *value = nullptr;
    value = &local;
    return *value;
}
