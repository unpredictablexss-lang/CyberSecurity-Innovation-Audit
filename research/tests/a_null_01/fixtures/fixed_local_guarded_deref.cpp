int fixed_local_guarded_deref(const int *value) {
    if (value == nullptr) {
        return 0;
    }
    return *value;
}
