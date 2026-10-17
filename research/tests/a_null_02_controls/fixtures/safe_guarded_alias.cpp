int safe_guarded_alias(int *value) {
    int *alias = value;
    if (alias == nullptr) {
        return 0;
    }
    return *alias;
}
