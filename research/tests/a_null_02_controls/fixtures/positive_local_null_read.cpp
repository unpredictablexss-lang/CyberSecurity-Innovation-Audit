int positive_local_null_read() {
    int *value = NULL;
    int observed = *value;
    return observed;
}
