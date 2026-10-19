int safe_address_of_local() {
    int value = 7;
    int *alias = &value;
    return *alias;
}
