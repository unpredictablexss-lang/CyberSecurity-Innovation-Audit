int safe_address_of_local_control() {
    int value = 7;
    int *alias = &value;
    return *alias;
}
