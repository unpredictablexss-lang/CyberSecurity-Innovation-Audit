int safe_reference_to_local() {
    int value = 7;
    int &reference = value;
    return reference;
}
