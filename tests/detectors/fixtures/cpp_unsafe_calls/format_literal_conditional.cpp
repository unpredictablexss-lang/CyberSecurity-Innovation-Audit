void test(bool condition, const char* dynamic, int value) {
    printf(condition ? "left=%d" : "right=%d", value);
    printf(condition ? dynamic : "fixed", value);
    fprintf(stderr, (condition ? "a=%d" : "b=%d"), value);
    printf(condition ? (value ? "nested-a=%d" : "nested-b=%d") : "outer=%d", value);
}
