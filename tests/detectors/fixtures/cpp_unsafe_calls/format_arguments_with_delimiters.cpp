void test(const char* dynamic_format, int value) {
    fprintf(stderr, "format,[literal]", value);
    fprintf(stderr, dynamic_format, "argument,[literal]");
}
