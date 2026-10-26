void test(const char* dynamic_format, const char* value) {
    fprintf(stderr, R"fmt(fixed, [literal] %s)fmt", value);
    fprintf(stderr, dynamic_format, R"arg(argument, [brackets])arg");
}
