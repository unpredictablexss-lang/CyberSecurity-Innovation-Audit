#include <cstring>

void bad_copy(const char *input) {
    char buf[8];
    strcpy(buf, input);
}

int main() {
    bad_copy("this string is too long");
    return 0;
}
