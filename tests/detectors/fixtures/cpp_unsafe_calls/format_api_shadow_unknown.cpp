#include <stdio.h>

namespace local {
int fprintf(const char *format, const char *value);
}

void custom_format(FILE *stream, const char *format) {
    local::fprintf(format, "fixed");
    fprintf(stream, format);
}
