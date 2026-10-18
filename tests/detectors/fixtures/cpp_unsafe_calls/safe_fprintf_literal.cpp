#include <cstdio>

void SafeFprintf(FILE *stream, const char *value)
{
    fprintf(stream, "%s", value);
}
