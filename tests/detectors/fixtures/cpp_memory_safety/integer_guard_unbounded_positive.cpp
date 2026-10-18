#include <cstddef>

void unguarded(size_t len)
{
    char *buffer = new char[len + 1];
    (void)buffer;
}
