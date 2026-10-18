#include <cstddef>

void guarded(size_t len)
{
    if (len > 1024) return;
    char *buffer = new char[len + 1];
    (void)buffer;
}
