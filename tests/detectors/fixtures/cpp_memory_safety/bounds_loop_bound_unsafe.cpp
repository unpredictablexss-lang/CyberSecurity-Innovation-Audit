void loop_bound_unsafe(const char *src)
{
    char dst[4];
    for (unsigned int i = 0; i < 8; ++i) {
        dst[i] = src[i];
    }
}
