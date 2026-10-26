void bounds_safe(char *src) {
    char dst[8];
    memcpy(dst, src, sizeof(dst));
    dst[7] = 1;
}
