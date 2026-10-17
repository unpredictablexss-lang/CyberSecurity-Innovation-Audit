void bounds_positive(char *src, unsigned int n) {
    char dst[8];
    memcpy(dst, src, n);
    dst[16] = 1;
}
