void bounds_fixed(char *src, unsigned int n) {
    char dst[8];
    if (n >= 8) return;
    memcpy(dst, src, n);
    if (n > 7) return;
    dst[n] = 1;
}
