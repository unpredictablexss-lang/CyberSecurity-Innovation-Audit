// D5 semantic regression, synthetic only; this is not a product vulnerability.
int memcpy_s(char *destination, int size, const char *source, int count) { return 0; }
void Callback(const char *secret) {
    char output[64];
    memcpy_s(output, 64, secret, 8);
    AUTH_LOGI(0, "%{public}s", output);
}
