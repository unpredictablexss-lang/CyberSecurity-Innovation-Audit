// D5 semantic regression, synthetic only; this is not a product vulnerability.
int strcpy_s(char *destination, int size, const char *source) { return 0; }
void Callback(const char *secret) {
    char output[64];
    strcpy_s(output, 64, secret);
    AUTH_LOGI(0, "%{public}s", output);
}
