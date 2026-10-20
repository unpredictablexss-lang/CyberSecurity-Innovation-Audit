// D5 semantic regression, synthetic only; this is not a product vulnerability.
int snprintf(char *destination, int size, const char *format, const char *value) { return 0; }
void Callback(const char *secret) {
    char output[64];
    snprintf(output, sizeof(output), "%s", secret);
    AUTH_LOGI(0, "%{public}s", output);
}
