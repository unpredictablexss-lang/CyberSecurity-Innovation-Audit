// D5 semantic regression, synthetic only; this is not a product vulnerability.
void Callback(const char *secret, int condition) {
    const char *output = "safe";
    for (int index = 0; index < condition; ++index) {
        output = secret;
    }
    AUTH_LOGI(0, "%{public}s", output);
}
