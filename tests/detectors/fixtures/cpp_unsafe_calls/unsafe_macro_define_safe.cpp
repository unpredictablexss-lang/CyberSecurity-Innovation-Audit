#define LOG_TAG "Demo"
#define LOGD(fmt, ...) printf(LOG_TAG ": " fmt "\n", ##__VA_ARGS__)

void use_macro(int value)
{
    LOGD("%{public}d", value);
}
