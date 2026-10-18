#include <cstring>

void memcpy_s_wifi_safe(const char *src, size_t cfgLen)
{
    char *dst = new char[cfgLen];
    memcpy_s(dst, cfgLen, src, cfgLen);
}
