// Safe control: reserve a terminator byte and accept the full xattr length.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

constexpr int MTP_DEVICE_NAME_LEN = 512;

int main()
{
    char *value = static_cast<char *>(malloc(sizeof(char) * (MTP_DEVICE_NAME_LEN + 1)));
    if (value == nullptr) return 2;
    std::memset(value, 'A', MTP_DEVICE_NAME_LEN);
    int len = MTP_DEVICE_NAME_LEN;
    if (len >= 0 && len <= MTP_DEVICE_NAME_LEN) {
        value[len] = '\0';
    }
    std::string description(value);
    std::cout << description.size() << "\n";
    free(value);
    return description.size() == MTP_DEVICE_NAME_LEN ? 0 : 1;
}
