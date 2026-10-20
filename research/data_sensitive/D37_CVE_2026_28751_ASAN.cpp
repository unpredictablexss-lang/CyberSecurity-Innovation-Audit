// Source-shaped CVE-2026-28751 boundary harness.
// Models NotifyMtpMounted's full-capacity xattr result and C-string use;
// this is not a build of filemanagement_storage_service or product PoC.
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

constexpr int MTP_DEVICE_NAME_LEN = 512;

int main()
{
    char *value = static_cast<char *>(malloc(sizeof(char) * MTP_DEVICE_NAME_LEN));
    if (value == nullptr) return 2;
    std::memset(value, 'A', MTP_DEVICE_NAME_LEN);
    int len = MTP_DEVICE_NAME_LEN; // getxattr may return the requested size
    if (len >= 0 && len < MTP_DEVICE_NAME_LEN) {
        value[len] = '\0';
    }
    // On the full-length case the prior guard skipped termination.
    std::string description(value);
    std::cout << description.size() << "\n";
    free(value);
    return 0;
}
