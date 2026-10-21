// Source-derived reduced model of communication_wifi RemoteOnConfigChanged (lines 365-392).
// This validates the bounded copy method only; it is not a product build or a product PoC.
#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

constexpr int32_t MAX_LEN = 1024;
constexpr int EOK = 0;

int memcpy_s(void *dest, size_t destsz, const void *src, size_t count) {
    if (dest == nullptr || src == nullptr || destsz < count) return 22;
    std::memcpy(dest, src, count);
    return EOK;
}

enum class Outcome { Rejected, Copied };

class Parcel {
public:
    explicit Parcel(int32_t requested) {
        size_t n = requested > 0 ? static_cast<size_t>(requested) : 1;
        n = std::min<size_t>(n, static_cast<size_t>(MAX_LEN) * 2);
        bytes_.assign(n, 0x41);
    }
    const void *ReadBuffer(int32_t n) {
        if (n < 0 || static_cast<size_t>(n) > bytes_.size()) return nullptr;
        return bytes_.data();
    }
private:
    std::vector<unsigned char> bytes_;
};

Outcome RemoteOnConfigChanged(Parcel &data, int32_t cfgLen) {
    if (cfgLen <= 0) return Outcome::Rejected;
    if (cfgLen > MAX_LEN) return Outcome::Rejected;
    const char *dataBuffer = static_cast<const char *>(data.ReadBuffer(cfgLen));
    if (dataBuffer == nullptr) return Outcome::Rejected;
    char *cfgData = new (std::nothrow) char[cfgLen];
    if (cfgData == nullptr) return Outcome::Rejected;
    if (memcpy_s(cfgData, cfgLen, dataBuffer, cfgLen) != EOK) {
        delete[] cfgData;
        return Outcome::Rejected;
    }
    volatile unsigned char sink = static_cast<unsigned char>(cfgData[cfgLen - 1]);
    (void)sink;
    delete[] cfgData;
    return Outcome::Copied;
}

int main() {
    struct Case { long long raw; bool expectCopy; };
    const Case cases[] = {
        {-2147483648LL, false}, {-1LL, false}, {0LL, false},
        {1LL, true}, {1024LL, true}, {1025LL, false}, {2147483647LL, false}
    };
    for (const auto &c : cases) {
        if (c.raw < std::numeric_limits<int32_t>::min() ||
            c.raw > std::numeric_limits<int32_t>::max()) {
            std::cout << "case=" << c.raw << " outcome=rejected_before_i32\n";
            if (c.expectCopy) return 2;
            continue;
        }
        int32_t cfgLen = static_cast<int32_t>(c.raw);
        Parcel data(std::max<int32_t>(cfgLen, 1));
        Outcome outcome = RemoteOnConfigChanged(data, cfgLen);
        const char *name = outcome == Outcome::Copied ? "copied" : "rejected";
        std::cout << "case=" << cfgLen << " outcome=" << name << "\n";
        if ((outcome == Outcome::Copied) != c.expectCopy) return 3;
    }
    std::cout << "result=source_model_bounded_no_asan_ubsan_finding\n";
    return 0;
}
