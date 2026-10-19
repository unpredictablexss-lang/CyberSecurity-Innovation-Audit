#ifndef OHSCANNER_POC_NOCOPYABLE_H
#define OHSCANNER_POC_NOCOPYABLE_H

namespace OHOS {
class NoCopyable {
protected:
    NoCopyable() = default;
    ~NoCopyable() = default;

private:
    NoCopyable(const NoCopyable&) = delete;
    NoCopyable& operator=(const NoCopyable&) = delete;
};
} // namespace OHOS

#endif