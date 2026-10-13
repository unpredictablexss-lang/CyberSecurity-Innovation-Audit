// Minimal stand-in for hilog; every log call degrades to nothing.
//
// The historical inputmethod_imf headers reference OHOS::HiviewDFX::HiLogLabel
// and OHOS::HiviewDFX::HiLog, so the stub keeps that exact shape.
#ifndef STUB_HILOG_LOG_H
#define STUB_HILOG_LOG_H

#include <cstdint>

enum LogType { LOG_CORE = 0, LOG_APP = 1 };
enum LogLevel { LOG_DEBUG = 0, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_FATAL };

namespace OHOS {
namespace HiviewDFX {

struct HiLogLabel {
    int type;
    unsigned int domain;
    const char *tag;
};

class HiLog {
public:
    template <typename... Args>
    static int Debug(const HiLogLabel &label, const char *format, Args...)
    {
        (void)label;
        (void)format;
        return 0;
    }
    template <typename... Args>
    static int Info(const HiLogLabel &label, const char *format, Args...)
    {
        (void)label;
        (void)format;
        return 0;
    }
    template <typename... Args>
    static int Warn(const HiLogLabel &label, const char *format, Args...)
    {
        (void)label;
        (void)format;
        return 0;
    }
    template <typename... Args>
    static int Error(const HiLogLabel &label, const char *format, Args...)
    {
        (void)label;
        (void)format;
        return 0;
    }
    template <typename... Args>
    static int Fatal(const HiLogLabel &label, const char *format, Args...)
    {
        (void)label;
        (void)format;
        return 0;
    }
};

} // namespace HiviewDFX
} // namespace OHOS

#define HILOG_DEBUG(...) ((void)0)
#define HILOG_INFO(...) ((void)0)
#define HILOG_WARN(...) ((void)0)
#define HILOG_ERROR(...) ((void)0)
#define HILOG_FATAL(...) ((void)0)

#endif
