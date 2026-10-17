// No-op hilog stand-in.
//
// The declarations mirror the OpenHarmony hilog public header
// (Apache-2.0, Copyright (c) 2021 Huawei Device Co., Ltd.): HiLogIsLoggable and
// HILOG_IMPL sit at global scope, HiLogLabel/HiLog in OHOS::HiviewDFX. Only the
// bodies differ -- every call is dropped. Logging is not control flow here: the
// PASTEBOARD_CHECK_* macros in the component's own header keep their `if`/`return`
// shape regardless of what the log expression expands to.
#ifndef STUB_HILOG_LOG_H
#define STUB_HILOG_LOG_H

#include <cstdint>

typedef enum {
    LOG_TYPE_MIN = 0,
    LOG_APP = 0,
    LOG_INIT = 1,
    LOG_CORE = 2,
    LOG_TYPE_MAX = 3,
} LogType;

typedef enum {
    LOG_LEVEL_MIN = 0,
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARN = 2,
    LOG_ERROR = 3,
    LOG_FATAL = 4,
    LOG_LEVEL_MAX = 5,
} LogLevel;

namespace OHOS {
namespace HiviewDFX {
using HiLogLabel = struct {
    LogType type;
    unsigned int domain;
    const char *tag;
};
} // namespace HiviewDFX
} // namespace OHOS

inline bool HiLogIsLoggable(unsigned int, const char *, LogLevel)
{
    return false;
}

inline int HiLogPrint(LogType, LogLevel, unsigned int, const char *, const char *, ...)
{
    return 0;
}

#define HILOG_IMPL(type, level, domain, tag, ...) \
    HiLogPrint(type, level, domain, tag, ##__VA_ARGS__)

#endif
