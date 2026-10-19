// Minimal stand-in for the bounds_checking_function component.
//
// c_utils base/src/parcel.cpp only uses memcpy_s; the same shim is already used
// by the project's c_utils standalone-compile recipe
// (docs/targets/c_utils_parcel_onboarding.md).
#ifndef SECUREC_STUB_H
#define SECUREC_STUB_H

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int errno_t;
#define EOK 0

static inline errno_t memcpy_s(void *dest, size_t destMax, const void *src, size_t count)
{
    if (dest == NULL || src == NULL) {
        return -1;
    }
    if (destMax < count) {
        return -1;
    }
    memcpy(dest, src, count);
    return 0;
}

static inline errno_t strcpy_s(char *dest, size_t destMax, const char *src)
{
    if (dest == NULL || src == NULL) {
        return -1;
    }
    size_t n = strlen(src);
    if (destMax <= n) {
        return -1;
    }
    memcpy(dest, src, n + 1);
    return 0;
}

#ifdef __cplusplus
}
#endif
#endif
